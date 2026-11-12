"""Feature contract v1: one fixed, versioned vector per asset, built only from data ASIVM already stores.

Changing, adding or reordering a feature means a new FEATURE_VERSION; models record the version they were
trained on and refuse to score a different one.
"""
import math
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Asset, AssetSnapshot, Finding, ServiceObservation, Vulnerability, utcnow
from ..services.remediation import OPEN_STATES

FEATURE_VERSION = "v1"
CLASSES = ("low", "moderate", "high", "critical")
EXPOSURE_LEVEL = {"internal": 0, "dmz": 1, "internet": 2}
ASSUMED_CVSS = 5.0  # same assumption the rule-based risk policy makes for an unscored CVE

RISK_FEATURES = (
    "n_findings", "max_cvss", "mean_cvss", "n_cvss_ge7", "n_kev", "max_epss", "mean_epss",
    "criticality", "exposure_level", "n_exposed_services", "n_new_30d", "oldest_open_days",
    "n_overdue", "mean_match_conf", "findings_trend_30d", "services_trend_30d",
)
# Change features: the latest snapshot compared with the asset's own recent history.
# (d_max_cvss / d_max_epss were tried and dropped: they swing whenever the top finding is fixed and drowned out
# real signals, e.g. a sudden jump in exposed services.)
ANOMALY_FEATURES = ("d_services", "d_findings", "d_kev", "services_ratio", "findings_ratio")


def aggregate(cvss: list, epss: list, kev: int, ages: list, overdue: int, conf: list, criticality: int,
              exposure_level: int, n_services: int, new_30d: int, f_trend: float, s_trend: float) -> dict:
    """Pure function shared by live extraction and the synthetic generator (identical contract)."""
    n = len(cvss)
    return {
        "n_findings": n,
        "max_cvss": max(cvss) if n else 0.0,
        "mean_cvss": round(sum(cvss) / n, 3) if n else 0.0,
        "n_cvss_ge7": sum(1 for c in cvss if c >= 7.0),
        "n_kev": kev,
        "max_epss": max(epss) if n else 0.0,
        "mean_epss": round(sum(epss) / n, 4) if n else 0.0,
        "criticality": criticality,
        "exposure_level": exposure_level,
        "n_exposed_services": n_services,
        "n_new_30d": new_30d,
        "oldest_open_days": max(ages) if ages else 0,
        "n_overdue": overdue,
        "mean_match_conf": round(sum(conf) / len(conf), 3) if conf else 0.0,
        "findings_trend_30d": f_trend,
        "services_trend_30d": s_trend,
    }


def asset_features(db: Session, asset: Asset, now=None) -> dict:
    now = now or utcnow()
    rows = db.execute(select(Finding, Vulnerability)
                      .join(Vulnerability, Vulnerability.cve_id == Finding.cve_id)
                      .where(Finding.asset_id == asset.id, Finding.state.in_(OPEN_STATES))).all()
    cvss = [v.cvss if v.cvss is not None else ASSUMED_CVSS for _, v in rows]
    epss = [v.epss or 0.0 for _, v in rows]
    ages = [max(0, (now - f.first_seen).days) for f, _ in rows]
    n_svc = db.scalar(select(func.count()).select_from(ServiceObservation).where(
        ServiceObservation.asset_id == asset.id, ServiceObservation.active == True)) or 0  # noqa: E712
    first = db.scalar(select(AssetSnapshot).where(
        AssetSnapshot.asset_id == asset.id, AssetSnapshot.at >= now - timedelta(days=30))
        .order_by(AssetSnapshot.at.asc()).limit(1))
    f_trend = len(rows) - first.features.get("n_findings", len(rows)) if first else 0
    s_trend = n_svc - first.features.get("n_exposed_services", n_svc) if first else 0
    return aggregate(
        cvss, epss, sum(1 for _, v in rows if v.kev), ages,
        sum(1 for f, _ in rows if f.due_at and f.due_at < now), [f.match_confidence for f, _ in rows],
        asset.criticality, EXPOSURE_LEVEL.get(asset.exposure, 0), n_svc,
        sum(1 for a in ages if a <= 30), f_trend, s_trend)


def delta_features(cur: dict, history: list[dict]) -> dict | None:
    """Compare a snapshot with the asset's previous snapshots (newest first). None if there is no history."""
    if not history:
        return None
    prev = history[0]
    mean = lambda k: sum(h.get(k, 0) for h in history) / len(history)  # noqa: E731
    return {
        "d_services": cur["n_exposed_services"] - prev.get("n_exposed_services", 0),
        "d_findings": cur["n_findings"] - prev.get("n_findings", 0),
        "d_kev": cur["n_kev"] - prev.get("n_kev", 0),
        "services_ratio": round((cur["n_exposed_services"] + 1) / (mean("n_exposed_services") + 1), 3),
        "findings_ratio": round((cur["n_findings"] + 1) / (mean("n_findings") + 1), 3),
    }


def record_snapshot(db: Session, asset: Asset, scan_id=None) -> AssetSnapshot:
    s = AssetSnapshot(org_id=asset.org_id, asset_id=asset.id, scan_id=scan_id,
                      feature_version=FEATURE_VERSION, features=asset_features(db, asset))
    db.add(s)
    db.flush()
    return s


def vector(feats: dict, names=RISK_FEATURES) -> list[float]:
    return [float(feats.get(k, 0.0)) for k in names]


def phrase(feat: str, v: float) -> str:
    """Plain-language description of a feature value, used in explanations."""
    n = int(round(v))  # always an int: the table below is built eagerly, so every entry must tolerate any feature's value
    plural = lambda k, one, many: one if k == 1 else many  # noqa: E731
    return {
        "n_findings": f"{n} open finding{plural(n, '', 's')}",
        "max_cvss": f"Highest CVSS score is {v:.1f}",
        "mean_cvss": f"Average CVSS score is {v:.1f}",
        "n_cvss_ge7": f"{n} high or critical severity vulnerabilit{plural(n, 'y', 'ies')}",
        "n_kev": f"{n} known exploited vulnerabilit{plural(n, 'y', 'ies')} (CISA KEV)",
        "max_epss": f"Exploitation probability up to {v:.0%} (EPSS)",
        "mean_epss": f"Average exploitation probability {v:.1%} (EPSS)",
        "criticality": f"Asset criticality {n} of 5",
        "exposure_level": ("Internal only", "DMZ exposure", "Internet-facing")[max(0, min(2, n))],
        "n_exposed_services": f"{n} exposed service{plural(n, '', 's')}",
        "n_new_30d": f"{n} new finding{plural(n, '', 's')} in the last 30 days",
        "oldest_open_days": f"Oldest open finding is {n} days old",
        "n_overdue": f"{n} finding{plural(n, '', 's')} past the fix date",
        "mean_match_conf": f"Average match confidence {v:.0%}",
        "findings_trend_30d": f"Open findings {'up' if v > 0 else 'down'} by {abs(n)} over 30 days" if n else "Open findings unchanged over 30 days",
        "services_trend_30d": f"Exposed services {'up' if v > 0 else 'down'} by {abs(n)} over 30 days" if n else "Exposed services unchanged over 30 days",
        "d_services": f"Exposed services changed by {v:+.0f} since the previous scan",
        "d_findings": f"Open findings changed by {v:+.0f} since the previous scan",
        "d_kev": f"Known exploited vulnerabilities changed by {v:+.0f}",
        "d_max_cvss": f"Highest CVSS changed by {v:+.1f}",
        "d_max_epss": f"Highest EPSS changed by {v:+.2f}",
        "services_ratio": f"Exposed services are {v:.1f}x the recent average",
        "findings_ratio": f"Open findings are {v:.1f}x the recent average",
    }.get(feat, f"{feat} = {v}")


def label_index(label: str) -> int:
    return CLASSES.index(label)


__all__ = ["FEATURE_VERSION", "CLASSES", "RISK_FEATURES", "ANOMALY_FEATURES", "asset_features",
           "delta_features", "record_snapshot", "vector", "phrase", "aggregate", "math"]
