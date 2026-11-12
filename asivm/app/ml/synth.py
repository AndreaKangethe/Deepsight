"""Controlled DEMONSTRATION data. Not real telemetry.

A synthetic fleet is generated week by week (assets, findings that appear and get fixed, services that come
and go, a few injected sudden changes). The risk label comes from LABEL_POLICY below, a hidden "compromise
propensity" with interactions and noise. It is deliberately NOT the formula in services/risk.py, so the model
cannot simply re-learn the rule engine; but it is still synthetic, so any score on it only shows that the
pipeline works end to end. Real predictive value needs approved analyst labels (see MLFeedback).
"""
import math
from datetime import datetime, timedelta

import numpy as np

from .features import (CLASSES, RISK_FEATURES, ANOMALY_FEATURES, aggregate, delta_features, vector)

LABEL_POLICY = {
    "version": "synthetic-v1",
    "summary": ("Hidden compromise propensity = severity + exploitation evidence + asset criticality + "
                "exposure interactions + overdue backlog + growth, plus Gaussian noise (sd 0.5). Classes are "
                "cut at fixed population quantiles: low 45%, moderate 30%, high 17%, critical 8%. "
                "An asset with no open findings is always 'low'."),
    "quantiles": [0.45, 0.75, 0.92],
}

# archetype: (weight, criticality mean, exposure probs [internal, dmz, internet], services, vulns)
ARCHETYPES = {
    "web_server": (0.22, 3.6, (0.05, 0.35, 0.60), 4, 6),
    "database": (0.14, 4.3, (0.85, 0.13, 0.02), 2, 4),
    "workstation": (0.30, 2.0, (0.97, 0.03, 0.00), 1, 3),
    "app_server": (0.16, 3.4, (0.60, 0.30, 0.10), 3, 5),
    "network_device": (0.08, 3.8, (0.60, 0.20, 0.20), 3, 2),
    "test_box": (0.10, 1.4, (0.90, 0.08, 0.02), 2, 7),
}


def _finding(rng, age, boosted=False):
    cvss = float(np.clip(rng.beta(5, 2.5) * 10, 1.0, 10.0))
    if boosted:
        cvss = max(cvss, 7.5)
    kev = bool(rng.random() < (0.02 + (0.10 if cvss >= 9 else 0.0) + (0.25 if boosted else 0.0)))
    epss = float(rng.beta(4, 3)) if kev else float(min(1.0, rng.beta(0.35, 9)))
    return {"cvss": round(cvss, 1), "epss": round(epss, 4), "kev": kev, "age": int(age)}


def _overdue(f):
    sla = 7 if f["cvss"] >= 9 else 30 if f["cvss"] >= 7 else 90
    return f["age"] > sla


def _propensity(x: dict, rng) -> float:
    exp = x["exposure_level"]
    z = (0.28 * x["max_cvss"] + 0.9 * math.log1p(x["n_cvss_ge7"]) + 1.4 * math.sqrt(min(x["n_kev"], 3))
         + 2.0 * x["max_epss"] + 0.35 * x["criticality"]
         + exp * (0.5 + 0.9 * (x["n_kev"] > 0) + 1.6 * x["max_epss"])
         + (0.10 * min(x["n_exposed_services"], 15) if exp > 0 else 0.0)
         + 0.45 * math.log1p(x["n_overdue"]) + 0.06 * max(x["findings_trend_30d"], 0))
    return z + float(rng.normal(0, 0.5))


def generate(n_assets: int = 400, steps: int = 8, seed: int = 7, anomaly_rate: float = 0.03) -> dict:
    """-> dict with risk dataset (X, y, groups, ts) and anomaly dataset (Xa, ya, ga)."""
    rng = np.random.default_rng(seed)
    kinds = list(ARCHETYPES)
    probs = np.array([ARCHETYPES[k][0] for k in kinds])
    t0 = datetime(2026, 1, 5)
    feats_rows, groups, ts, z, has_findings = [], [], [], [], []
    anom_rows, anom_y, anom_g = [], [], []
    for aid in range(n_assets):
        _, crit_mu, exp_p, svc_mu, vuln_mu = ARCHETYPES[kinds[rng.choice(len(kinds), p=probs / probs.sum())]]
        crit = int(np.clip(round(rng.normal(crit_mu, 0.8)), 1, 5))
        exposure = int(rng.choice(3, p=exp_p))
        n_svc = int(rng.poisson(svc_mu))
        findings = [_finding(rng, rng.integers(0, 200)) for _ in range(int(rng.poisson(vuln_mu)))]
        conf = float(rng.uniform(0.72, 0.95))
        hist_f, hist_s, hist_feats = [], [], []
        for t in range(steps):
            injected = 0  # 0 none, 1 services only, 2 findings only, 3 both
            if t > 0:
                findings = [f for f in findings if rng.random() > 0.10]
                for f in findings:
                    f["age"] += 7
                findings += [_finding(rng, 0) for _ in range(int(rng.poisson(0.5)))]
                n_svc = max(0, n_svc + int(rng.integers(-1, 2)))
                if rng.random() < anomaly_rate:
                    injected = int(rng.choice([1, 2, 3], p=[0.4, 0.3, 0.3]))
                    if injected in (1, 3):  # sudden new exposure, e.g. 2 services -> 12
                        n_svc += int(rng.integers(6, 11))
                    if injected in (2, 3):  # sudden burst of serious vulnerabilities
                        findings += [_finding(rng, 0, boosted=True) for _ in range(int(rng.integers(6, 13)))]
            k = max(0, t - 4)
            f_trend = len(findings) - hist_f[k] if hist_f else 0
            s_trend = n_svc - hist_s[k] if hist_s else 0
            x = aggregate([f["cvss"] for f in findings], [f["epss"] for f in findings],
                          sum(f["kev"] for f in findings), [f["age"] for f in findings],
                          sum(_overdue(f) for f in findings), [conf] * len(findings), crit, exposure, n_svc,
                          sum(1 for f in findings if f["age"] <= 30), f_trend, s_trend)
            hist_f.append(len(findings))
            hist_s.append(n_svc)
            d = delta_features(x, hist_feats[::-1][:4])
            if d is not None:
                anom_rows.append(vector(d, ANOMALY_FEATURES))
                anom_y.append(injected)
                anom_g.append(aid)
            hist_feats.append(x)
            feats_rows.append(vector(x))
            groups.append(aid)
            ts.append((t0 + timedelta(weeks=t)).isoformat())
            has_findings.append(len(findings) > 0)
            z.append(_propensity(x, rng))
    z = np.array(z)
    cuts = np.quantile(z[np.array(has_findings)], LABEL_POLICY["quantiles"])
    y = np.digitize(z, cuts)
    y[~np.array(has_findings)] = 0
    return {"X": np.array(feats_rows), "y": y.astype(int), "groups": np.array(groups), "ts": np.array(ts),
            "feature_names": list(RISK_FEATURES), "classes": list(CLASSES),
            "Xa": np.array(anom_rows), "ya": (np.array(anom_y) > 0).astype(int), "ta": np.array(anom_y), "ga": np.array(anom_g),
            "anomaly_feature_names": list(ANOMALY_FEATURES), "policy": LABEL_POLICY}
