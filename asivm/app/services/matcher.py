"""CVE matching with explicit method + confidence, and finding fingerprints."""
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (Asset, CveProduct, Finding, FindingEvent, Organization, Software,
                      Vulnerability, utcnow)
from . import remediation, risk
from .identity import fingerprint
from .versions import BACKPORT_HINT, in_range, vtuple

ALIASES = {
    "apache httpd": ("apache", "http_server"), "apache http server": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"), "nginx": ("nginx", "nginx"), "vsftpd": ("beasts", "vsftpd"),
    "samba smbd": ("samba", "samba"), "samba": ("samba", "samba"), "proftpd": ("proftpd", "proftpd"),
    "apache tomcat": ("apache", "tomcat"), "apache tomcat/coyote jsp engine": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"), "log4j": ("apache", "log4j"), "log4j-core": ("apache", "log4j"),
    "mysql": ("oracle", "mysql"), "mariadb": ("mariadb", "mariadb"), "openssl": ("openssl", "openssl"),
    "postgresql db": ("postgresql", "postgresql"), "postfix smtpd": ("postfix", "postfix"),
    "exim smtpd": ("exim", "exim"), "isc bind": ("isc", "bind"), "lighttpd": ("lighttpd", "lighttpd"),
    "redis key-value store": ("redis", "redis"), "microsoft iis httpd": ("microsoft", "internet_information_services"),
}


def identify(sw: Software):
    """-> (vendor|None, product_slug, version, method, base_confidence)"""
    ver = sw.version
    if sw.cpe:
        p = re.split(r"[:]", sw.cpe.replace("cpe:/", "cpe:2.3:", 1) if sw.cpe.startswith("cpe:/") else sw.cpe)
        if len(p) > 4 and p[2] == "a":
            ver = ver or (p[5] if len(p) > 5 and p[5] not in ("*", "-") else None)
            return p[3], p[4], ver, "cpe", 0.95
    key = (sw.name or "").strip().lower()
    if key in ALIASES:
        v, p = ALIASES[key]
        return v, p, ver, "alias", 0.85
    return None, re.sub(r"[^a-z0-9]+", "_", key).strip("_"), ver, "name", 0.7


def _upsert(db, org, asset, sw, vuln, method, conf, evidence, source, fp_key, scan_id, policy):
    fp = fingerprint(asset.id, fp_key)
    f = db.scalar(select(Finding).where(Finding.org_id == org.id, Finding.fingerprint == fp))
    score, tier, inputs = risk.compute(vuln, asset, conf, policy)
    evidence = {**evidence, "risk_inputs": inputs}
    now = utcnow()
    if not f:
        from datetime import timedelta
        f = Finding(org_id=org.id, asset_id=asset.id, software_id=sw.id if sw else None, cve_id=vuln.cve_id,
                    fp_key=fp_key, fingerprint=fp, source=source, state="open", match_method=method,
                    match_confidence=conf, evidence=evidence, risk_score=score, risk_tier=tier,
                    risk_inputs=inputs, last_scan_id=scan_id,
                    due_at=now + timedelta(days=policy["sla_days"][tier]))
        db.add(f)
        db.flush()
        db.add(FindingEvent(finding_id=f.id, org_id=org.id, from_state=None, to_state="open", actor="system",
                            note=f"detected by scan #{scan_id}" if scan_id else "detected by re-match"))
    else:
        f.match_method, f.match_confidence, f.evidence = method, conf, evidence
        f.risk_score, f.risk_tier, f.risk_inputs = score, tier, inputs
        f.last_seen, f.last_scan_id = now, scan_id or f.last_scan_id
        remediation.system_reobserved(db, f, scan_id)
    return f


def match_asset(db: Session, org: Organization, asset: Asset, scan_id=None, reconcile=True) -> dict:
    policy = risk.get_policy(org)
    min_conf = float((org.settings or {}).get("min_match_confidence", settings.min_match_confidence))
    stats = {"matched": 0, "skipped_unknown_version": 0, "below_confidence": 0}
    seen = set()
    sws = db.scalars(select(Software).where(Software.asset_id == asset.id, Software.active == True,  # noqa: E712
                                            Software.source != "trivy")).all()
    for sw in sws:
        vendor, product, ver, method, base = identify(sw)
        if not product:
            continue
        if vtuple(ver) is None:
            stats["skipped_unknown_version"] += 1
            continue
        best: dict[str, tuple] = {}
        for cp in db.scalars(select(CveProduct).where(CveProduct.product == product)):
            if not in_range(ver, cp.version_exact, cp.start_incl, cp.start_excl, cp.end_incl, cp.end_excl):
                continue
            conf, notes = base, []
            if vendor and cp.vendor != vendor:
                conf, notes = min(conf, 0.75), [f"vendor differs (observed '{vendor}', advisory '{cp.vendor}')"]
            if BACKPORT_HINT.search(f"{sw.version or ''} {(sw.evidence or {}).get('extrainfo') or ''}"):
                conf, notes = round(conf - 0.15, 2), notes + ["distribution package: vendor may have backported the fix"]
            if cp.cve_id not in best or conf > best[cp.cve_id][0]:
                best[cp.cve_id] = (conf, cp, notes)
        for cid, (conf, cp, notes) in best.items():
            if conf < min_conf:
                stats["below_confidence"] += 1
                continue
            vuln = db.get(Vulnerability, cid)
            rng = {k: getattr(cp, k) for k in ("version_exact", "start_incl", "start_excl", "end_incl", "end_excl") if getattr(cp, k)}
            ev = {"asset": {"id": asset.id, "name": asset.name}, "scan_id": scan_id,
                  "software": {"name": sw.name, "version": sw.version, "cpe": sw.cpe, "port": sw.port,
                               "protocol": sw.protocol, "extrainfo": (sw.evidence or {}).get("extrainfo"),
                               "source": sw.source},
                  "matching": {"method": method, "confidence": conf, "advisory_product": f"{cp.vendor}:{cp.product}",
                               "affected_range": rng, "notes": notes}}
            fp_key = f"{cid}|{cp.product}|{sw.port}/{sw.protocol}"
            f = _upsert(db, org, asset, sw, vuln, method, conf, ev, "intel", fp_key, scan_id, policy)
            seen.add(f.id)
            stats["matched"] += 1
    if reconcile:
        vanish_unseen(db, asset, "intel", seen, scan_id)
    db.flush()
    return stats


def vanish_unseen(db: Session, asset: Asset, source: str, seen: set, scan_id):
    for f in db.scalars(select(Finding).where(Finding.asset_id == asset.id, Finding.source == source)).all():
        if f.id not in seen and f.state not in ("verified", "accepted_risk"):
            remediation.system_vanished(db, f, scan_id)


def rescore(db: Session, org: Organization, asset_id: int | None = None) -> int:
    policy = risk.get_policy(org)
    q = select(Finding).where(Finding.org_id == org.id, Finding.state.in_(remediation.OPEN_STATES))
    if asset_id:
        q = q.where(Finding.asset_id == asset_id)
    n = 0
    for f in db.scalars(q).all():
        v, a = db.get(Vulnerability, f.cve_id), db.get(Asset, f.asset_id)
        if v and a:
            f.risk_score, f.risk_tier, f.risk_inputs = risk.compute(v, a, f.match_confidence, policy)
            n += 1
    return n


def rematch_all(db: Session, org: Organization) -> dict:
    tot = {"assets": 0, "matched": 0}
    for a in db.scalars(select(Asset).where(Asset.org_id == org.id, Asset.status != "merged")):
        s = match_asset(db, org, a, None, reconcile=False)
        tot["assets"] += 1
        tot["matched"] += s["matched"]
    return tot
