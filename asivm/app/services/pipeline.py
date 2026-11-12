"""Ingest observations -> persistent assets, services, software, findings, change events."""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (Asset, ChangeEvent, Finding, Organization, Scan, ServiceObservation,
                      Software, Vulnerability, utcnow)
from . import identity, matcher, risk
from .parsers import ParsedHost, port_in_spec


def change(db, org_id, kind, asset_id=None, scan_id=None, **detail):
    db.add(ChangeEvent(org_id=org_id, asset_id=asset_id, scan_id=scan_id, kind=kind, detail=detail))


def _sync_services(db, org_id, scan, asset, host: ParsedHost, new_asset: bool) -> dict:
    now = utcnow()
    existing = {(s.port, s.protocol): s for s in db.scalars(
        select(ServiceObservation).where(ServiceObservation.asset_id == asset.id))}
    sw_rows = {(s.port, s.protocol): s for s in db.scalars(
        select(Software).where(Software.asset_id == asset.id, Software.source == "nmap"))}
    seen, st = set(), {"new": 0, "changed": 0, "removed": 0}
    for p in host.services:
        key = (p.port, p.protocol)
        seen.add(key)
        s = existing.get(key)
        if not s:
            s = ServiceObservation(org_id=org_id, asset_id=asset.id, port=p.port, protocol=p.protocol)
            db.add(s)
            st["new"] += 1
            if not new_asset:
                change(db, org_id, "new_service", asset.id, scan.id, port=p.port, protocol=p.protocol,
                       product=p.product, version=p.version)
        elif not s.active:
            st["new"] += 1
            change(db, org_id, "new_service", asset.id, scan.id, port=p.port, protocol=p.protocol,
                   product=p.product, version=p.version, reappeared=True)
        elif (s.product, s.version) != (p.product, p.version):
            st["changed"] += 1
            change(db, org_id, "version_changed", asset.id, scan.id, port=p.port,
                   old={"product": s.product, "version": s.version}, new={"product": p.product, "version": p.version})
        s.service, s.product, s.version, s.extrainfo, s.cpe = p.service, p.product, p.version, p.extrainfo, p.cpe
        s.active, s.last_seen, s.scan_id = True, now, scan.id
        sw = sw_rows.get(key)
        if p.product:
            if not sw:
                sw = Software(org_id=org_id, asset_id=asset.id, source="nmap", name=p.product,
                              port=p.port, protocol=p.protocol)
                db.add(sw)
                sw_rows[key] = sw
            sw.name, sw.version, sw.cpe, sw.active, sw.last_seen = p.product, p.version, p.cpe, True, now
            sw.evidence = {"service": p.service, "extrainfo": p.extrainfo, "scan_id": scan.id}
        elif sw:
            sw.active = False
    for key, s in existing.items():
        if key in seen or not s.active:
            continue
        if port_in_spec(key[0], (host.scanned_ports or {}).get(key[1])):  # only if this scan looked there
            s.active = False
            st["removed"] += 1
            change(db, org_id, "service_removed", asset.id, scan.id, port=key[0], protocol=key[1],
                   product=s.product, version=s.version)
            if key in sw_rows:
                sw_rows[key].active = False
    return st


def ingest_hosts(db: Session, scan: Scan, hosts: list[ParsedHost], with_services: bool = True) -> dict:
    org = db.get(Organization, scan.org_id)
    stats = {"hosts": 0, "new_assets": 0, "matched_to_existing": 0, "services_new": 0,
             "services_changed": 0, "services_removed": 0, "findings_evaluated": 0, "merged": 0}
    touched = []
    for h in hosts:
        try:
            res = identity.resolve(db, org.id, h.identifiers(), source=scan.tool, actor=f"scan#{scan.id}")
        except ValueError:
            continue
        a = res.asset
        stats["hosts"] += 1
        stats["merged"] += len(res.merged)
        if res.created:
            stats["new_assets"] += 1
            change(db, org.id, "new_asset", a.id, scan.id, name=a.name, identifiers=h.identifiers())
        else:
            stats["matched_to_existing"] += 1
            if a.status == "stale":
                change(db, org.id, "asset_returned", a.id, scan.id)
        a.status = "active"
        if h.os:
            a.os = h.os
        if with_services:
            st = _sync_services(db, org.id, scan, a, h, res.created)
            stats["services_new"] += st["new"]
            stats["services_changed"] += st["changed"]
            stats["services_removed"] += st["removed"]
        touched.append(a)
    db.flush()
    if with_services:
        for a in touched:
            stats["findings_evaluated"] += matcher.match_asset(db, org, a, scan.id)["matched"]
        from ..ml import service as ml_service  # local import: keeps ML optional for the core pipeline
        for a in touched:
            ml_service.on_observation(db, a, scan.id)
    return stats


def ingest_trivy(db: Session, scan: Scan, artifact: str | None, vulns: list[dict], asset_id=None,
                 identifiers: dict | None = None) -> dict:
    org = db.get(Organization, scan.org_id)
    policy = risk.get_policy(org)
    if asset_id:
        asset = db.get(Asset, asset_id)
        if not asset or asset.org_id != org.id:
            raise ValueError("asset not found")
    else:
        ids = identifiers or {"artifact": [artifact or scan.target]}
        res = identity.resolve(db, org.id, ids, source="trivy", name=artifact or scan.target)
        asset = res.asset
        if res.created:
            change(db, org.id, "new_asset", asset.id, scan.id, name=asset.name, via="trivy")
    now, seen = utcnow(), set()
    pkgs: dict = {}
    for v in vulns:
        sw = pkgs.get((v["pkg"], v["target"]))
        if not sw:
            sw = db.scalar(select(Software).where(Software.asset_id == asset.id, Software.source == "trivy",
                                                  Software.name == v["pkg"], Software.cpe == v["target"]))
            if not sw:
                sw = Software(org_id=org.id, asset_id=asset.id, source="trivy", name=v["pkg"], cpe=v["target"])
                db.add(sw)
                db.flush()
            pkgs[(v["pkg"], v["target"])] = sw
        sw.version, sw.active, sw.last_seen = v["installed"], True, now
        vuln = db.get(Vulnerability, v["id"])
        if not vuln:
            vuln = Vulnerability(cve_id=v["id"], source="trivy")
        if vuln.cvss is None and v["cvss"] is not None:
            vuln.cvss = v["cvss"]
        vuln.severity = vuln.severity or v["severity"]
        vuln.description = vuln.description or v["title"] or v["description"]
        db.add(vuln)
        db.flush()
        ev = {"asset": {"id": asset.id, "name": asset.name}, "scan_id": scan.id,
              "software": {"name": v["pkg"], "version": v["installed"], "fixed_version": v["fixed"],
                           "target": v["target"], "package_type": v["type"], "source": "trivy"},
              "matching": {"method": "trivy", "confidence": 0.9, "notes": ["matched by Trivy against its advisory DB"]}}
        fp_key = f"{v['id']}|{v['pkg']}|trivy|{v['target']}"
        f = matcher._upsert(db, org, asset, sw, vuln, "trivy", 0.9, ev, "trivy", fp_key, scan.id, policy)
        seen.add(f.id)
    matcher.vanish_unseen(db, asset, "trivy", seen, scan.id)
    db.flush()
    return {"asset_id": asset.id, "asset_name": asset.name, "findings": len(seen)}


def mark_stale(db: Session, days: int) -> int:
    cutoff, n = utcnow() - timedelta(days=days), 0
    for a in db.scalars(select(Asset).where(Asset.status == "active", Asset.last_seen < cutoff)):
        a.status = "stale"
        change(db, a.org_id, "asset_stale", a.id, last_seen=a.last_seen.isoformat())
        n += 1
    return n


def expire_acceptances(db: Session) -> int:
    from . import remediation
    n = 0
    for f in db.scalars(select(Finding).where(Finding.state == "accepted_risk", Finding.accepted_until < utcnow())):
        f.accepted_until = None
        remediation.set_state(db, f, "open", "system", "risk acceptance expired")
        n += 1
    return n
