import csv
import io

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import audit, current_user, require
from ..models import (Asset, AssetIdentifier, CveProduct, Finding, FindingEvent, Organization, Scan, User,
                      Vulnerability, row, utcnow)
from ..services import advice, matcher, remediation, scanner, scope, trends

router = APIRouter(prefix="/api", tags=["findings"])
VIEW_EX = ("evidence", "risk_inputs", "fp_key", "fingerprint")


class Transition(BaseModel):
    to_state: str
    note: str | None = None
    assignee: str | None = None
    accepted_days: int | None = None


def query(db, u, state=None, tier=None, asset_id=None, cve=None, min_score=None, open_only=False):
    st = (select(Finding, Asset, Vulnerability)
          .join(Asset, Asset.id == Finding.asset_id).join(Vulnerability, Vulnerability.cve_id == Finding.cve_id)
          .where(Finding.org_id == u.org_id))
    if open_only:
        st = st.where(Finding.state.in_(remediation.OPEN_STATES))
    if state:
        st = st.where(Finding.state == state)
    if tier:
        st = st.where(Finding.risk_tier == tier)
    if asset_id:
        st = st.where(Finding.asset_id == asset_id)
    if cve:
        st = st.where(Finding.cve_id == cve)
    if min_score is not None:
        st = st.where(Finding.risk_score >= min_score)
    return st.order_by(Finding.risk_score.desc(), Finding.id)


def view(f, a, v, ips=(), rows=()):
    ev = f.evidence or {}
    sw = ev.get("software", {})
    svc = None
    if sw.get("port"):
        svc = f"{sw['port']}/{sw.get('protocol') or 'tcp'}"
    prod = " ".join(x for x in (sw.get("name"), sw.get("version")) if x)
    return {**row(f, exclude=VIEW_EX), "asset_name": a.name, "ips": list(ips), "owner": a.owner,
            "owner_email": a.owner_email, "department": a.department, "location": a.location,
            "exposure": a.exposure, "criticality": a.criticality, "port": svc, "software": prod or None,
            "cvss": v.cvss, "kev": v.kev, "epss": v.epss, "description": v.description,
            "overdue": bool(f.due_at and f.due_at < utcnow() and f.state in remediation.OPEN_STATES),
            "fix_hint": advice.fix_hint(f, rows), "why": _why(f, v)}


def run(db, q):
    """Execute a query() and return enriched finding dicts (IPs, owner, fix hint)."""
    rs = db.execute(q).all()
    if not rs:
        return []
    aids = {a.id for _, a, _ in rs}
    cves = {v.cve_id for _, _, v in rs}
    ips, prods = {}, {}
    for r in db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id.in_(aids), AssetIdentifier.type == "ip",
                                                      AssetIdentifier.active == True)):  # noqa: E712
        ips.setdefault(r.asset_id, []).append(r.value)
    for p in db.scalars(select(CveProduct).where(CveProduct.cve_id.in_(cves))):
        prods.setdefault(p.cve_id, []).append(p)
    return [view(f, a, v, ips.get(a.id, []), prods.get(v.cve_id, [])) for f, a, v in rs]


def _why(f, v):
    bits = []
    if v.kev:
        bits.append("actively exploited (CISA KEV)")
    if v.epss is not None and v.epss >= 0.1:
        bits.append(f"EPSS {v.epss:.0%}")
    if v.cvss is not None:
        bits.append(f"CVSS {v.cvss}")
    bits.append(f"{f.risk_inputs.get('asset_exposure', '?')} exposure, criticality {f.risk_inputs.get('asset_criticality', '?')}")
    bits.append(f"{f.match_method} match at {f.match_confidence:.0%} confidence")
    return "; ".join(bits)


@router.get("/findings")
def list_findings(state: str | None = None, tier: str | None = None, asset_id: int | None = None,
                  cve: str | None = None, min_score: float | None = None, open_only: bool = False,
                  limit: int = Query(200, le=2000), u: User = Depends(current_user), db: Session = Depends(get_db)):
    return run(db, query(db, u, state, tier, asset_id, cve, min_score, open_only).limit(limit))


@router.get("/findings/export.csv")
def export_csv(open_only: bool = True, u: User = Depends(current_user), db: Session = Depends(get_db)):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "asset", "ip", "owner", "owner_email", "department", "location", "cve", "tier", "score", "state",
                "assignee", "due", "service", "fix", "why"])
    for x in run(db, query(db, u, open_only=open_only)):
        w.writerow([x["id"], x["asset_name"], " ".join(x["ips"]), x["owner"] or "", x["owner_email"] or "",
                    x["department"] or "", x["location"] or "", x["cve_id"], x["risk_tier"], x["risk_score"],
                    x["state"], x["assignee"] or "", x["due_at"][:10] if x["due_at"] else "",
                    f"{x['port'] or ''} {x['software'] or ''}".strip(), x["fix_hint"], x["why"]])
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=asivm-findings.csv"})


@router.get("/findings/{fid}")
def get_finding(fid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    f = db.get(Finding, fid)
    if not f or f.org_id != u.org_id:
        raise HTTPException(404, "finding not found")
    a, v = db.get(Asset, f.asset_id), db.get(Vulnerability, f.cve_id)
    rows = db.scalars(select(CveProduct).where(CveProduct.cve_id == f.cve_id)).all()
    ips = db.scalars(select(AssetIdentifier.value).where(AssetIdentifier.asset_id == a.id, AssetIdentifier.type == "ip",
                                                         AssetIdentifier.active == True)).all()  # noqa: E712
    ev = [row(e) for e in db.scalars(select(FindingEvent).where(FindingEvent.finding_id == f.id).order_by(FindingEvent.id))]
    return {**row(f), "asset": {**row(a), "ips": ips}, "asset_name": a.name, "vulnerability": row(v), "history": ev,
            "why": _why(f, v), "remediation": advice.build(f, v, rows, a, ips)}


@router.post("/findings/{fid}/transition")
def transition(fid: int, b: Transition, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    f = db.get(Finding, fid)
    if not f or f.org_id != u.org_id:
        raise HTTPException(404, "finding not found")
    try:
        remediation.user_transition(db, f, b.to_state, u.email, b.note, b.assignee, b.accepted_days)
    except remediation.TransitionError as e:
        raise HTTPException(400, str(e))
    audit(db, u, "finding_transition", f"finding:{f.id}", b.model_dump())
    trends.record_snapshot(db, u.org_id)
    db.commit()
    return row(f, exclude=VIEW_EX)


@router.post("/findings/{fid}/verify", status_code=202)
def verify(fid: int, bg: BackgroundTasks, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    """Re-scan the asset; closure is verified only if the issue is no longer observed."""
    f = db.get(Finding, fid)
    if not f or f.org_id != u.org_id:
        raise HTTPException(404, "finding not found")
    if f.source != "intel":
        raise HTTPException(400, "verification re-scans apply to network findings; re-import a Trivy report instead")
    ips = db.scalars(select(AssetIdentifier.value).where(AssetIdentifier.asset_id == f.asset_id, AssetIdentifier.type == "ip",
                                                         AssetIdentifier.active == True)).all()  # noqa: E712
    if not ips:
        raise HTTPException(422, "asset has no active IP address to re-scan")
    d = scope.validate_target(db, u.org_id, ips[0])
    if not d.allowed:
        raise HTTPException(422, f"Target rejected by scope validator: {d.reason}")
    s = Scan(org_id=u.org_id, tool="nmap", target=ips[0], profile="standard", requested_by=u.email)
    db.add(s)
    audit(db, u, "verification_scan", f"finding:{f.id}", {"target": ips[0]})
    db.commit()
    bg.add_task(scanner.run_scan, s.id)
    return row(s)


@router.post("/findings/rescore")
def rescore(u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    n = matcher.rescore(db, db.get(Organization, u.org_id))
    db.commit()
    return {"rescored": n}


@router.post("/findings/rematch")
def rematch(u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    org = db.get(Organization, u.org_id)
    out = matcher.rematch_all(db, org)
    db.commit()
    return out
