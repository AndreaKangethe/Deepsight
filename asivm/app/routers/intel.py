from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal, get_db
from ..deps import audit, current_user, require
from ..models import (Asset, AuditLog, ChangeEvent, CveProduct, Finding, IntelStatus, Organization,
                      User, Vulnerability, row, utcnow)
from ..services import intel as svc, matcher, remediation, risk, trends
from .findings import query, run

router = APIRouter(prefix="/api", tags=["intel"])


class SyncIn(BaseModel):
    kinds: list[str] = ["seed"]  # seed|nvd|kev|epss
    days: int = 30
    cve: str | None = None


def _bg(kinds, days, cve):
    with SessionLocal() as db:
        svc.run_sync(db, kinds, days, cve)
        for org in db.scalars(select(Organization)):
            matcher.rematch_all(db, org)
            matcher.rescore(db, org)
            trends.record_snapshot(db, org.id)
        db.commit()


@router.get("/intel/status")
def status(u: User = Depends(current_user), db: Session = Depends(get_db)):
    return {"sources": [row(s) for s in db.scalars(select(IntelStatus))],
            "vulnerabilities": db.scalar(select(func.count(Vulnerability.cve_id))),
            "kev": db.scalar(select(func.count(Vulnerability.cve_id)).where(Vulnerability.kev == True)),  # noqa: E712
            "with_epss": db.scalar(select(func.count(Vulnerability.cve_id)).where(Vulnerability.epss != None)),  # noqa: E711
            "product_ranges": db.scalar(select(func.count(CveProduct.id)))}


@router.post("/intel/sync", status_code=202)
def sync(b: SyncIn, bg: BackgroundTasks, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    bad = set(b.kinds) - {"seed", "nvd", "kev", "epss"}
    if bad:
        raise HTTPException(422, f"unknown kinds: {sorted(bad)}")
    audit(db, u, "intel_sync", None, b.model_dump())
    db.commit()
    bg.add_task(_bg, b.kinds, b.days, b.cve)
    return {"started": b.kinds}


@router.post("/intel/import/{kind}")
async def import_feed(kind: str, file: UploadFile = File(...), u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    """Offline / air-gapped feed import (nvd JSON 2.0, kev JSON, epss CSV[.gz])."""
    try:
        n = svc.import_file(db, kind, await file.read())
    except Exception as e:
        db.rollback()
        raise HTTPException(422, str(e))
    org = db.get(Organization, u.org_id)
    matcher.rematch_all(db, org)
    matcher.rescore(db, org)
    audit(db, u, "intel_import", kind, {"count": n})
    db.commit()
    return {"imported": n}


@router.get("/vulns/{cve_id}")
def vuln(cve_id: str, u: User = Depends(current_user), db: Session = Depends(get_db)):
    v = db.get(Vulnerability, cve_id.upper())
    if not v:
        raise HTTPException(404, "unknown CVE")
    return {**row(v), "affected": [row(p) for p in db.scalars(select(CveProduct).where(CveProduct.cve_id == v.cve_id))]}


def _changes(db, rows):
    ids = {c.asset_id for c in rows if c.asset_id}
    names = {a.id: a.name for a in db.scalars(select(Asset).where(Asset.id.in_(ids)))} if ids else {}
    return [{**row(c), "asset_name": names.get(c.asset_id)} for c in rows]


# ------------------------------------------------------------------ dashboard / reports / audit
@router.get("/dashboard")
def dashboard(u: User = Depends(current_user), db: Session = Depends(get_db)):
    org = u.org_id
    opn = Finding.state.in_(remediation.OPEN_STATES)
    tiers = dict(db.execute(select(Finding.risk_tier, func.count()).where(Finding.org_id == org, opn).group_by(Finding.risk_tier)).all())
    states = dict(db.execute(select(Finding.state, func.count()).where(Finding.org_id == org).group_by(Finding.state)).all())
    assets = db.scalars(select(Asset).where(Asset.org_id == org, Asset.status != "merged")).all()
    owned = sum(1 for a in assets if a.owner)
    overdue = db.scalar(select(func.count()).select_from(Finding).where(Finding.org_id == org, opn, Finding.due_at < utcnow()))
    mttr = {}
    for f in db.scalars(select(Finding).where(Finding.org_id == org, Finding.state == "verified", Finding.closed_at != None)):  # noqa: E711
        mttr.setdefault(f.risk_tier, []).append((f.closed_at - f.first_seen).total_seconds() / 86400)
    top = run(db, query(db, u, open_only=True).limit(10))
    changes = _changes(db, db.scalars(select(ChangeEvent).where(ChangeEvent.org_id == org).order_by(ChangeEvent.id.desc()).limit(15)).all())
    return {"assets": {"total": len(assets), "with_owner": owned, "owner_coverage": round(owned / len(assets), 3) if assets else None,
                       "stale": sum(1 for a in assets if a.status == "stale"),
                       "internet_exposed": sum(1 for a in assets if a.exposure == "internet")},
            "open_by_tier": {t: tiers.get(t, 0) for t in ("critical", "high", "medium", "low")},
            "by_state": states, "overdue": overdue,
            "mean_days_to_verified_by_tier": {t: round(sum(v) / len(v), 2) for t, v in mttr.items()},
            "fix_first": top, "recent_changes": changes}


@router.get("/reports/fix-first")
def fix_first(limit: int = 20, u: User = Depends(current_user), db: Session = Depends(get_db)):
    return run(db, query(db, u, open_only=True).limit(min(limit, 200)))


@router.get("/changes")
def changes(kind: str | None = None, limit: int = 100, u: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(ChangeEvent).where(ChangeEvent.org_id == u.org_id)
    if kind:
        q = q.where(ChangeEvent.kind == kind)
    return _changes(db, db.scalars(q.order_by(ChangeEvent.id.desc()).limit(min(limit, 500))).all())


@router.get("/audit")
def audit_log(limit: int = 200, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    return [row(a) for a in db.scalars(select(AuditLog).where(AuditLog.org_id == u.org_id).order_by(AuditLog.id.desc()).limit(min(limit, 1000)))]


# ------------------------------------------------------------------ trends, owner rollup, risk policy
@router.get("/trends")
def trend(days: int = 30, u: User = Depends(current_user), db: Session = Depends(get_db)):
    from ..models import TrendSnapshot
    trends.record_snapshot(db, u.org_id)
    db.commit()
    rows = db.scalars(select(TrendSnapshot).where(TrendSnapshot.org_id == u.org_id)
                      .order_by(TrendSnapshot.day.desc()).limit(max(1, min(days, 365)))).all()
    return [{"day": r.day, **r.data} for r in reversed(rows)]


@router.get("/reports/by")
def rollup(group: str = "owner", u: User = Depends(current_user), db: Session = Depends(get_db)):
    """Open findings, overdue and verified fixes grouped by owner, department or location."""
    if group not in ("owner", "department", "location"):
        raise HTTPException(422, "group must be owner, department or location")
    assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.org_id == u.org_id, Asset.status != "merged"))}
    out: dict = {}

    def g(a):
        return (getattr(a, group) or "").strip() or "(not set)"

    for a in assets.values():
        r = out.setdefault(g(a), {"name": g(a), "assets": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                                  "open": 0, "overdue": 0, "verified": 0, "top_score": 0.0})
        r["assets"] += 1
    now = utcnow()
    for f in db.scalars(select(Finding).where(Finding.org_id == u.org_id)):
        a = assets.get(f.asset_id)
        if not a:
            continue
        r = out[g(a)]
        if f.state in remediation.OPEN_STATES:
            r[f.risk_tier] += 1
            r["open"] += 1
            r["top_score"] = max(r["top_score"], f.risk_score)
            if f.due_at and f.due_at < now:
                r["overdue"] += 1
        elif f.state == "verified":
            r["verified"] += 1
    return sorted(out.values(), key=lambda r: (-r["critical"], -r["high"], -r["open"], r["name"]))


class PolicyIn(BaseModel):
    weights: dict[str, float] | None = None
    tiers: dict[str, float] | None = None
    sla_days: dict[str, int] | None = None
    min_match_confidence: float | None = None


@router.get("/risk-policy")
def get_policy(u: User = Depends(current_user), db: Session = Depends(get_db)):
    org = db.get(Organization, u.org_id)
    return {"policy": risk.get_policy(org), "defaults": risk.DEFAULT_POLICY,
            "min_match_confidence": (org.settings or {}).get("min_match_confidence", settings.min_match_confidence),
            "customised": bool((org.settings or {}).get("risk_policy") or "min_match_confidence" in (org.settings or {}))}


@router.put("/risk-policy")
def set_policy(b: PolicyIn, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    org = db.get(Organization, u.org_id)
    cur = risk.get_policy(org)
    new = {}
    if b.weights:
        if set(b.weights) - set(cur["weights"]) or any(v < 0 or v > 100 for v in b.weights.values()):
            raise HTTPException(422, f"weights must be 0-100 for: {', '.join(cur['weights'])}")
        new["weights"] = b.weights
    if b.tiers:
        t = {**cur["tiers"], **b.tiers}
        if set(b.tiers) - set(cur["tiers"]) or not (100 >= t["critical"] > t["high"] > t["medium"] > 0):
            raise HTTPException(422, "tier thresholds must satisfy 100 >= critical > high > medium > 0")
        new["tiers"] = b.tiers
    if b.sla_days:
        if set(b.sla_days) - set(cur["sla_days"]) or any(v < 1 or v > 3650 for v in b.sla_days.values()):
            raise HTTPException(422, "SLA days must be 1-3650 for: critical, high, medium, low")
        new["sla_days"] = b.sla_days
    s = dict(org.settings or {})
    s["risk_policy"] = {**(s.get("risk_policy") or {}), **{k: {**(s.get("risk_policy") or {}).get(k, {}), **v} for k, v in new.items()}}
    if b.min_match_confidence is not None:
        if not 0 <= b.min_match_confidence <= 1:
            raise HTTPException(422, "min_match_confidence must be between 0 and 1")
        s["min_match_confidence"] = b.min_match_confidence
    org.settings = s
    n = matcher.rescore(db, org)
    audit(db, u, "risk_policy_updated", None, {"rescored": n})
    trends.record_snapshot(db, org.id)
    db.commit()
    return {"saved": True, "rescored": n}


@router.delete("/risk-policy")
def reset_policy(u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    org = db.get(Organization, u.org_id)
    s = dict(org.settings or {})
    s.pop("risk_policy", None)
    s.pop("min_match_confidence", None)
    org.settings = s
    n = matcher.rescore(db, org)
    audit(db, u, "risk_policy_reset", None, {"rescored": n})
    db.commit()
    return {"reset": True, "rescored": n}
