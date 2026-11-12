import json
import re
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import audit, current_user, require
from ..models import Scan, ScheduledScan, ScopeRule, User, row, utcnow
from ..services import parsers, pipeline, scanner, scope, trends

router = APIRouter(prefix="/api", tags=["scanning"])


class RuleIn(BaseModel):
    kind: str = Field(pattern="^(cidr|hostname)$")
    value: str
    action: str = Field("allow", pattern="^(allow|deny)$")
    note: str | None = None


class TargetIn(BaseModel):
    target: str


class ScanIn(BaseModel):
    target: str
    tool: str = Field("nmap", pattern="^(nmap|discovery|trivy)$")
    profile: str = "standard"
    asset_id: int | None = None


class ScheduleIn(BaseModel):
    target: str
    tool: str = Field("nmap", pattern="^(nmap|discovery)$")
    profile: str = "standard"
    interval_hours: int = Field(24, ge=1, le=24 * 30)


# ------------------------------------------------------------------ scope
@router.get("/scope")
def list_scope(u: User = Depends(current_user), db: Session = Depends(get_db)):
    return [row(r) for r in db.scalars(select(ScopeRule).where(ScopeRule.org_id == u.org_id))]


@router.post("/scope", status_code=201)
def add_rule(b: RuleIn, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    if b.kind == "cidr":
        import ipaddress
        try:
            b.value = str(ipaddress.ip_network(b.value, strict=False))
        except ValueError:
            raise HTTPException(422, "invalid CIDR")
    elif not scope.HOST_RE.match(b.value.replace("*", "x")):
        raise HTTPException(422, "invalid hostname pattern")
    r = ScopeRule(org_id=u.org_id, **b.model_dump())
    db.add(r)
    audit(db, u, "scope_rule_added", b.value, b.model_dump())
    db.commit()
    return row(r)


@router.delete("/scope/{rule_id}")
def del_rule(rule_id: int, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    r = db.get(ScopeRule, rule_id)
    if not r or r.org_id != u.org_id:
        raise HTTPException(404, "rule not found")
    db.delete(r)
    audit(db, u, "scope_rule_deleted", r.value)
    db.commit()
    return {"deleted": rule_id}


@router.post("/scope/validate")
def validate(b: TargetIn, u: User = Depends(current_user), db: Session = Depends(get_db)):
    d = scope.validate_target(db, u.org_id, b.target)
    return {"allowed": d.allowed, "reason": d.reason}


# ------------------------------------------------------------------ scans
@router.get("/scans")
def list_scans(u: User = Depends(current_user), db: Session = Depends(get_db)):
    return [row(s) for s in db.scalars(select(Scan).where(Scan.org_id == u.org_id).order_by(Scan.id.desc()).limit(100))]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.get(Scan, scan_id)
    if not s or s.org_id != u.org_id:
        raise HTTPException(404, "scan not found")
    return row(s)


def create_scan(db, u, b: ScanIn) -> Scan:
    if b.tool in ("nmap", "discovery"):
        if b.profile not in scanner.PROFILES or b.profile == "discovery" and b.tool == "nmap":
            raise HTTPException(422, f"profile must be one of {[p for p in scanner.PROFILES if p != 'discovery']}")
        d = scope.validate_target(db, u.org_id, b.target)
        if not d.allowed:
            audit(db, u, "scan_denied", b.target, {"reason": d.reason})
            db.commit()
            raise HTTPException(422, f"Target rejected by scope validator: {d.reason}")
    elif not scanner.IMAGE_RE.match(b.target):
        raise HTTPException(422, "invalid image name")
    s = Scan(org_id=u.org_id, tool=b.tool, target=b.target, profile=b.profile, requested_by=u.email,
             summary={"asset_id": b.asset_id} if b.asset_id else {})
    db.add(s)
    audit(db, u, "scan_requested", b.target, {"tool": b.tool, "profile": b.profile})
    db.commit()
    return s


@router.post("/scans", status_code=202)
def start_scan(b: ScanIn, bg: BackgroundTasks, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    s = create_scan(db, u, b)
    bg.add_task(scanner.run_scan, s.id)
    return row(s)


async def _import(kind, file, u, db):
    raw = await file.read()
    if len(raw) > 50_000_000:
        raise HTTPException(413, "file too large")
    s = Scan(org_id=u.org_id, tool=kind, target=f"import:{file.filename}", profile="import",
             requested_by=u.email, status="running", started_at=utcnow())
    db.add(s)
    db.flush()
    try:
        if kind == "nmap":
            s.summary = pipeline.ingest_hosts(db, s, parsers.parse_nmap_xml(raw.decode()))
        else:
            art, vulns = parsers.parse_trivy(json.loads(raw))
            s.target = f"import:{art or file.filename}"
            s.summary = pipeline.ingest_trivy(db, s, art, vulns)
        s.status = "completed"
    except Exception as e:
        db.rollback()
        raise HTTPException(422, f"could not import: {e}")
    s.finished_at = utcnow()
    trends.record_snapshot(db, u.org_id)
    audit(db, u, f"import_{kind}", file.filename, s.summary)
    db.commit()
    return row(s)


@router.post("/scans/import-nmap")
async def import_nmap(file: UploadFile = File(...), u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    return await _import("nmap", file, u, db)


@router.post("/scans/import-trivy")
async def import_trivy(file: UploadFile = File(...), u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    return await _import("trivy", file, u, db)


# ------------------------------------------------------------------ schedules (continuous monitoring)
@router.get("/schedules")
def schedules(u: User = Depends(current_user), db: Session = Depends(get_db)):
    return [row(s) for s in db.scalars(select(ScheduledScan).where(ScheduledScan.org_id == u.org_id))]


@router.post("/schedules", status_code=201)
def add_schedule(b: ScheduleIn, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    d = scope.validate_target(db, u.org_id, b.target)
    if not d.allowed:
        raise HTTPException(422, f"Target rejected by scope validator: {d.reason}")
    s = ScheduledScan(org_id=u.org_id, created_by=u.email, **b.model_dump())
    db.add(s)
    audit(db, u, "schedule_created", b.target, b.model_dump())
    db.commit()
    return row(s)


@router.delete("/schedules/{sid}")
def del_schedule(sid: int, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    s = db.get(ScheduledScan, sid)
    if not s or s.org_id != u.org_id:
        raise HTTPException(404, "schedule not found")
    db.delete(s)
    db.commit()
    return {"deleted": sid}
