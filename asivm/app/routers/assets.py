import csv
import io

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import audit, current_user, require
from ..models import (Asset, AssetIdentifier, ChangeEvent, Finding, Organization, ServiceObservation,
                      Software, User, row, utcnow)
from ..services import identity, matcher, remediation

router = APIRouter(prefix="/api/assets", tags=["assets"])
EXPOSURES = ("internal", "dmz", "internet")


class AssetIn(BaseModel):
    name: str | None = None
    identifiers: dict
    owner: str | None = None
    owner_email: str | None = None
    location: str | None = None
    department: str | None = None
    asset_type: str | None = None
    criticality: int | None = None
    exposure: str | None = None


class AssetPatch(BaseModel):
    name: str | None = None
    owner: str | None = None
    owner_email: str | None = None
    location: str | None = None
    department: str | None = None
    asset_type: str | None = None
    criticality: int | None = None
    exposure: str | None = None
    notes: str | None = None


class SoftwareIn(BaseModel):
    name: str
    version: str
    cpe: str | None = None


def _apply(a: Asset, d: dict):
    if d.get("criticality") is not None and not 1 <= d["criticality"] <= 5:
        raise HTTPException(422, "criticality must be 1-5")
    if d.get("exposure") is not None and d["exposure"] not in EXPOSURES:
        raise HTTPException(422, f"exposure must be one of {EXPOSURES}")
    for k, v in d.items():
        if v is not None and k != "identifiers":
            setattr(a, k, v)


def get_asset(db, user, asset_id) -> Asset:
    a = db.get(Asset, asset_id)
    if not a or a.org_id != user.org_id:
        raise HTTPException(404, "asset not found")
    return a


def _summaries(db, assets):
    ids = [a.id for a in assets]
    idents, counts = {}, {}
    for r in db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id.in_(ids), AssetIdentifier.active == True)):  # noqa: E712
        idents.setdefault(r.asset_id, {}).setdefault(r.type, []).append(r.value)
    for aid, n in db.execute(select(Finding.asset_id, func.count()).where(
            Finding.asset_id.in_(ids), Finding.state.in_(remediation.OPEN_STATES)).group_by(Finding.asset_id)):
        counts[aid] = n
    return [{**row(a), "identifiers": idents.get(a.id, {}), "open_findings": counts.get(a.id, 0)} for a in assets]


@router.get("")
def list_assets(q: str | None = None, owner: str | None = None, status: str | None = None,
                limit: int = Query(200, le=1000), u: User = Depends(current_user), db: Session = Depends(get_db)):
    st = select(Asset).where(Asset.org_id == u.org_id, Asset.status != "merged")
    if status:
        st = st.where(Asset.status == status)
    if owner:
        st = st.where(Asset.owner == owner)
    if q:
        sub = select(AssetIdentifier.asset_id).where(AssetIdentifier.org_id == u.org_id,
                                                      AssetIdentifier.value.ilike(f"%{q}%"))
        st = st.where(Asset.name.ilike(f"%{q}%") | Asset.id.in_(sub))
    return _summaries(db, db.scalars(st.order_by(Asset.id).limit(limit)).all())


@router.post("", status_code=201)
def create_asset(b: AssetIn, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    try:
        res = identity.resolve(db, u.org_id, b.identifiers, source="manual", name=b.name, actor=u.email)
    except ValueError as e:
        raise HTTPException(422, str(e))
    _apply(res.asset, b.model_dump(exclude={"identifiers", "name"}))
    if b.name:
        res.asset.name = b.name
    audit(db, u, "asset_resolved", f"asset:{res.asset.id}", {"created": res.created, "reason": res.reason})
    db.commit()
    return {"asset": _summaries(db, [res.asset])[0], "created": res.created,
            "confidence": res.confidence, "reason": res.reason, "merged": res.merged}


@router.post("/import-csv")
async def import_csv(file: UploadFile = File(...), u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(413, "file too large (5 MB max)")
    out = {"created": 0, "matched_existing": 0, "errors": []}
    for i, r in enumerate(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))), start=2):
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
        ids = {t: r[t] for t in ("ip", "hostname", "fqdn", "mac", "cloud_id", "serial") if r.get(t)}
        try:
            res = identity.resolve(db, u.org_id, ids, source="csv", name=r.get("name") or None, actor=u.email)
            d = {k: r.get(k) or None for k in ("owner", "owner_email", "location", "department", "asset_type", "exposure")}
            d["criticality"] = int(r["criticality"]) if r.get("criticality") else None
            _apply(res.asset, d)
            out["created" if res.created else "matched_existing"] += 1
        except (ValueError, HTTPException) as e:
            out["errors"].append({"line": i, "error": getattr(e, "detail", str(e))})
    audit(db, u, "asset_csv_import", None, {k: (v if k != "errors" else len(v)) for k, v in out.items()})
    db.commit()
    return out


@router.get("/{asset_id}")
def detail(asset_id: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    a = get_asset(db, u, asset_id)
    ids = [row(i) for i in db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id == a.id))]
    svc = [row(s) for s in db.scalars(select(ServiceObservation).where(ServiceObservation.asset_id == a.id).order_by(ServiceObservation.port))]
    sw = [row(s) for s in db.scalars(select(Software).where(Software.asset_id == a.id, Software.active == True))]  # noqa: E712
    fnd = [row(f, exclude=("evidence", "risk_inputs")) for f in db.scalars(
        select(Finding).where(Finding.asset_id == a.id).order_by(Finding.risk_score.desc()))]
    ch = [row(c) for c in db.scalars(select(ChangeEvent).where(ChangeEvent.asset_id == a.id).order_by(ChangeEvent.id.desc()).limit(50))]
    return {**row(a), "identifiers": ids, "services": svc, "software": sw, "findings": fnd, "changes": ch}


@router.patch("/{asset_id}")
def patch(asset_id: int, b: AssetPatch, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    a = get_asset(db, u, asset_id)
    d = b.model_dump(exclude_none=True)
    _apply(a, d)
    if {"criticality", "exposure"} & d.keys():
        matcher.rescore(db, db.get(Organization, u.org_id), a.id)
    audit(db, u, "asset_updated", f"asset:{a.id}", d)
    db.commit()
    return row(a)


@router.post("/{asset_id}/merge/{other_id}")
def merge(asset_id: int, other_id: int, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    keep, drop = get_asset(db, u, asset_id), get_asset(db, u, other_id)
    try:
        identity.merge_assets(db, keep, drop, u.email)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(db, u, "asset_merged", f"asset:{keep.id}", {"merged": drop.id})
    db.commit()
    return {"kept": keep.id, "merged": drop.id}


@router.post("/{asset_id}/software", status_code=201)
def add_software(asset_id: int, b: SoftwareIn, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    a = get_asset(db, u, asset_id)
    s = Software(org_id=u.org_id, asset_id=a.id, source="manual", name=b.name, version=b.version, cpe=b.cpe,
                 evidence={"added_by": u.email})
    db.add(s)
    db.flush()
    stats = matcher.match_asset(db, db.get(Organization, u.org_id), a, None, reconcile=False)
    audit(db, u, "software_added", f"asset:{a.id}", b.model_dump())
    db.commit()
    return {"software": row(s), "matching": stats}
