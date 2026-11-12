from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Asset, Finding, TrendSnapshot, utcnow
from .remediation import OPEN_STATES


def snapshot_data(db: Session, org_id: int) -> dict:
    tiers = dict(db.execute(select(Finding.risk_tier, func.count()).where(
        Finding.org_id == org_id, Finding.state.in_(OPEN_STATES)).group_by(Finding.risk_tier)).all())
    d = {t: tiers.get(t, 0) for t in ("critical", "high", "medium", "low")}
    d["open"] = sum(d.values())
    d["verified"] = db.scalar(select(func.count()).select_from(Finding).where(
        Finding.org_id == org_id, Finding.state == "verified")) or 0
    d["overdue"] = db.scalar(select(func.count()).select_from(Finding).where(
        Finding.org_id == org_id, Finding.state.in_(OPEN_STATES), Finding.due_at < utcnow())) or 0
    d["assets"] = db.scalar(select(func.count()).select_from(Asset).where(
        Asset.org_id == org_id, Asset.status != "merged")) or 0
    return d


def record_snapshot(db: Session, org_id: int) -> TrendSnapshot:
    day = utcnow().strftime("%Y-%m-%d")
    s = db.scalar(select(TrendSnapshot).where(TrendSnapshot.org_id == org_id, TrendSnapshot.day == day))
    if not s:
        s = TrendSnapshot(org_id=org_id, day=day)
        db.add(s)
    s.data, s.updated_at = snapshot_data(db, org_id), utcnow()
    db.flush()
    return s
