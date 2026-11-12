"""Continuous monitoring: scheduled scans, stale-asset detection, optional daily intel refresh."""
import logging
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from ..config import settings
from ..db import SessionLocal
from ..models import Organization, Scan, ScheduledScan, utcnow
from . import intel, matcher, pipeline, scanner, trends

log = logging.getLogger("asivm.scheduler")
_sched: BackgroundScheduler | None = None


def tick():
    ids = []
    with SessionLocal() as db:
        for s in db.scalars(select(ScheduledScan).where(ScheduledScan.enabled == True)):  # noqa: E712
            if s.last_run is None or s.last_run + timedelta(hours=s.interval_hours) <= utcnow():
                s.last_run = utcnow()
                sc = Scan(org_id=s.org_id, tool=s.tool, target=s.target, profile=s.profile,
                          requested_by=f"schedule#{s.id}")
                db.add(sc)
                db.flush()
                ids.append(sc.id)
        db.commit()
    for i in ids:
        scanner.run_scan(i)


def maintenance():
    with SessionLocal() as db:
        pipeline.mark_stale(db, settings.stale_after_days)
        pipeline.expire_acceptances(db)
        for org in db.scalars(select(Organization)):
            trends.record_snapshot(db, org.id)
        db.commit()


def intel_refresh():
    with SessionLocal() as db:
        intel.run_sync(db, ["kev", "epss"])
        for org in db.scalars(select(Organization)):
            matcher.rescore(db, org)
        db.commit()


def start():
    global _sched
    if not settings.scheduler_enabled or _sched:
        return
    _sched = BackgroundScheduler(daemon=True)
    _sched.add_job(tick, "interval", minutes=1, max_instances=1, coalesce=True)
    _sched.add_job(maintenance, "interval", hours=6, max_instances=1)
    _sched.add_job(maintenance, "date")  # also once at startup
    if settings.auto_intel_sync:
        _sched.add_job(intel_refresh, "interval", hours=24, max_instances=1)
    _sched.start()


def stop():
    global _sched
    if _sched:
        _sched.shutdown(wait=False)
        _sched = None
