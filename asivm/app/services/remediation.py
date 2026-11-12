"""Finding state machine: open, assigned, in_progress, fixed, verified, reopened (+ accepted_risk)."""
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import Finding, FindingEvent, utcnow

OPEN_STATES = ("open", "assigned", "in_progress", "reopened")
TRANSITIONS = {
    "open": {"assigned", "in_progress", "fixed", "accepted_risk"},
    "assigned": {"open", "in_progress", "fixed", "accepted_risk"},
    "in_progress": {"assigned", "fixed", "accepted_risk"},
    "reopened": {"assigned", "in_progress", "fixed", "accepted_risk"},
    "fixed": {"reopened"},            # -> verified only by re-observation (system)
    "verified": {"reopened"},
    "accepted_risk": {"open"},
}


class TransitionError(ValueError):
    pass


def set_state(db: Session, f: Finding, to: str, actor: str, note: str | None = None):
    db.add(FindingEvent(finding_id=f.id, org_id=f.org_id, from_state=f.state, to_state=to, actor=actor, note=note))
    f.state = to
    if to in ("fixed", "verified"):
        f.closed_at = f.closed_at or utcnow()
    elif to in OPEN_STATES:
        f.closed_at = None


def user_transition(db: Session, f: Finding, to: str, actor: str, note: str | None = None,
                    assignee: str | None = None, accepted_days: int | None = None):
    if to == "verified":
        raise TransitionError("'verified' is set only by a re-scan that no longer observes the issue; use /verify")
    if to not in TRANSITIONS.get(f.state, set()):
        raise TransitionError(f"cannot move from '{f.state}' to '{to}'")
    if to == "assigned":
        if not (assignee or f.assignee):
            raise TransitionError("assigned requires an assignee")
        f.assignee = assignee or f.assignee
    if to == "accepted_risk":
        if not note:
            raise TransitionError("accepting risk requires a documented justification (note)")
        f.accepted_until = utcnow() + timedelta(days=accepted_days or 90)
    if to == "open":
        f.accepted_until = None
    set_state(db, f, to, actor, note)


def system_reobserved(db: Session, f: Finding, scan_id):
    """Issue seen again in a scan."""
    if f.state in ("fixed", "verified"):
        set_state(db, f, "reopened", "system", f"re-observed in scan #{scan_id}" if scan_id else "re-observed")
    elif f.state == "accepted_risk" and f.accepted_until and f.accepted_until < utcnow():
        f.accepted_until = None
        set_state(db, f, "open", "system", "risk acceptance expired")


def system_vanished(db: Session, f: Finding, scan_id):
    """Issue no longer observed on a re-scanned asset -> verified closure."""
    note = f"no longer observed in scan #{scan_id}"
    if f.state in OPEN_STATES:
        set_state(db, f, "fixed", "system", note)
    if f.state == "fixed":
        set_state(db, f, "verified", "system", f"verified by re-observation: {note}")
