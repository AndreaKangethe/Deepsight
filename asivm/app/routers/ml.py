"""ML intelligence: model registry, risk assessment, anomaly triage, analyst feedback."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import audit, current_user, require
from ..ml import service, train
from ..ml.features import CLASSES, FEATURE_VERSION, asset_features
from ..models import (Asset, AnomalyEvent, Finding, MLFeedback, MLModel, MLPrediction, User, row, utcnow)

router = APIRouter(prefix="/api/ml", tags=["ml"])
TIER_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
NOTICE = {"synthetic": "Trained on synthetic demonstration data. Scores show the pipeline works; they are not "
                       "validated predictions of real-world risk.",
          "feedback": "Trained on analyst-approved labels from this organisation.",
          "csv": "Trained on an imported labelled dataset."}


class TrainIn(BaseModel):
    kind: str = "risk"
    source: str = "synthetic"


class FeedbackIn(BaseModel):
    label: str
    note: str | None = None


class ReviewIn(BaseModel):
    status: str
    note: str | None = None


def _model_view(m: MLModel) -> dict:
    d = row(m, exclude=("path",))
    d["notice"] = NOTICE.get(m.data_source, "")
    return d


def _asset(db, u, asset_id) -> Asset:
    a = db.get(Asset, asset_id)
    if not a or a.org_id != u.org_id:
        raise HTTPException(404, "Asset not found")
    return a


def _pred_view(p: MLPrediction, db=None) -> dict:
    d = row(p)
    d["confidence"] = d["probabilities"].get("confidence")
    d["probabilities"] = {k: v for k, v in d["probabilities"].items() if k in CLASSES}
    return d


def _train(db, u, kind, source) -> MLModel:
    try:
        m = train.train_and_register(db, u.org_id, kind, source, u.email)
    except train.DatasetError as e:
        raise HTTPException(422, str(e))
    audit(db, u, "ml_train", m.version, {"kind": kind, "source": source})
    return m


@router.get("/status")
def status(u: User = Depends(current_user), db: Session = Depends(get_db)):
    models = db.scalars(select(MLModel).where(MLModel.org_id == u.org_id).order_by(MLModel.id.desc()).limit(20)).all()
    act = {k: service.active(db, u.org_id, k) for k in ("risk", "anomaly")}
    return {"feature_version": FEATURE_VERSION, "classes": CLASSES,
            "active": {k: _model_view(m) if m else None for k, m in act.items()},
            "models": [_model_view(m) for m in models],
            "open_anomalies": db.scalar(select(func.count()).select_from(AnomalyEvent).where(
                AnomalyEvent.org_id == u.org_id, AnomalyEvent.status == "open")) or 0,
            "approved_feedback": db.scalar(select(func.count()).select_from(MLFeedback).where(
                MLFeedback.org_id == u.org_id, MLFeedback.approved == True)) or 0}  # noqa: E712


@router.post("/train", status_code=201)
def train_model(b: TrainIn, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    if b.kind not in ("risk", "anomaly") or b.source not in ("synthetic", "feedback"):
        raise HTTPException(422, "kind must be risk|anomaly and source synthetic|feedback")
    m = _train(db, u, b.kind, b.source)
    db.commit()
    return _model_view(m)


@router.post("/bootstrap", status_code=201)
def bootstrap(u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    """One click for demos: train both models on the synthetic baseline and promote them (admin action, audited)."""
    out = []
    for kind in ("risk", "anomaly"):
        m = service.promote(db, _train(db, u, kind, "synthetic"), u.email, force=True)
        audit(db, u, "ml_promote", m.version, {"forced": True, "bootstrap": True})
        out.append(_model_view(m))
    db.commit()
    return out


@router.post("/models/{model_id}/promote")
def promote(model_id: int, force: bool = False, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    m = db.get(MLModel, model_id)
    if not m or m.org_id != u.org_id:
        raise HTTPException(404, "Model not found")
    if m.status == "retired":
        raise HTTPException(409, "Retired models cannot be promoted")
    try:
        service.promote(db, m, u.email, force)
    except ValueError as e:
        raise HTTPException(409, str(e))
    audit(db, u, "ml_promote", m.version, {"forced": force})
    db.commit()
    return _model_view(m)


# ------------------------------------------------------------------ risk
@router.post("/assets/{asset_id}/assess")
def assess(asset_id: int, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    a = _asset(db, u, asset_id)
    try:
        p = service.assess_asset(db, a, u.email)
    except service.NoActiveModel as e:
        raise HTTPException(409, str(e))
    db.commit()
    return _pred_view(p)


@router.post("/assess-all")
def assess_all(u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    assets = db.scalars(select(Asset).where(Asset.org_id == u.org_id, Asset.status != "merged")).all()
    try:
        for a in assets:
            service.assess_asset(db, a, u.email)
    except service.NoActiveModel as e:
        raise HTTPException(409, str(e))
    db.commit()
    return {"assessed": len(assets)}


@router.get("/assessments")
def assessments(u: User = Depends(current_user), db: Session = Depends(get_db)):
    latest = (select(func.max(MLPrediction.id)).where(MLPrediction.org_id == u.org_id)
              .group_by(MLPrediction.asset_id))
    rows = db.execute(select(MLPrediction, Asset).join(Asset, Asset.id == MLPrediction.asset_id)
                      .where(MLPrediction.id.in_(latest)).order_by(MLPrediction.risk_index.desc())).all()
    tiers = {}
    for aid, tier in db.execute(select(Finding.asset_id, Finding.risk_tier).where(
            Finding.org_id == u.org_id, Finding.state.in_(("open", "assigned", "in_progress", "reopened")))):
        if TIER_RANK.get(tier, 0) >= TIER_RANK.get(tiers.get(aid, "low"), 0):
            tiers[aid] = tier
    open_anom = {x for x in db.scalars(select(AnomalyEvent.asset_id).where(
        AnomalyEvent.org_id == u.org_id, AnomalyEvent.status == "open"))}
    out = []
    for p, a in rows:
        v = _pred_view(p)
        out.append({**{k: v[k] for k in ("id", "asset_id", "predicted", "confidence", "risk_index", "model_version", "at")},
                    "asset_name": a.name, "exposure": a.exposure, "criticality": a.criticality,
                    "rule_tier": tiers.get(a.id, "none"), "anomaly_open": a.id in open_anom,
                    "top_factor": next((f["text"] for f in v["factors"] if f["effect"] == "raises"), None)})
    return out


@router.get("/assets/{asset_id}")
def asset_detail(asset_id: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    a = _asset(db, u, asset_id)
    ps = db.scalars(select(MLPrediction).where(MLPrediction.asset_id == a.id).order_by(MLPrediction.id.desc()).limit(10)).all()
    an = db.scalars(select(AnomalyEvent).where(AnomalyEvent.asset_id == a.id).order_by(AnomalyEvent.id.desc()).limit(5)).all()
    m = db.get(MLModel, db.scalar(select(MLModel.id).where(MLModel.version == ps[0].model_version))) if ps else None
    return {"asset": {"id": a.id, "name": a.name}, "latest": _pred_view(ps[0]) if ps else None,
            "history": [{"at": p.at.isoformat(), "predicted": p.predicted, "risk_index": p.risk_index,
                         "model_version": p.model_version} for p in ps],
            "anomalies": [row(x) for x in an], "notice": NOTICE.get(m.data_source, "") if m else None}


# ------------------------------------------------------------------ feedback (labels for future training)
@router.post("/assets/{asset_id}/feedback", status_code=201)
def feedback(asset_id: int, b: FeedbackIn, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    a = _asset(db, u, asset_id)
    if b.label not in CLASSES:
        raise HTTPException(422, "label must be one of: " + ", ".join(CLASSES))
    last = db.scalar(select(MLPrediction).where(MLPrediction.asset_id == a.id).order_by(MLPrediction.id.desc()).limit(1))
    fb = MLFeedback(org_id=u.org_id, asset_id=a.id, prediction_id=last.id if last else None, label=b.label, note=b.note,
                    features=last.features if last else asset_features(db, a), feature_version=FEATURE_VERSION,
                    submitted_by=u.email)
    db.add(fb)
    audit(db, u, "ml_feedback", a.name, {"label": b.label})
    db.commit()
    return row(fb)


@router.get("/feedback")
def list_feedback(u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    rs = db.scalars(select(MLFeedback).where(MLFeedback.org_id == u.org_id).order_by(MLFeedback.id.desc()).limit(200)).all()
    return [row(r, exclude=("features",)) for r in rs]


@router.post("/feedback/{fb_id}/approve")
def approve_feedback(fb_id: int, u: User = Depends(require("admin")), db: Session = Depends(get_db)):
    fb = db.get(MLFeedback, fb_id)
    if not fb or fb.org_id != u.org_id:
        raise HTTPException(404, "Feedback not found")
    if fb.submitted_by == u.email:
        raise HTTPException(403, "A label must be approved by someone other than its author")
    fb.approved, fb.approved_by = True, u.email
    audit(db, u, "ml_feedback_approved", str(fb.id))
    db.commit()
    return row(fb, exclude=("features",))


# ------------------------------------------------------------------ anomalies
@router.get("/anomalies")
def anomalies(status: str | None = None, u: User = Depends(current_user), db: Session = Depends(get_db)):
    st = select(AnomalyEvent, Asset).join(Asset, Asset.id == AnomalyEvent.asset_id).where(AnomalyEvent.org_id == u.org_id)
    if status:
        st = st.where(AnomalyEvent.status == status)
    return [{**row(e), "asset_name": a.name} for e, a in db.execute(st.order_by(AnomalyEvent.id.desc()).limit(100))]


@router.post("/anomalies/rescan")
def rescan(u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    try:
        n = service.rescan_anomalies(db, u.org_id)
    except service.NoActiveModel as e:
        raise HTTPException(409, str(e))
    db.commit()
    return {"new_anomalies": n}


@router.post("/anomalies/{event_id}/review")
def review(event_id: int, b: ReviewIn, u: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    e = db.get(AnomalyEvent, event_id)
    if not e or e.org_id != u.org_id:
        raise HTTPException(404, "Anomaly not found")
    if b.status not in ("confirmed", "dismissed"):
        raise HTTPException(422, "status must be confirmed or dismissed")
    e.status, e.reviewed_by, e.review_note, e.reviewed_at = b.status, u.email, b.note, utcnow()
    audit(db, u, "ml_anomaly_review", str(e.id), {"status": b.status})
    db.commit()
    return row(e)
