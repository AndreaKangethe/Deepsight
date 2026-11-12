"""Inference: registry lookups, risk prediction with SHAP explanations, shadow comparison, anomaly scoring."""
import logging
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Asset, AssetSnapshot, AnomalyEvent, MLModel, MLPrediction, utcnow
from .features import (ANOMALY_FEATURES, CLASSES, FEATURE_VERSION, RISK_FEATURES, asset_features, delta_features,
                       phrase, record_snapshot, vector)

log = logging.getLogger("asivm.ml")
RISK_INDEX_WEIGHTS = np.array([5.0, 35.0, 65.0, 95.0])  # class -> 0..100 index for sorting only
_cache: dict = {}


class NoActiveModel(RuntimeError):
    pass


def active(db: Session, org_id: int, kind: str) -> MLModel | None:
    return db.scalar(select(MLModel).where(MLModel.org_id == org_id, MLModel.kind == kind, MLModel.status == "active"))


def shadows(db: Session, org_id: int, kind: str) -> list[MLModel]:
    return list(db.scalars(select(MLModel).where(MLModel.org_id == org_id, MLModel.kind == kind,
                                                 MLModel.status == "shadow").order_by(MLModel.id.desc()).limit(3)))


def load(m: MLModel) -> dict:
    p = Path(m.path)
    key = (str(p), p.stat().st_mtime if p.exists() else 0)
    if key not in _cache:
        if not p.exists():
            raise NoActiveModel(f"model file for {m.version} is missing")
        b = joblib.load(p)
        if b.get("feature_version") != FEATURE_VERSION:
            raise NoActiveModel(f"{m.version} was trained on features {b.get('feature_version')}, "
                                f"this build computes {FEATURE_VERSION}")
        if b.get("sklearn_version") != sklearn.__version__:
            raise NoActiveModel(f"{m.version} was trained with scikit-learn {b.get('sklearn_version')} but this build "
                                f"runs {sklearn.__version__}; retrain the model")
        _cache.clear()
        _cache[key] = b
    return _cache[key]


def _shap_matrix(bundle: dict, x: np.ndarray) -> np.ndarray | None:
    """SHAP values, shape (features, classes), or None if SHAP is unavailable."""
    try:
        if "explainer" not in bundle:
            import shap
            bundle["explainer"] = shap.TreeExplainer(bundle["model"])
        sv = bundle["explainer"].shap_values(x)
        sv = np.stack(sv, axis=-1) if isinstance(sv, list) else np.asarray(sv)
        return sv[0]
    except Exception as e:  # explanation must never block a prediction
        log.warning("SHAP unavailable (%s); using importance-weighted deviation instead", e)
        return None


def explain(bundle: dict, x: np.ndarray, feats: dict, top: int = 6) -> list[dict]:
    names = bundle["features"]
    sv = _shap_matrix(bundle, x)
    if sv is not None:
        contrib = sv @ RISK_INDEX_WEIGHTS / 100.0  # contribution to the 0..1 risk index; +ve raises risk
        method = "shap"
    else:
        z = (x[0] - np.array(bundle["means"])) / np.array(bundle["stds"])
        contrib = np.clip(z, -3, 3) * bundle["model"].feature_importances_
        method = "importance_deviation"
    order = np.argsort(-np.abs(contrib))[:top]
    return [{"feature": names[i], "value": float(x[0][i]), "contribution": round(float(contrib[i]), 4),
             "effect": "raises" if contrib[i] > 0 else "lowers", "text": phrase(names[i], float(x[0][i])),
             "method": method} for i in order if abs(contrib[i]) > 1e-4]


def predict_risk(bundle: dict, feats: dict, with_explanation: bool = True) -> dict:
    x = np.array([vector(feats, bundle["features"])])
    proba = bundle["model"].predict_proba(x)[0]
    full = np.zeros(len(CLASSES))
    for c, p in zip(bundle["model"].classes_, proba):
        full[int(c)] = p
    k = int(full.argmax())
    out = {"predicted": CLASSES[k], "confidence": round(float(full[k]), 4),
           "probabilities": {c: round(float(p), 4) for c, p in zip(CLASSES, full)},
           "risk_index": round(float(full @ RISK_INDEX_WEIGHTS), 1)}
    if with_explanation:
        out["factors"] = explain(bundle, x, feats)
    return out


def assess_asset(db: Session, asset: Asset, actor: str) -> MLPrediction:
    model = active(db, asset.org_id, "risk")
    if not model:
        raise NoActiveModel("No active risk model. An administrator must train and promote one first.")
    feats = asset_features(db, asset)
    res = predict_risk(load(model), feats)
    sh = []
    for s in shadows(db, asset.org_id, "risk"):
        try:
            r = predict_risk(load(s), feats, with_explanation=False)
            sh.append({"model_version": s.version, "predicted": r["predicted"], "confidence": r["confidence"]})
        except Exception as e:
            log.warning("shadow model %s failed: %s", s.version, e)
    p = MLPrediction(org_id=asset.org_id, asset_id=asset.id, model_version=model.version, feature_version=FEATURE_VERSION,
                     predicted=res["predicted"], probabilities={**res["probabilities"], "confidence": res["confidence"]},
                     risk_index=res["risk_index"], features=feats, factors=res["factors"], shadow=sh, actor=actor)
    db.add(p)
    db.flush()
    return p


# ------------------------------------------------------------------ anomaly detection
def score_anomaly(bundle: dict, deltas: dict) -> dict:
    x = np.array([vector(deltas, bundle["features"])])
    iso = bundle["model"]
    z = (x[0] - np.array(bundle["median"])) / np.array(bundle["mad"])
    order = np.argsort(-np.abs(z))[:3]
    return {"is_anomaly": bool(iso.predict(x)[0] == -1), "score": round(float(-iso.score_samples(x)[0]), 4),
            "factors": [{"feature": bundle["features"][i], "value": float(x[0][i]), "robust_z": round(float(z[i]), 1),
                         "text": phrase(bundle["features"][i], float(x[0][i]))} for i in order if abs(z[i]) >= 2.0]}


def history(db: Session, asset_id: int, before_id: int, n: int = 5) -> list[AssetSnapshot]:
    return list(db.scalars(select(AssetSnapshot).where(AssetSnapshot.asset_id == asset_id, AssetSnapshot.id < before_id)
                           .order_by(AssetSnapshot.id.desc()).limit(n)))


def check_snapshot(db: Session, snap: AssetSnapshot, model: MLModel | None = None) -> AnomalyEvent | None:
    """Score one snapshot against the asset's own earlier snapshots. Idempotent per snapshot."""
    model = model or active(db, snap.org_id, "anomaly")
    if not model or db.scalar(select(AnomalyEvent.id).where(AnomalyEvent.snapshot_id == snap.id)):
        return None
    d = delta_features(snap.features, [h.features for h in history(db, snap.asset_id, snap.id)])
    if d is None:
        return None
    r = score_anomaly(load(model), d)
    if not r["is_anomaly"]:
        return None
    ev = AnomalyEvent(org_id=snap.org_id, asset_id=snap.asset_id, snapshot_id=snap.id, model_version=model.version,
                      score=r["score"], deltas=d, factors=r["factors"])
    db.add(ev)
    db.flush()
    return ev


def on_observation(db: Session, asset: Asset, scan_id=None):
    """Called after every scan/import: store a snapshot and, if an anomaly model is active, score it.
    Never raises: ML problems must not break asset ingestion."""
    try:
        with db.begin_nested():
            check_snapshot(db, record_snapshot(db, asset, scan_id))
    except Exception as e:
        log.warning("ML observation hook failed for asset %s: %s", asset.id, e)


def rescan_anomalies(db: Session, org_id: int) -> int:
    model = active(db, org_id, "anomaly")
    if not model:
        raise NoActiveModel("No active anomaly model. An administrator must train and promote one first.")
    n = 0
    for aid in db.scalars(select(AssetSnapshot.asset_id).where(AssetSnapshot.org_id == org_id).distinct()):
        last = db.scalar(select(AssetSnapshot).where(AssetSnapshot.asset_id == aid).order_by(AssetSnapshot.id.desc()).limit(1))
        n += 1 if check_snapshot(db, last, model) else 0
    return n


def promote(db: Session, model: MLModel, approver: str, force: bool = False) -> MLModel:
    cur = active(db, model.org_id, model.kind)
    if cur and cur.id != model.id and not force:
        key = model.metrics.get("primary", "macro_f1")
        if model.metrics.get(key, 0) < cur.metrics.get(key, 0):
            raise ValueError(f"candidate {key} {model.metrics.get(key)} is below the active model's "
                             f"{cur.metrics.get(key)}; promotion refused (an admin can force it)")
    if cur and cur.id != model.id:
        cur.status = "retired"
    model.status, model.approved_by, model.approved_at = "active", approver, utcnow()
    return model
