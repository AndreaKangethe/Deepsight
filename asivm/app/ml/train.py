"""Training, validation, evaluation and registration. CLI: python -m app.ml.train --synthetic"""
import argparse
import csv
import logging
import os
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.tree import DecisionTreeClassifier

from ..config import settings
from ..models import MLFeedback, MLModel, utcnow
from . import synth
from .features import ANOMALY_FEATURES, CLASSES, FEATURE_VERSION, RISK_FEATURES, vector

log = logging.getLogger("asivm.ml")
SEED = 42
MIN_ROWS, MIN_GROUPS, MIN_PER_CLASS = 200, 30, 10


class DatasetError(ValueError):
    """Training data failed a safeguard; the message says what to fix."""


def validate_dataset(X, y, groups, ts, min_rows=MIN_ROWS) -> dict:
    X = np.asarray(X, dtype=float)
    if X.ndim != 2 or X.shape[1] != len(RISK_FEATURES):
        raise DatasetError(f"expected {len(RISK_FEATURES)} features ({FEATURE_VERSION}), got shape {X.shape}")
    if len(X) < min_rows:
        raise DatasetError(f"need at least {min_rows} labelled snapshots, have {len(X)}")
    if not np.isfinite(X).all():
        raise DatasetError("dataset contains NaN or infinite values")
    if not set(np.unique(y)) <= set(range(len(CLASSES))):
        raise DatasetError("labels must be one of: " + ", ".join(CLASSES))
    counts = np.bincount(y, minlength=len(CLASSES))
    thin = [CLASSES[i] for i, c in enumerate(counts) if c < MIN_PER_CLASS]
    if thin:
        raise DatasetError(f"too few examples (<{MIN_PER_CLASS}) for class(es): {', '.join(thin)}")
    if len(set(groups)) < MIN_GROUPS:
        raise DatasetError(f"need at least {MIN_GROUPS} distinct assets, have {len(set(groups))}")
    keys = list(zip(groups, ts))
    if len(set(keys)) != len(keys):
        raise DatasetError("duplicate (asset, timestamp) rows found")
    last = {}
    for g, t in keys:
        if g in last and t <= last[g]:
            raise DatasetError(f"timestamps for asset {g} are not strictly increasing")
        last[g] = t
    return {"rows": int(len(X)), "assets": int(len(set(groups))), "class_counts": dict(zip(CLASSES, map(int, counts))),
            "checks": ["shape", "finite", "labels", "min_rows", "class_balance", "min_assets", "duplicates", "timestamps"]}


def _ece(proba, y, bins=10) -> float:
    conf, pred = proba.max(1), proba.argmax(1)
    ok, e = (pred == y).astype(float), 0.0
    for lo in np.linspace(0, 1, bins, endpoint=False):
        m = (conf > lo) & (conf <= lo + 1 / bins)
        if m.any():
            e += m.mean() * abs(ok[m].mean() - conf[m].mean())
    return round(float(e), 4)


def _severity_baseline(Xtr, ytr, Xte) -> np.ndarray:
    """Fair severity-only baseline: a small tree FITTED on the highest CVSS score alone (so thresholds are
    tuned to the data, not guessed). This is what 'rank by severity' can achieve at best."""
    i = [RISK_FEATURES.index("max_cvss")]
    return DecisionTreeClassifier(max_depth=3, random_state=SEED).fit(Xtr[:, i], ytr).predict(Xte[:, i])


def train_risk(X, y, groups, ts, source: str, seed: int = SEED):
    X, y, groups, ts = np.asarray(X, float), np.asarray(y, int), np.asarray(groups), np.asarray(ts)
    report = validate_dataset(X, y, groups, ts)
    mk = lambda: RandomForestClassifier(n_estimators=300, min_samples_leaf=3, class_weight="balanced_subsample",
                                        random_state=seed, n_jobs=-1)
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed).split(X, y, groups))
    if set(groups[tr]) & set(groups[te]):
        raise DatasetError("leakage: an asset appears in both train and test")
    model = mk().fit(X[tr], y[tr])
    proba, pred = model.predict_proba(X[te]), model.predict(X[te])
    labels = list(range(len(CLASSES)))
    rep = classification_report(y[te], pred, labels=labels, target_names=CLASSES, output_dict=True, zero_division=0)
    cv = [f1_score(y[b], mk().fit(X[a], y[a]).predict(X[b]), average="macro")
          for a, b in GroupKFold(n_splits=3).split(X, y, groups)]
    macro = float(f1_score(y[te], pred, average="macro"))
    rule = _severity_baseline(X[tr], y[tr], X[te])
    maj = np.full_like(y[te], np.bincount(y[tr]).argmax())
    imp = sorted(zip(RISK_FEATURES, model.feature_importances_), key=lambda t: -t[1])
    metrics = {
        "primary": "macro_f1", "macro_f1": round(macro, 4), "accuracy": round(float(accuracy_score(y[te], pred)), 4),
        "per_class": {c: {k: round(rep[c][k], 4) for k in ("precision", "recall", "f1-score")} | {"support": int(rep[c]["support"])}
                      for c in CLASSES},
        "critical_recall": round(rep["critical"]["recall"], 4),
        "confusion_matrix": confusion_matrix(y[te], pred, labels=labels).tolist(),
        "ece": _ece(proba, y[te]),
        "cv_macro_f1_mean": round(float(np.mean(cv)), 4), "cv_macro_f1_std": round(float(np.std(cv)), 4),
        "baselines": {"majority_class_macro_f1": round(float(f1_score(y[te], maj, average="macro", zero_division=0)), 4),
                      "severity_only_tree_macro_f1": round(float(f1_score(y[te], rule, average="macro")), 4)},
        "top_features": [{"feature": f, "importance": round(float(v), 4)} for f, v in imp[:8]],
        "evaluation": {"split": "grouped by asset, 25% held out", "train_rows": int(len(tr)), "test_rows": int(len(te)),
                       "train_assets": int(len(set(groups[tr]))), "test_assets": int(len(set(groups[te]))),
                       "leakage_check": "passed: no asset in both train and test"},
        "dataset": report, "probabilities_calibrated": False,
    }
    final = mk().fit(X, y)  # deployed model uses all validated data; metrics above come from the held-out split
    bundle = {"kind": "risk", "model": final, "features": list(RISK_FEATURES), "classes": list(CLASSES),
              "feature_version": FEATURE_VERSION, "sklearn_version": sklearn.__version__, "means": X.mean(0).tolist(), "stds": (X.std(0) + 1e-9).tolist()}
    return bundle, metrics, "random_forest", len(X)


ANOMALY_TYPES = {1: "services_only", 2: "findings_only", 3: "services_and_findings"}


def train_anomaly(Xa, ya, ga, ta=None, seed: int = SEED):
    Xa, ya, ga = np.asarray(Xa, float), np.asarray(ya, int), np.asarray(ga)
    if len(Xa) < MIN_ROWS:
        raise DatasetError(f"need at least {MIN_ROWS} change observations, have {len(Xa)}")
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed).split(Xa, ya, ga))
    contamination = 0.05  # share of observations flagged; tune with analyst confirm/dismiss feedback
    mk = lambda: IsolationForest(n_estimators=300, contamination=contamination, random_state=seed)
    pred = (mk().fit(Xa[tr]).predict(Xa[te]) == -1).astype(int)  # trained WITHOUT labels
    by_type = {}
    if ta is not None:  # recall for each kind of injected change, so a blind spot cannot hide in one number
        ta = np.asarray(ta, int)
        for k, name in ANOMALY_TYPES.items():
            m = ta[te] == k
            by_type[name] = {"injected": int(m.sum()), "recall": round(float(pred[m].mean()), 4) if m.any() else None}
    med = np.median(Xa, axis=0)
    mad = np.median(np.abs(Xa - med), axis=0) * 1.4826
    metrics = {"primary": "f1", "f1": round(float(f1_score(ya[te], pred, zero_division=0)), 4),
               "precision": round(float(precision_score(ya[te], pred, zero_division=0)), 4),
               "recall": round(float(recall_score(ya[te], pred, zero_division=0)), 4),
               "recall_by_type": by_type,
               "evaluation": {"split": "grouped by asset, 25% held out",
                              "note": "model is unsupervised; labels (injected jumps) are used only to evaluate",
                              "test_rows": int(len(te)), "injected_in_test": int(ya[te].sum()), "contamination": contamination}}
    bundle = {"kind": "anomaly", "model": mk().fit(Xa), "features": list(ANOMALY_FEATURES),
              "feature_version": FEATURE_VERSION, "sklearn_version": sklearn.__version__, "median": med.tolist(), "mad": np.maximum(mad, 1e-3).tolist()}
    return bundle, metrics, "isolation_forest", len(Xa)


def register(db, org_id: int, bundle: dict, metrics: dict, algo: str, rows: int, source: str, actor: str) -> MLModel:
    """Save the model file and add it to the registry as SHADOW. It never serves results until promoted."""
    stamp = utcnow().strftime("%Y%m%d%H%M%S")
    version = f"{bundle['kind']}-{algo}-{FEATURE_VERSION}-{stamp}"
    d = Path(settings.model_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{version}.joblib"
    joblib.dump(bundle, path)
    m = MLModel(org_id=org_id, version=version, kind=bundle["kind"], algo=algo, feature_version=FEATURE_VERSION,
                data_source=source, status="shadow", metrics=metrics, path=str(path), trained_rows=rows, created_by=actor)
    db.add(m)
    db.flush()
    return m


def feedback_dataset(db, org_id: int):
    from sqlalchemy import select
    rs = db.scalars(select(MLFeedback).where(MLFeedback.org_id == org_id, MLFeedback.approved == True,  # noqa: E712
                                             MLFeedback.feature_version == FEATURE_VERSION).order_by(MLFeedback.at)).all()
    return (np.array([vector(r.features) for r in rs]), np.array([CLASSES.index(r.label) for r in rs]),
            np.array([r.asset_id for r in rs]), np.array([r.at.isoformat() for r in rs]))


def load_csv(path: str):
    """CSV columns: asset_id, timestamp, label (low|moderate|high|critical) + the v1 feature columns."""
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    need = {"asset_id", "timestamp", "label", *RISK_FEATURES}
    if not rows or not need <= set(rows[0]):
        raise DatasetError("CSV must have columns: " + ", ".join(sorted(need)))
    return (np.array([[float(r[k]) for k in RISK_FEATURES] for r in rows]),
            np.array([CLASSES.index(r["label"]) for r in rows]),
            np.array([r["asset_id"] for r in rows]), np.array([r["timestamp"] for r in rows]))


def train_and_register(db, org_id: int, kind: str, source: str, actor: str, csv_path: str | None = None) -> MLModel:
    if kind == "anomaly":
        if source != "synthetic":
            raise DatasetError("anomaly models currently train on the synthetic baseline only")
        ds = synth.generate()
        b, m, algo, n = train_anomaly(ds["Xa"], ds["ya"], ds["ga"], ds["ta"])
    elif source == "synthetic":
        ds = synth.generate()
        b, m, algo, n = train_risk(ds["X"], ds["y"], ds["groups"], ds["ts"], source)
        m["label_policy"] = ds["policy"]
    elif source == "feedback":
        X, y, g, ts = feedback_dataset(db, org_id)
        b, m, algo, n = train_risk(X, y, g, ts, source) if len(X) else (_ for _ in ()).throw(
            DatasetError(f"no approved analyst labels yet (need at least {MIN_ROWS})"))
    elif source == "csv" and csv_path:
        X, y, g, ts = load_csv(csv_path)
        b, m, algo, n = train_risk(X, y, g, ts, source)
    else:
        raise DatasetError("unknown training source")
    return register(db, org_id, b, m, algo, n, source, actor)


def main():
    from sqlalchemy import select
    from ..db import Base, SessionLocal, engine
    from ..models import Organization
    ap = argparse.ArgumentParser(description="Train ASIVM models and register them as shadow")
    ap.add_argument("--kind", choices=["risk", "anomaly"], default="risk")
    ap.add_argument("--source", choices=["synthetic", "feedback", "csv"], default="synthetic")
    ap.add_argument("--csv")
    a = ap.parse_args()
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = db.scalar(select(Organization))
        if not org:
            raise SystemExit("No organisation yet: complete first-run setup in the app first.")
        m = train_and_register(db, org.id, a.kind, a.source, "cli", a.csv)
        db.commit()
        print(m.version, "shadow", {k: v for k, v in m.metrics.items() if k in ("macro_f1", "f1", "critical_recall", "baselines")})


if __name__ == "__main__":
    main()
