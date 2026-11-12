# ASIVM machine-learning layer

Everything here exists in the repository and is covered by tests (`tests/test_ml.py`). Where something in the
Product Vision Brief is not built, section 6 says so.

## 1. What it does

| Capability | How | Where |
|---|---|---|
| Asset risk prediction | Random Forest, 4 classes (low / moderate / high / critical) on a fixed 16-feature vector | `app/ml/train.py`, `service.py` |
| Explanations | SHAP contributions per prediction, in plain language, plus model version and timestamp | `service.explain` |
| Anomaly detection | Isolation Forest on how an asset changed since its own previous scans | `service.score_anomaly` |
| History | An `AssetSnapshot` is stored after every scan or import | `features.record_snapshot`, hooked in `pipeline.py` |
| Governed lifecycle | New models start as **shadow**; only an admin promotes them; promotion is refused if the candidate is worse than the active model | `MLModel`, `service.promote` |
| Analyst feedback | An analyst proposes a label; a *different* admin approves it; only approved labels can train a model | `MLFeedback`, `/api/ml/feedback` |

## 2. Quick start

```bash
docker compose up --build            # models persist in the `models` volume
# UI: sign in as admin -> "ML intelligence" -> "Train & activate demo models"
# then "Assess all assets". Scan or import a report twice to see change detection.
```

Command line (registers a **shadow** model; promote it in the UI or `POST /api/ml/models/{id}/promote`):

```bash
python -m app.ml.train --kind risk                  # synthetic demonstration data
python -m app.ml.train --kind anomaly
python -m app.ml.train --source feedback            # approved analyst labels (needs >= 200)
python -m app.ml.train --source csv --csv labels.csv
```

API (all under `/api/ml`): `GET /status`, `POST /train`, `POST /bootstrap`, `POST /models/{id}/promote`,
`POST /assets/{id}/assess`, `POST /assess-all`, `GET /assessments`, `GET /assets/{id}`,
`POST /assets/{id}/feedback`, `GET /feedback`, `POST /feedback/{id}/approve`, `GET /anomalies`,
`POST /anomalies/rescan`, `POST /anomalies/{id}/review`. Interactive docs at `/docs`.

## 3. Feature contract v1

Sixteen features per asset, built only from data ASIVM already stores (`app/ml/features.py`):
`n_findings, max_cvss, mean_cvss, n_cvss_ge7, n_kev, max_epss, mean_epss, criticality, exposure_level,
n_exposed_services, n_new_30d, oldest_open_days, n_overdue, mean_match_conf, findings_trend_30d,
services_trend_30d`.

Anomaly features compare the newest snapshot with the asset's earlier ones:
`d_services, d_findings, d_kev, services_ratio, findings_ratio`.

A model records the feature version and scikit-learn version it was trained with, and refuses to load under a
different one (the message says to retrain).

## 4. Training data and evaluation

**There is no real labelled data yet, so the shipped models are trained on synthetic demonstration data**
(`app/ml/synth.py`). The label comes from a documented hidden "compromise propensity" with interactions and
noise, cut at fixed quantiles. It is deliberately *not* the formula in `services/risk.py`, but it is still
invented. The UI and API say so on every prediction (`notice`).

Safeguards before any model is trained (`validate_dataset`): feature shape, no NaN/inf, valid labels, minimum
rows and assets, minimum examples per class, no duplicate (asset, timestamp), timestamps increasing per asset.
Evaluation uses a split **grouped by asset** (no asset appears in both train and test, checked and recorded).

Measured on 8 independent synthetic datasets (mean ± sd; min to max):

| Metric | Result |
|---|---|
| Macro F1 (held-out assets) | 0.80 ± 0.02 (0.75 to 0.83) |
| Critical-class recall | 0.90 ± 0.10 (0.67 to 1.00) |
| Fitted severity-only baseline (tree on max CVSS) | 0.28 ± 0.03 |
| Expected calibration error | 0.09 ± 0.02 (probabilities are **not** calibrated) |

How to read this: it shows the pipeline learns and generalises across assets **on data we generated**. The gap
over the severity-only baseline is largely because our synthetic labels depend on exposure and criticality,
which CVSS cannot see. It is not evidence of real-world accuracy. Critical recall varies a lot because
"critical" is a small class.

Anomaly model (unsupervised; injected changes are used only to evaluate): F1 about 0.82, precision about 0.73,
recall about 0.94 on one held-out split with only 17 injected changes in the test set, so treat it as indicative.
Recall is reported per change type (services only, findings only, both) because an earlier version missed
"services jump with no new vulnerabilities" entirely; that gap was found and fixed. The threshold flags about
5% of observations by construction and should be tuned with analyst confirm/dismiss decisions.

## 5. Known limitations

- No real labels, no independently verified outcomes, so no production-validated model.
- Risk assessment runs on demand (`assess` / `assess-all`), not automatically after each scan. Anomaly checks do
  run automatically after each scan once an anomaly model is active.
- Anomaly models currently train on the synthetic baseline only.
- Synchronous training inside the API request (a few seconds); suitable for small datasets, not for large ones.
- No drift or post-deployment performance monitoring.
- Model files are pickles: only load models this system produced.

## 6. Status of the Product Vision Brief

| Brief | Status |
|---|---|
| 4.1 Random Forest, four risk classes | Built (synthetic data) |
| 4.1 Inputs: vuln count, severity, KEV, EPSS, criticality, exposure, services, trends | Built |
| 4.1 "Previous validated risk outcomes" as an input | Not built (feedback loop exists, no data) |
| 4.1 XGBoost / LightGBM | Roadmap |
| 4.2 Isolation Forest anomaly detection | Built |
| 4.3 Historical context | Partial: snapshots and 30-day trends; no sequence models |
| 4.4 Explanations: class, factors, evidence, version, timestamp | Built (SHAP) |
| 4.4 Calibrated probability | Not built (reported, uncalibrated) |
| 4.5 Continuous inference | Partial (anomalies automatic; risk on demand) |
| 4.5 Improvement: history, analyst feedback, validated datasets, candidates, held-out eval, comparison with approved model, registration, approval before promotion | Built |
| 4.5 Independently verified outcomes; post-deployment monitoring | Not built |
| 7 NVD / KEV / EPSS ingestion | Built; NVD pagination yes, retry handling **no** |
| 7 Provenance-aware ingestion, historical intelligence snapshots | **Not in the code** |
| 7 Alembic migrations | **Not in the code** (additive column upgrade only) |
| 7 "Versioned v1, v2 and v3 feature contracts" | Only **v1** exists |
| 7 Dataset validation, duplicate/timestamp checks, asset grouping, held-out evaluation | Built |
| 7 Shadow registration and lifecycle controls | Built |
| 7 Anomaly triage workflow | Built (confirm / dismiss with reviewer and note) |
| 7 FastAPI, PostgreSQL, Docker, dashboard, tests | Built |
| 8 Discovery, temporal models, autoencoders, attack paths, business-aware risk, remediation, drift | Roadmap |
