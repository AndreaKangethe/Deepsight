# ASIVM: Asset Security Intelligence and Visibility Management

One persistent identity per asset; discovery -> scan -> identify -> match -> prioritise -> remediate -> verify -> monitor.

## Run

    docker compose up --build            # API + UI on http://localhost:8000, API docs at /docs
    docker compose --profile lab up -d   # optional vulnerable demo targets (172.28.0.21, .22)

Set real secrets first:  `export ASIVM_SECRET_KEY=$(openssl rand -hex 32) ASIVM_DB_PASSWORD=...`

Single image (needs your own Postgres, or use SQLite for a trial):

    docker build -t asivm:latest .
    docker run -p 8000:8000 -e ASIVM_SECRET_KEY=... asivm:latest      # SQLite inside container, not persistent
    docker save asivm:latest | gzip > asivm-image.tar.gz               # portable image file

## First 5 minutes
1. Open http://localhost:8000, create the admin (first-run only).
2. **Intel** tab -> Sync `seed` (offline starter set), then `kev`, `epss`, `nvd` for real data.
3. **Scope** tab -> allow rule `172.28.0.0/24` (nothing scans without one).
4. **Scans** -> `nmap` / `standard` on `172.28.0.21`, then `.22`. Or import an Nmap XML / Trivy JSON report.
5. **Dashboard** -> "Fix these first". Open a finding for evidence, confidence and risk inputs; assign, fix, then **Verify by re-scan**.

## What's in the UI
Dashboard (risk bars, 30-day trend, fix-first list, change timeline), Findings (owner, location, assignee, due date, fix hint),
a finding panel (how to fix, workarounds, references, evidence, score breakdown, history, status updates, verify by re-scan),
Assets (ownership, department, location, exposure, criticality), Owners & teams rollup, Scans (auto-refresh), Scope,
Intelligence (feeds + editable risk policy), Team, Audit log.

Upgrading from an earlier build: just `docker compose up --build`. New columns are added to your existing database automatically.

## Design (matches the pitch)
- `services/identity.py` identity resolution: weighted identifiers, strong-ID conflict detection, IP-reuse protection, merges.
- `services/scope.py` scope validator, run at request time **and** again at execution; deny rules win; nmap gets `--exclude` and `--` before the target.
- `services/matcher.py` CVE matching with method + confidence (cpe .95 / alias .85 / name .7, minus distro-backport penalty); unknown versions never match.
- `services/risk.py` CVSS + KEV + EPSS + asset criticality + exposure, scaled by match confidence; every input stored on the finding.
- `services/remediation.py` states open/assigned/in_progress/fixed/verified/reopened (+accepted_risk); `verified` is only set by re-observation.
- `services/pipeline.py` + `scheduler.py` change detection (new asset/service, version change, service gone, stale asset), scheduled scans.
- Roles: admin / analyst / viewer. All rows carry `org_id`. Audit log for security-relevant actions.

## Config (env, prefix ASIVM_)
(risk weights, levels and SLA days are edited in the UI under Intelligence)
DATABASE_URL, SECRET_KEY, NVD_API_KEY, MIN_MATCH_CONFIDENCE, AUTO_INTEL_SYNC, SCHEDULER_ENABLED, MAX_SCAN_HOSTS, STALE_AFTER_DAYS

## Tests
    pip install -r requirements.txt && pytest -q tests

Only scan networks you are authorised to scan.


## Machine-learning layer

Risk prediction (Random Forest), change detection (Isolation Forest), SHAP explanations, a shadow-model registry and analyst-feedback loop. The shipped models are trained on **synthetic demonstration data**. See [docs/ML.md](docs/ML.md) for usage, evaluation, limitations, and a claim-by-claim status against the product brief.

## Walkthrough sample data

`lab/demo/` holds a small sample estate for showing the whole product: six assets with owners, criticality and exposure (`assets.csv`), a baseline Nmap report (`scan1_baseline.xml`), a follow-up report where one database server suddenly exposes twelve services (`scan2_db_exposure_change.xml`), and a sample EPSS file (`epss_illustrative.csv`, illustrative values for offline use).

```bash
docker compose up --build                      # then complete first-run setup at http://localhost:8000
python lab/demo/prepare.py --email you@example.org --password '...'              # offline
python lab/demo/prepare.py --email you@example.org --password '...' --online-epss   # real KEV + EPSS feeds
```

Then import `scan1_baseline.xml` on the Scans page, open **ML intelligence**, and import `scan2_db_exposure_change.xml` later to see change detection. `tests/test_demo_flow.py` keeps this path working.

## Live-scan lab

Scan real targets instead of importing reports. `docker compose --profile lab up -d --build` starts an old Apache (172.28.0.21) and an old nginx (172.28.0.22) on the platform network. In the app: **Scope** (allow `172.28.0.0/24`, deny `172.28.0.128/25`), then **Scans** (target `172.28.0.16/28`). `docker compose --profile lab-change up -d lab-newhost` adds a third host (172.28.0.23) to show change detection. `tests/test_live_scan.py` covers this flow using a stand-in for Nmap.
