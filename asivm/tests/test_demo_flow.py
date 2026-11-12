"""Guards the sample walkthrough in lab/demo so it keeps working."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app
from app.models import MLModel

D = Path(__file__).parent.parent / "lab" / "demo"


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        client.post("/api/auth/bootstrap", json={"org_name": "TestOrg", "email": "a@t.io", "password": "supersecret123"})
        tok = client.post("/api/auth/login", data={"username": "a@t.io", "password": "supersecret123"}).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {tok}"
        yield client
        with SessionLocal() as db:  # leave no active models behind: other tests assume a clean registry
            for m in db.query(MLModel).all():
                m.status = "retired"
            db.commit()


def up(c, url, name):
    with open(D / name, "rb") as fh:
        return c.post(url, files={"file": (name, fh)})


def test_walkthrough_end_to_end(c):
    assert c.post("/api/intel/sync", json={"kinds": ["seed"]}).status_code == 202
    assert up(c, "/api/intel/import/epss", "epss_illustrative.csv").json()["imported"] >= 5
    r = up(c, "/api/assets/import-csv", "assets.csv").json()
    assert r["created"] + r["matched_existing"] == 6 and not r["errors"]
    s = up(c, "/api/scans/import-nmap", "scan1_baseline.xml").json()["summary"]
    assert s["hosts"] == 6 and s["new_assets"] == 0 and s["findings_evaluated"] > 0  # all six matched the CSV assets
    d = c.get("/api/dashboard").json()
    assert d["open_by_tier"]["critical"] >= 1 and any(f["kev"] for f in d["fix_first"])  # Apache path traversal is KEV-listed

    assert len(c.post("/api/ml/bootstrap").json()) == 2
    assert c.post("/api/ml/assess-all").json()["assessed"] >= 6
    rows = {x["asset_name"]: x for x in c.get("/api/ml/assessments").json()}
    assert rows["web-prod-01"]["predicted"] in ("high", "critical") and rows["web-prod-01"]["rule_tier"] == "critical"
    demo = ("web-prod-01", "web-staging", "db-prod-01", "app-01", "file-srv", "test-box")
    assert all(rows[n]["top_factor"] for n in ("web-prod-01", "app-01", "file-srv"))  # assets with real risk drivers
    assert all(n in rows for n in demo)
    p = c.get(f"/api/ml/assets/{rows['web-prod-01']['asset_id']}").json()["latest"]
    assert p["factors"] and p["factors"][0]["method"] == "shap"

    up(c, "/api/scans/import-nmap", "scan2_db_exposure_change.xml")
    flagged = [e for e in c.get("/api/ml/anomalies?status=open").json() if e["asset_name"] == "db-prod-01"]
    assert flagged and any(f["feature"] in ("d_services", "services_ratio") for f in flagged[0]["factors"])
