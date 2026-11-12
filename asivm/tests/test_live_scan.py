"""Live-scan lab path: scope rules -> scan an IP range -> assets discovered -> enrich -> ML -> patch -> verify."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import MLModel

APACHE = (80, "Apache httpd", "2.4.49", ["cpe:/a:apache:http_server:2.4.49"])
# Real Nmap has reported nginx under the legacy vendor name igor_sysoev; matching must still work.
NGINX_OLD = (80, "nginx", "1.18.0", ["cpe:/a:igor_sysoev:nginx:1.18.0"])
NGINX_NEW = (80, "nginx", "1.25.3", ["cpe:/a:f5:nginx:1.25.3"])


@pytest.fixture
def lab(tmp_path, monkeypatch):
    state = tmp_path / "lab.json"
    set_hosts = lambda hosts: state.write_text(json.dumps({"hosts": hosts}))  # noqa: E731
    set_hosts([{"ip": "172.28.0.21", "services": [APACHE]}, {"ip": "172.28.0.22", "services": [NGINX_OLD]}])
    monkeypatch.setenv("FAKE_NMAP_STATE", str(state))
    monkeypatch.setattr(settings, "nmap_path", str(Path(__file__).parent / "fake_nmap.py"))
    return set_hosts


@pytest.fixture
def c():
    with TestClient(app) as client:
        client.post("/api/auth/bootstrap", json={"org_name": "TestOrg", "email": "a@t.io", "password": "supersecret123"})
        tok = client.post("/api/auth/login", data={"username": "a@t.io", "password": "supersecret123"}).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {tok}"
        yield client
        with SessionLocal() as db:
            for m in db.query(MLModel).all():
                m.status = "retired"
            db.commit()


def asset_by_ip(c, ip):
    return next(a for a in c.get("/api/assets").json() if ip in a["identifiers"].get("ip", []))


def test_live_scan_lab(c, lab):
    c.post("/api/intel/sync", json={"kinds": ["seed"]})

    # 1. nothing is scanned unless a rule allows it (the empty-scope case is covered in test_asivm)
    assert not c.post("/api/scope/validate", json={"target": "172.28.0.16/28"}).json()["allowed"]

    # 2. allow the lab network but deny the half that holds the platform's own containers
    for v, act in (("172.28.0.0/24", "allow"), ("172.28.0.128/25", "deny")):
        assert c.post("/api/scope", json={"kind": "cidr", "value": v, "action": act}).status_code == 201
    ok = c.post("/api/scope/validate", json={"target": "172.28.0.16/28"}).json()
    assert ok["allowed"], ok
    assert not c.post("/api/scope/validate", json={"target": "172.28.0.0/24"}).json()["allowed"]  # overlaps the deny rule
    assert not c.post("/api/scope/validate", json={"target": "8.8.8.8"}).json()["allowed"]        # outside every allow rule
    assert c.post("/api/scans", json={"target": "8.8.8.8", "tool": "nmap"}).status_code in (403, 422)

    # 3. scan the range: both hosts become assets automatically
    r = c.post("/api/scans", json={"target": "172.28.0.16/28", "tool": "nmap", "profile": "quick"})
    assert r.status_code == 202, r.text
    scan = c.get(f"/api/scans/{r.json()['id']}").json()
    assert scan["status"] == "completed" and scan["summary"]["hosts"] == 2 and scan["summary"]["new_assets"] == 2, scan
    apache, nginx = asset_by_ip(c, "172.28.0.21"), asset_by_ip(c, "172.28.0.22")

    # 4. findings carry evidence; the legacy-vendor nginx match is kept but with lower, explained confidence
    fa = c.get(f"/api/assets/{apache['id']}").json()["findings"]
    fn = c.get(f"/api/assets/{nginx['id']}").json()["findings"]
    assert any(f["cve_id"] == "CVE-2021-42013" for f in fa)
    n = next(f for f in fn if f["cve_id"] == "CVE-2021-23017")
    detail = c.get(f"/api/findings/{n['id']}").json()
    assert 0.5 <= detail["match_confidence"] < 0.95
    assert "vendor differs" in json.dumps(detail["evidence"])

    # 5. enriching an asset re-scores its findings
    before = max(f["risk_score"] for f in fa)
    assert c.patch(f"/api/assets/{apache['id']}", json={"criticality": 5, "exposure": "internet", "owner": "Amina"}).status_code == 200
    after = max(f["risk_score"] for f in c.get(f"/api/assets/{apache['id']}").json()["findings"])
    assert after > before

    # 6. ML on live-discovered assets
    assert len(c.post("/api/ml/bootstrap").json()) == 2
    rows = {x["asset_id"]: x for x in c.get("/api/ml/assessments").json()}
    c.post("/api/ml/assess-all")
    rows = {x["asset_id"]: x for x in c.get("/api/ml/assessments").json()}
    assert rows[apache["id"]]["predicted"] in ("moderate", "high", "critical") and rows[apache["id"]]["top_factor"]
    assert rows[apache["id"]]["risk_index"] > rows[nginx["id"]]["risk_index"]

    # 7. a new host appears on the network -> a new asset and a change event on the next scan
    lab([{"ip": "172.28.0.21", "services": [APACHE]}, {"ip": "172.28.0.22", "services": [NGINX_OLD]},
         {"ip": "172.28.0.23", "services": [(80, "Apache httpd", "2.4.50", ["cpe:/a:apache:http_server:2.4.50"])]}])
    s2 = c.get(f"/api/scans/{c.post('/api/scans', json={'target': '172.28.0.16/28', 'tool': 'nmap', 'profile': 'quick'}).json()['id']}").json()
    assert s2["summary"]["new_assets"] == 1
    assert any(x["kind"] == "new_asset" for x in c.get("/api/changes").json())

    # 8. patch nginx, then verify by re-scan: the finding closes itself
    lab([{"ip": "172.28.0.21", "services": [APACHE]}, {"ip": "172.28.0.22", "services": [NGINX_NEW]}])
    assert c.post(f"/api/findings/{n['id']}/verify").status_code == 202
    assert c.get(f"/api/findings/{n['id']}").json()["state"] == "verified"
