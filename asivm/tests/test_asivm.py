import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import scanner

def nmap_xml(ip, mac, hostname, services, ports="1-1000"):
    sv = ""
    for port, prod, ver, cpe in services:
        sv += (f'<port protocol="tcp" portid="{port}"><state state="open"/>'
               f'<service name="x" product="{prod}" version="{ver}" extrainfo="Unix"><cpe>{cpe}</cpe></service></port>')
    m = f'<address addr="{mac}" addrtype="mac"/>' if mac else ""
    hn = f'<hostnames><hostname name="{hostname}"/></hostnames>' if hostname else ""
    return (f'<nmaprun><scaninfo type="connect" protocol="tcp" services="{ports}"/>'
            f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>{m}{hn}<ports>{sv}</ports></host></nmaprun>')

APACHE = (80, "Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49")
SSH = (22, "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6", "cpe:/a:openbsd:openssh:8.9p1")


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        assert client.post("/api/auth/bootstrap", json={"org_name": "TestOrg", "email": "a@t.io", "password": "supersecret123"}).status_code == 201
        tok = client.post("/api/auth/login", data={"username": "a@t.io", "password": "supersecret123"}).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {tok}"
        yield client


def imp(c, xml):
    r = c.post("/api/scans/import-nmap", files={"file": ("s.xml", xml)})
    assert r.status_code == 200, r.text
    return r.json()


def test_auth_required(c):
    with TestClient(app) as anon:
        assert anon.get("/api/assets").status_code == 401
        assert anon.post("/api/auth/bootstrap", json={"org_name": "Other", "email": "b@t.io", "password": "supersecret123"}).status_code == 403


def test_scope(c):
    v = lambda t: c.post("/api/scope/validate", json={"target": t}).json()
    assert not v("10.0.0.5")["allowed"]  # empty scope denies everything
    c.post("/api/scope", json={"kind": "cidr", "value": "10.0.0.0/24"})
    c.post("/api/scope", json={"kind": "cidr", "value": "10.0.0.250/32", "action": "deny"})
    assert v("10.0.0.5")["allowed"]
    assert v("10.0.0.0/25")["allowed"]
    assert not v("10.0.0.0/16")["allowed"]
    assert not v("10.0.1.5")["allowed"]
    assert not v("10.0.0.250")["allowed"]
    assert not v("10.0.0.0/24")["allowed"]  # overlaps deny
    assert not v("-oX /tmp/x")["allowed"]
    assert not v("--script=evil")["allowed"]
    r = c.post("/api/scans", json={"target": "192.168.5.5"})
    assert r.status_code == 422 and "scope" in r.text.lower()


def test_nmap_command_is_safe():
    cmd = scanner.nmap_command("10.0.0.5", "standard", ["10.0.0.250/32"])
    assert cmd[-2:] == ["--", "10.0.0.5"] and "--exclude" in cmd


def test_pipeline_identity_findings_verification(c):
    assert c.post("/api/intel/sync", json={"kinds": ["seed"]}).status_code == 202
    assert c.get("/api/intel/status").json()["vulnerabilities"] >= 10

    s = imp(c, nmap_xml("10.0.0.5", "AA:BB:CC:00:00:01", "web01.corp.local", [APACHE, SSH]))
    assert s["summary"]["new_assets"] == 1
    fs = c.get("/api/findings").json()
    cves = {f["cve_id"] for f in fs}
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= cves
    assert "CVE-2018-15473" not in cves  # 8.9 > 7.7
    f = next(f for f in fs if f["cve_id"] == "CVE-2021-42013")
    assert f["kev"] and f["risk_score"] > 50 and f["match_method"] == "cpe"
    det = c.get(f"/api/findings/{f['id']}").json()
    assert det["evidence"]["software"]["version"] == "2.4.49" and det["history"][0]["to_state"] == "open"
    assert det["risk_inputs"]["components"]["kev"] == 25

    # same machine, new IP -> same asset
    s2 = imp(c, nmap_xml("10.0.0.77", "aa:bb:cc:00:00:01", "web01.corp.local", [APACHE, SSH]))
    assert s2["summary"]["new_assets"] == 0 and s2["summary"]["matched_to_existing"] == 1
    assets = c.get("/api/assets").json()
    assert len(assets) == 1 and set(assets[0]["identifiers"]["ip"]) >= {"10.0.0.77"}
    # old IP reassigned to a different machine -> new asset, not a false merge
    s3 = imp(c, nmap_xml("10.0.0.5", "AA:BB:CC:00:00:02", "db01.corp.local", []))
    assert s3["summary"]["new_assets"] == 1
    assert len(c.get("/api/assets").json()) == 2
    assert len(c.get("/api/findings").json()) == len(fs)  # no duplicate findings

    # remediation workflow
    assert c.post(f"/api/findings/{f['id']}/transition", json={"to_state": "verified"}).status_code == 400
    assert c.post(f"/api/findings/{f['id']}/transition", json={"to_state": "assigned"}).status_code == 400
    assert c.post(f"/api/findings/{f['id']}/transition", json={"to_state": "assigned", "assignee": "bob"}).status_code == 200
    assert c.post(f"/api/findings/{f['id']}/transition", json={"to_state": "fixed", "note": "upgraded"}).status_code == 200

    # upgrade apache -> rescan -> verified by re-observation
    web = next(a for a in c.get("/api/assets").json() if a["name"].startswith("web01"))
    imp(c, nmap_xml("10.0.0.77", "AA:BB:CC:00:00:01", "web01.corp.local",
                    [(80, "Apache httpd", "2.4.58", "cpe:/a:apache:http_server:2.4.58"), SSH]))
    det = c.get(f"/api/findings/{f['id']}").json()
    assert det["state"] == "verified"
    assert [e["to_state"] for e in det["history"]] == ["open", "assigned", "fixed", "verified"]
    ch = {x["kind"] for x in c.get("/api/changes").json()}
    assert {"new_asset", "version_changed"} <= ch

    # regression: old version returns -> reopened
    imp(c, nmap_xml("10.0.0.77", "AA:BB:CC:00:00:01", "web01.corp.local", [APACHE, SSH]))
    assert c.get(f"/api/findings/{f['id']}").json()["state"] == "reopened"

    # service on an unscanned port is not falsely "removed"
    imp(c, nmap_xml("10.0.0.77", "AA:BB:CC:00:00:01", "web01.corp.local", [SSH], ports="1-79"))
    assert c.get(f"/api/findings/{f['id']}").json()["state"] == "reopened"

    # context changes rescore
    before = c.get(f"/api/findings/{f['id']}").json()["risk_score"]
    c.patch(f"/api/assets/{web['id']}", json={"exposure": "internet", "criticality": 5, "owner": "ops"})
    assert c.get(f"/api/findings/{f['id']}").json()["risk_score"] > before


def test_confidence_and_manual_software(c):
    a = c.post("/api/assets", json={"identifiers": {"ip": "10.0.0.9", "hostname": "lib01"}}).json()["asset"]
    r = c.post(f"/api/assets/{a['id']}/software", json={"name": "log4j-core", "version": "2.14.1"}).json()
    assert r["matching"]["matched"] == 1
    f = c.get(f"/api/findings?asset_id={a['id']}").json()[0]
    assert f["cve_id"] == "CVE-2021-44228" and f["match_method"] == "alias" and f["risk_tier"] in ("critical", "high")
    r = c.post(f"/api/assets/{a['id']}/software", json={"name": "log4j-core", "version": "2.17.1"}).json()
    assert len([x for x in c.get(f"/api/findings?asset_id={a['id']}").json()]) == 1


def test_csv_import_dedup_and_merge(c):
    csvdata = "name,ip,hostname,owner,criticality,exposure\nfoo,10.0.0.40,foo,alice,4,dmz\nfoo,10.0.0.40,foo,alice,4,dmz\n"
    r = c.post("/api/assets/import-csv", files={"file": ("a.csv", csvdata)}).json()
    assert r["created"] == 1 and r["matched_existing"] == 1 and not r["errors"]
    a = c.post("/api/assets", json={"identifiers": {"ip": "10.0.0.41"}}).json()["asset"]
    b = c.post("/api/assets", json={"identifiers": {"ip": "10.0.0.42"}}).json()["asset"]
    assert c.post(f"/api/assets/{a['id']}/merge/{b['id']}").status_code == 200
    assert c.get(f"/api/assets/{b['id']}").json()["status"] == "merged"


def test_trivy_import_and_dashboard(c):
    trivy = {"ArtifactName": "shop:1.0", "Results": [{"Target": "shop (debian 11)", "Type": "debian", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-0001", "PkgName": "libfoo", "InstalledVersion": "1.0", "FixedVersion": "1.1",
         "Severity": "HIGH", "Title": "demo", "CVSS": {"nvd": {"V3Score": 8.1}}}]}]}
    r = c.post("/api/scans/import-trivy", files={"file": ("t.json", json.dumps(trivy))}).json()
    assert r["status"] == "completed" and r["summary"]["findings"] == 1
    trivy["Results"][0]["Vulnerabilities"] = []
    c.post("/api/scans/import-trivy", files={"file": ("t.json", json.dumps(trivy))})
    f = c.get("/api/findings?cve=CVE-2023-0001").json()[0]
    assert f["state"] == "verified"
    d = c.get("/api/dashboard").json()
    assert d["assets"]["total"] >= 4 and d["fix_first"]
    assert c.get("/api/findings/export.csv").text.startswith("id,asset")
    assert c.get("/api/audit").json()


def test_rbac(c):
    assert c.post("/api/users", json={"email": "v@t.io", "password": "viewerpass123", "role": "viewer"}).status_code == 201
    tok = c.post("/api/auth/login", data={"username": "v@t.io", "password": "viewerpass123"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert c.get("/api/assets", headers=h).status_code == 200
    assert c.post("/api/scope", json={"kind": "cidr", "value": "1.0.0.0/8"}, headers=h).status_code == 403
    assert c.post("/api/assets", json={"identifiers": {"ip": "1.1.1.1"}}, headers=h).status_code == 403


def test_scan_runner_with_fake_nmap(c):
    from app.db import SessionLocal
    from app.models import Scan
    scan = c.post("/api/scans", json={"target": "10.0.0.60", "profile": "quick"})
    assert scan.status_code == 202
    sid = scan.json()["id"]
    # TestClient already ran background task with real subprocess -> nmap missing -> failed cleanly
    assert c.get(f"/api/scans/{sid}").json()["status"] in ("failed", "completed")
    class P:  # fake nmap
        returncode, stderr = 0, ""
        stdout = nmap_xml("10.0.0.60", None, "fake01", [APACHE])
    with SessionLocal() as db:
        s = Scan(org_id=1, tool="nmap", target="10.0.0.60", profile="quick"); db.add(s); db.commit(); i = s.id
    scanner.run_scan(i, runner=lambda *a, **k: P)
    assert c.get(f"/api/scans/{i}").json()["status"] == "completed"
    with SessionLocal() as db:   # scope is re-checked at execution time
        s = Scan(org_id=1, tool="nmap", target="8.8.8.8"); db.add(s); db.commit(); j = s.id
    scanner.run_scan(j, runner=lambda *a, **k: P)
    assert c.get(f"/api/scans/{j}").json()["status"] == "failed"


def test_remediation_advice_and_ownership(c):
    f = next(x for x in c.get("/api/findings?cve=CVE-2021-42013").json())
    assert f["fix_hint"].startswith("Upgrade to 2.4.51") and f["ips"] and f["port"] == "80/tcp"
    d = c.get(f"/api/findings/{f['id']}").json()
    r = d["remediation"]
    assert "2.4.51" in r["fixed_version"] and len(r["steps"]) >= 3 and r["workarounds"]
    assert any("nvd.nist.gov" in x["url"] for x in r["references"]) and "KEV" in r["urgency"]
    assert d["asset"]["ips"]
    # range-derived fix (no curated text): OpenSSH-style end_excl
    a = c.post("/api/assets", json={"identifiers": {"ip": "10.0.0.70"}, "owner": "Dana", "owner_email": "dana@corp.io",
                                     "location": "Nairobi DC, rack 4", "department": "Platform"}).json()["asset"]
    assert a["location"] == "Nairobi DC, rack 4" and a["owner_email"] == "dana@corp.io"
    c.post(f"/api/assets/{a['id']}/software", json={"name": "Samba smbd", "version": "4.5.2"})
    s = c.get(f"/api/findings?asset_id={a['id']}").json()[0]
    assert s["owner"] == "Dana" and s["location"] == "Nairobi DC, rack 4" and "4.5.10" in s["fix_hint"]
    assert {"email": "a@t.io", "role": "admin"} in c.get("/api/team").json()
    assert "Nairobi DC" in c.get("/api/findings/export.csv").text
    ch = c.get("/api/changes").json()
    assert all("asset_name" in x for x in ch)


def test_schema_upgrade_adds_missing_columns(c):
    from sqlalchemy import text, inspect
    from app.db import engine, ensure_columns
    with engine.begin() as cn:
        cn.execute(text("ALTER TABLE assets DROP COLUMN location"))
    assert "location" not in [x["name"] for x in inspect(engine).get_columns("assets")]
    ensure_columns()
    assert "location" in [x["name"] for x in inspect(engine).get_columns("assets")]
    assert c.get("/api/assets").status_code == 200


def test_trends_rollup_policy(c):
    t = c.get("/api/trends").json()
    assert t and t[-1]["open"] >= 1 and {"critical", "high", "verified", "overdue", "assets"} <= t[-1].keys()
    r = c.get("/api/reports/by?group=owner").json()
    assert any(x["name"] == "Dana" and x["assets"] == 1 for x in r) and any(x["name"] == "(not set)" for x in r)
    assert c.get("/api/reports/by?group=bogus").status_code == 422
    before = c.get("/api/dashboard").json()["fix_first"][0]["risk_score"]
    assert c.put("/api/risk-policy", json={"tiers": {"critical": 50, "high": 60}}).status_code == 422
    assert c.put("/api/risk-policy", json={"weights": {"kev": 40}}).status_code == 200
    assert c.get("/api/dashboard").json()["fix_first"][0]["risk_score"] != before
    assert c.get("/api/risk-policy").json()["policy"]["weights"]["kev"] == 40
    assert c.delete("/api/risk-policy").status_code == 200
    assert c.get("/api/dashboard").json()["fix_first"][0]["risk_score"] == before
