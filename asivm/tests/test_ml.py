import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app
from app.ml import service, synth, train
from app.ml.features import CLASSES, RISK_FEATURES
from app.models import MLModel


def nmap_xml(ip, mac, services):
    sv = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="x" product="{pr}" '
                 f'version="{v}"><cpe>{cpe}</cpe></service></port>' for p, pr, v, cpe in services)
    return (f'<nmaprun><scaninfo type="connect" protocol="tcp" services="1-65535"/><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><address addr="{mac}" addrtype="mac"/><ports>{sv}</ports></host></nmaprun>')


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        client.post("/api/auth/bootstrap", json={"org_name": "TestOrg", "email": "a@t.io", "password": "supersecret123"})
        tok = client.post("/api/auth/login", data={"username": "a@t.io", "password": "supersecret123"}).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {tok}"
        yield client


@pytest.fixture(scope="module")
def ds():
    return synth.generate(n_assets=150, steps=6, seed=3)


# ---------------------------------------------------------------- dataset safeguards
def test_validation_rejects_bad_data(ds):
    X, y, g, ts = ds["X"], ds["y"], ds["groups"], ds["ts"]
    assert train.validate_dataset(X, y, g, ts)["rows"] == len(X)
    with pytest.raises(train.DatasetError, match="at least"):
        train.validate_dataset(X[:50], y[:50], g[:50], ts[:50])
    bad = X.copy(); bad[0, 0] = np.nan
    with pytest.raises(train.DatasetError, match="NaN"):
        train.validate_dataset(bad, y, g, ts)
    with pytest.raises(train.DatasetError, match="duplicate"):
        train.validate_dataset(np.vstack([X, X[:1]]), np.append(y, y[0]), np.append(g, g[0]), np.append(ts, ts[0]))
    swapped = ts.copy(); swapped[0], swapped[1] = ts[1], ts[0]  # same asset, out-of-order timestamps
    with pytest.raises(train.DatasetError, match="increasing"):
        train.validate_dataset(X, y, g, swapped)
    with pytest.raises(train.DatasetError, match="class"):
        train.validate_dataset(X, np.where(y == 3, 2, y), g, ts)
    with pytest.raises(train.DatasetError, match="expected 16 features"):
        train.validate_dataset(X[:, :10], y, g, ts)


def test_training_is_leak_free_and_beats_baselines(ds):
    _, m, algo, n = train.train_risk(ds["X"], ds["y"], ds["groups"], ds["ts"], "synthetic")
    assert algo == "random_forest" and n == len(ds["X"])
    assert "no asset in both" in m["evaluation"]["leakage_check"]
    assert m["macro_f1"] > m["baselines"]["majority_class_macro_f1"] + 0.3
    assert m["macro_f1"] > m["baselines"]["severity_only_tree_macro_f1"]
    assert set(m["per_class"]) == set(CLASSES) and 0 <= m["ece"] <= 1
    assert m["probabilities_calibrated"] is False


def test_anomaly_model_has_no_blind_spot():
    d = synth.generate()
    _, m, algo, _ = train.train_anomaly(d["Xa"], d["ya"], d["ga"], d["ta"])
    assert algo == "isolation_forest" and m["precision"] > 0.6
    # every kind of sudden change must be caught, including the "2 services -> 12" case with no new vulnerabilities
    assert all(v["recall"] >= 0.6 for v in m["recall_by_type"].values()), m["recall_by_type"]


def test_explanations_work_for_realistic_assets(ds):
    """Regression: explanations crashed when float features (CVSS, EPSS) ranked among the top factors."""
    from app.ml.features import ANOMALY_FEATURES, phrase
    for feat in (*RISK_FEATURES, *ANOMALY_FEATURES):
        for v in (0.0, 1.0, 2.5, 9.8, -3.0):
            assert isinstance(phrase(feat, v), str) and phrase(feat, v)
    bundle, *_ = train.train_risk(ds["X"], ds["y"], ds["groups"], ds["ts"], "synthetic")
    feats = dict(zip(RISK_FEATURES, ds["X"][int(np.argmax(ds["y"]))]))  # a row from the highest-risk class
    feats.update(max_cvss=9.8, max_epss=0.94, n_kev=2, exposure_level=2)
    r = service.predict_risk(bundle, feats)
    assert r["factors"] and any(f["feature"] in ("max_cvss", "max_epss", "n_kev") for f in r["factors"])
    assert all(f["text"] for f in r["factors"])


# ---------------------------------------------------------------- API behaviour
def test_requires_auth_and_admin():
    with TestClient(app) as anon:
        assert anon.get("/api/ml/status").status_code == 401
        assert anon.post("/api/ml/train", json={}).status_code == 401


def test_assess_needs_an_active_model(c):
    r = c.post("/api/scans/import-nmap", files={"file": ("s.xml", nmap_xml("10.77.0.5", "AA:BB:CC:77:00:01", [(22, "OpenSSH", "8.9", "cpe:/a:openbsd:openssh:8.9p1")]))})
    assert r.status_code == 200, r.text
    aid = next(x for x in c.get("/api/assets").json() if "10.77.0.5" in x["identifiers"].get("ip", []))["id"]
    r = c.post(f"/api/ml/assets/{aid}/assess")
    assert r.status_code == 409 and "active" in r.text.lower()


def test_promotion_guard(c):
    r = c.post("/api/ml/train", json={"kind": "risk", "source": "synthetic"})
    assert r.status_code == 201 and r.json()["status"] == "shadow"
    cand = r.json()["id"]
    assert c.post("/api/ml/train", json={"kind": "risk", "source": "feedback"}).status_code == 422  # no approved labels yet
    assert c.post("/api/ml/models/%d/promote" % cand).status_code == 200  # nothing active yet
    worse = c.post("/api/ml/train", json={"kind": "risk", "source": "synthetic"}).json()["id"]
    with SessionLocal() as db:  # make the second candidate measurably worse than the active model
        m = db.get(MLModel, worse); m.metrics = {**m.metrics, "macro_f1": 0.1}; db.commit()
    assert c.post("/api/ml/models/%d/promote" % worse).status_code == 409
    assert c.post("/api/ml/models/%d/promote?force=true" % worse).status_code == 200
    st = c.get("/api/ml/status").json()
    assert st["active"]["risk"]["id"] == worse and "synthetic" in st["active"]["risk"]["notice"].lower()


def test_end_to_end_assessment_anomaly_and_feedback(c):
    assert len(c.post("/api/ml/bootstrap").json()) == 2
    base = [(22, "OpenSSH", "8.9", "cpe:/a:openbsd:openssh:8.9p1"), (80, "Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49")]
    mac = "AA:BB:CC:77:00:02"
    c.post("/api/scans/import-nmap", files={"file": ("s.xml", nmap_xml("10.77.0.6", mac, base))})
    c.post("/api/ml/anomalies/rescan")
    a = next(x for x in c.get("/api/assets").json() if "10.77.0.6" in x["identifiers"].get("ip", []))
    assert not [e for e in c.get("/api/ml/anomalies").json() if e["asset_id"] == a["id"]]  # one observation: no history
    # the asset suddenly exposes 12 services
    many = base + [(9000 + i, "svc", "1.0", "cpe:/a:x:svc:1.0") for i in range(10)]
    c.post("/api/scans/import-nmap", files={"file": ("s.xml", nmap_xml("10.77.0.6", mac, many))})
    an = [e for e in c.get("/api/ml/anomalies?status=open").json() if e["asset_id"] == a["id"]]
    assert an, "2 -> 12 exposed services should be flagged"
    assert any(f["feature"] in ("d_services", "services_ratio") for f in an[0]["factors"])
    r = c.post(f"/api/ml/anomalies/{an[0]['id']}/review", json={"status": "dismissed", "note": "planned rollout"})
    assert r.json()["status"] == "dismissed" and r.json()["reviewed_by"] == "a@t.io"
    # explainable risk assessment
    p = c.post(f"/api/ml/assets/{a['id']}/assess").json()
    assert p["predicted"] in CLASSES and 0 < p["confidence"] <= 1 and p["model_version"].startswith("risk-random_forest-v1-")
    assert abs(sum(p["probabilities"].values()) - 1) < 0.01
    assert p["feature_version"] == "v1" and set(RISK_FEATURES) == set(p["features"])
    assert p["factors"] and all(f["text"] and f["effect"] in ("raises", "lowers") for f in p["factors"])
    assert p["factors"][0]["method"] == "shap"
    assert c.post("/api/ml/assess-all").json()["assessed"] >= 1
    rows = c.get("/api/ml/assessments").json()
    assert rows and {"rule_tier", "predicted", "top_factor"} <= set(rows[0])
    # analyst feedback needs a second person to approve before it can train anything
    fb = c.post(f"/api/ml/assets/{a['id']}/feedback", json={"label": "high", "note": "confirmed exposed"}).json()
    assert c.post("/api/ml/assets/%d/feedback" % a["id"], json={"label": "bogus"}).status_code == 422
    assert c.post(f"/api/ml/feedback/{fb['id']}/approve").status_code == 403
    d = c.get(f"/api/ml/assets/{a['id']}").json()
    assert d["latest"]["id"] >= p["id"] and len(d["history"]) >= 2 and d["notice"]
