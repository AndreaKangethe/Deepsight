"""Prepare the walkthrough: load starter intelligence and the sample estate (6 assets with owners).

    python lab/demo/prepare.py --email admin@example.org --password '...'            # offline
    python lab/demo/prepare.py --email ... --password '...' --online-epss            # real KEV + EPSS feeds
    python lab/demo/prepare.py --email ... --password '...' --intel-only             # live-scan lab: no sample assets

Run it once after first-run setup. Everything after that (importing scans, the ML tab) is shown live in the app.
The bundled EPSS file holds ILLUSTRATIVE values for offline use; use --online-epss for real data.
"""
import argparse
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--online-epss", action="store_true", help="download real CISA KEV and EPSS instead of the bundled sample")
    ap.add_argument("--intel-only", action="store_true", help="load vulnerability intelligence only (use for the live-scan lab; skips the sample assets)")
    a = ap.parse_args()
    c = httpx.Client(base_url=a.url, timeout=180)
    r = c.post("/api/auth/login", data={"username": a.email, "password": a.password})
    if r.status_code != 200:
        sys.exit(f"Login failed ({r.status_code}). Complete first-run setup in the browser first.")
    c.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    kinds = ["seed", "kev", "epss"] if a.online_epss else ["seed"]
    c.post("/api/intel/sync", json={"kinds": kinds}).raise_for_status()
    for _ in range(120):  # the sync runs in the background
        st = c.get("/api/intel/status").json()
        done = {s["kind"] for s in st["sources"]}
        if set(kinds) <= done and st["vulnerabilities"] > 0:
            break
        time.sleep(1)
    if not a.online_epss:
        with open(HERE / "epss_illustrative.csv", "rb") as fh:
            c.post("/api/intel/import/epss", files={"file": fh}).raise_for_status()
    st = c.get("/api/intel/status").json()
    print(f"Intelligence: {st['vulnerabilities']} CVEs, {st['kev']} known exploited, {st['with_epss']} with EPSS")
    if a.intel_only:
        print("Next, in the app: Scope -> add rules, then Scans -> scan the lab range.")
        return
    with open(HERE / "assets.csv", "rb") as fh:
        out = c.post("/api/assets/import-csv", files={"file": fh}).json()
    print(f"Assets: {out['created']} created, {out['matched_existing']} matched, {len(out['errors'])} errors")
    print("Next, in the app: Scans -> import lab/demo/scan1_baseline.xml (Nmap XML).")


if __name__ == "__main__":
    main()
