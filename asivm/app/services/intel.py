"""Vulnerability intelligence: NVD, CISA KEV, EPSS (+ offline import and a small seed set)."""
import csv
import gzip
import io
import json
import time
from datetime import timedelta

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import CveProduct, IntelStatus, Vulnerability, utcnow

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def _status(db: Session, kind: str, count: int, note: str | None = None):
    s = db.get(IntelStatus, kind) or IntelStatus(kind=kind)
    s.last_sync, s.count, s.note = utcnow(), count, note
    db.add(s)


def parse_cpe23(c: str):
    p = c.split(":")
    return (p[2], p[3], p[4], p[5]) if len(p) > 5 and p[0] == "cpe" else (None,) * 4


def upsert_nvd(db: Session, items: list) -> int:
    n = 0
    for item in items:
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cvss = sev = None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            m = (cve.get("metrics") or {}).get(key)
            if m:
                d = m[0].get("cvssData", {})
                cvss, sev = d.get("baseScore"), d.get("baseSeverity") or m[0].get("baseSeverity")
                break
        v = db.get(Vulnerability, cid) or Vulnerability(cve_id=cid)
        v.description, v.published = desc, (cve.get("published") or "")[:10]
        if cvss is not None:
            v.cvss, v.severity = cvss, (sev or "").lower() or None
        v.source, v.updated_at = v.source or "nvd", utcnow()
        db.add(v)
        db.flush()
        db.execute(delete(CveProduct).where(CveProduct.cve_id == cid))
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    part, vendor, product, ver = parse_cpe23(m.get("criteria", ""))
                    if part != "a":
                        continue
                    exact = ver if ver not in ("*", "-", None) else None
                    b = (m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                         m.get("versionEndIncluding"), m.get("versionEndExcluding"))
                    if not exact and not any(b):
                        continue
                    db.add(CveProduct(cve_id=cid, vendor=vendor, product=product, version_exact=exact,
                                      start_incl=b[0], start_excl=b[1], end_incl=b[2], end_excl=b[3]))
        n += 1
    return n


def apply_kev(db: Session, data: dict) -> int:
    n = 0
    for e in data.get("vulnerabilities", []):
        cid = e.get("cveID")
        if not cid:
            continue
        v = db.get(Vulnerability, cid) or Vulnerability(cve_id=cid, description=e.get("shortDescription"), source="kev")
        v.kev, v.kev_due = True, e.get("dueDate")
        db.add(v)
        n += 1
    return n


def apply_epss(db: Session, text: str) -> int:
    known = set(db.scalars(select(Vulnerability.cve_id)))
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    n = 0
    for r in csv.DictReader(lines):
        v = r.get("cve") in known and db.get(Vulnerability, r["cve"])
        if v:
            v.epss, v.epss_percentile = float(r["epss"]), float(r.get("percentile") or 0)
            n += 1
    return n


def sync_nvd(db: Session, days: int = 30, cve: str | None = None) -> int:
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    delay = 0.7 if settings.nvd_api_key else 6.5
    total, start = 0, 0
    params = {"resultsPerPage": 2000}
    if cve:
        params["cveId"] = cve
    else:
        end = utcnow()
        params.update(lastModStartDate=(end - timedelta(days=min(days, 120))).strftime("%Y-%m-%dT%H:%M:%S.000"),
                      lastModEndDate=end.strftime("%Y-%m-%dT%H:%M:%S.000"))
    with httpx.Client(timeout=60, headers=headers) as c:
        while True:
            r = c.get(NVD_URL, params={**params, "startIndex": start})
            r.raise_for_status()
            j = r.json()
            total += upsert_nvd(db, j.get("vulnerabilities", []))
            db.commit()
            start += j.get("resultsPerPage", 0)
            if start >= j.get("totalResults", 0) or not j.get("resultsPerPage"):
                break
            time.sleep(delay)
    return total


def run_sync(db: Session, kinds: list[str], days: int = 30, cve: str | None = None) -> dict:
    out = {}
    for k in kinds:
        try:
            if k == "seed":
                n = seed(db)
            elif k == "kev":
                n = apply_kev(db, httpx.get(KEV_URL, timeout=60, follow_redirects=True).raise_for_status().json())
            elif k == "epss":
                raw = httpx.get(EPSS_URL, timeout=120, follow_redirects=True).raise_for_status().content
                n = apply_epss(db, gzip.decompress(raw).decode())
            elif k == "nvd":
                n = sync_nvd(db, days, cve)
            else:
                continue
            _status(db, k, n, "ok")
            out[k] = {"ok": True, "count": n}
        except Exception as e:  # keep going; record failure
            db.rollback()
            _status(db, k, 0, f"error: {e}")
            out[k] = {"ok": False, "error": str(e)}
        db.commit()
    return out


def import_file(db: Session, kind: str, content: bytes) -> int:
    if content[:2] == b"\x1f\x8b":
        content = gzip.decompress(content)
    if kind == "nvd":
        n = upsert_nvd(db, json.loads(content).get("vulnerabilities", []))
    elif kind == "kev":
        n = apply_kev(db, json.loads(content))
    elif kind == "epss":
        n = apply_epss(db, content.decode())
    else:
        raise ValueError("kind must be nvd, kev or epss")
    _status(db, kind, n, "imported from file")
    db.commit()
    return n


# Small offline starter set so the platform works on first boot. Run a KEV/EPSS/NVD sync for
# authoritative, current data. EPSS is intentionally left empty here (it changes daily).
SEED = [
    ("CVE-2021-41773", "Apache HTTP Server 2.4.49 path traversal / file disclosure (RCE when CGI enabled).", 7.5, "high", True,
     [("apache", "http_server", {"exact": "2.4.49"})]),
    ("CVE-2021-42013", "Apache HTTP Server 2.4.49-2.4.50 path traversal and remote code execution.", 9.8, "critical", True,
     [("apache", "http_server", {"exact": "2.4.49"}), ("apache", "http_server", {"exact": "2.4.50"})]),
    ("CVE-2019-0211", "Apache HTTP Server 2.4.17-2.4.38 local privilege escalation via scoreboard.", 7.8, "high", False,
     [("apache", "http_server", {"start_incl": "2.4.17", "end_incl": "2.4.38"})]),
    ("CVE-2024-6387", "OpenSSH sshd signal handler race condition (regreSSHion), unauthenticated RCE.", 8.1, "high", False,
     [("openbsd", "openssh", {"start_incl": "8.5", "end_excl": "9.8"})]),
    ("CVE-2023-38408", "OpenSSH ssh-agent PKCS#11 remote code execution via forwarded agent.", 9.8, "critical", False,
     [("openbsd", "openssh", {"end_excl": "9.3.2"})]),
    ("CVE-2018-15473", "OpenSSH username enumeration via malformed authentication packets.", 5.3, "medium", False,
     [("openbsd", "openssh", {"end_incl": "7.7"})]),
    ("CVE-2011-2523", "vsftpd 2.3.4 backdoor: smiley-face username opens a root shell on port 6200.", 9.8, "critical", False,
     [("beasts", "vsftpd", {"exact": "2.3.4"})]),
    ("CVE-2017-7494", "Samba 'SambaCry': remote code execution via a writable share and shared library upload.", 9.8, "critical", False,
     [("samba", "samba", {"start_incl": "3.5.0", "end_excl": "4.4.14"}),
      ("samba", "samba", {"start_incl": "4.5.0", "end_excl": "4.5.10"}),
      ("samba", "samba", {"start_incl": "4.6.0", "end_excl": "4.6.4"})]),
    ("CVE-2021-23017", "nginx resolver off-by-one allowing DNS-response memory overwrite.", 7.7, "high", False,
     [("nginx", "nginx", {"start_incl": "0.6.18", "end_excl": "1.20.1"})]),
    ("CVE-2021-44228", "Apache Log4j2 JNDI lookup remote code execution (Log4Shell).", 10.0, "critical", True,
     [("apache", "log4j", {"start_incl": "2.0", "end_excl": "2.15.0"})]),
    ("CVE-2020-1938", "Apache Tomcat AJP connector file read / RCE (Ghostcat).", 9.8, "critical", False,
     [("apache", "tomcat", {"start_incl": "7.0.0", "end_excl": "7.0.100"}),
      ("apache", "tomcat", {"start_incl": "8.5.0", "end_excl": "8.5.51"}),
      ("apache", "tomcat", {"start_incl": "9.0.0", "end_excl": "9.0.31"})]),
]


def seed(db: Session) -> int:
    for cid, desc, cvss, sev, kev, prods in SEED:
        v = db.get(Vulnerability, cid) or Vulnerability(cve_id=cid)
        v.description, v.cvss, v.severity = desc, cvss, sev
        v.kev = v.kev or kev
        v.source = v.source or "seed"
        db.add(v)
        db.flush()
        db.execute(delete(CveProduct).where(CveProduct.cve_id == cid))
        for vendor, product, b in prods:
            db.add(CveProduct(cve_id=cid, vendor=vendor, product=product, version_exact=b.get("exact"),
                              start_incl=b.get("start_incl"), end_incl=b.get("end_incl"), end_excl=b.get("end_excl")))
    db.flush()
    return len(SEED)
