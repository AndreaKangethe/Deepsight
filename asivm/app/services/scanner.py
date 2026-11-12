"""Scanner adapters (nmap, trivy) behind one runner. Scope is re-validated at execution time."""
import json
import re
import subprocess

from ..config import settings
from ..db import SessionLocal
from ..models import Scan, utcnow
from . import parsers, pipeline, scope, trends

PROFILES = {
    "discovery": ["-sn"],
    "quick": ["-F", "-sV", "--version-light"],
    "standard": ["-sV", "--top-ports", "1000"],
    "full": ["-sV", "-p-"],
}
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")


def nmap_command(target: str, profile: str, excludes: list[str]) -> list[str]:
    opts = PROFILES[profile]
    cmd = [settings.nmap_path, *opts, "-T3", "--host-timeout", "15m", "-oX", "-", "--no-stylesheet"]
    if excludes:
        cmd += ["--exclude", ",".join(excludes)]
    return cmd + ["--", target]  # argv list + '--' => target can never be parsed as an option


def run_scan(scan_id: int, runner=subprocess.run):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        scan.status, scan.started_at = "running", utcnow()
        db.commit()
        try:
            if scan.tool in ("nmap", "discovery"):
                d = scope.validate_target(db, scan.org_id, scan.target)
                if not d.allowed:
                    raise PermissionError(f"scope violation: {d.reason}")
                prof = "discovery" if scan.tool == "discovery" else (scan.profile or "standard")
                cmd = nmap_command(scan.target, prof, scope.deny_cidrs(db, scan.org_id))
                p = runner(cmd, capture_output=True, text=True, timeout=settings.scan_timeout_seconds)
                if p.returncode != 0:
                    raise RuntimeError(f"nmap exited {p.returncode}: {p.stderr[:500]}")
                hosts = parsers.parse_nmap_xml(p.stdout)
                summary = pipeline.ingest_hosts(db, scan, hosts, with_services=scan.tool == "nmap")
                summary["scope_decision"] = d.reason
            elif scan.tool == "trivy":
                if not IMAGE_RE.match(scan.target):
                    raise ValueError("invalid image/artifact name")
                p = runner([settings.trivy_path, "image", "--quiet", "--format", "json", scan.target],
                           capture_output=True, text=True, timeout=settings.scan_timeout_seconds)
                if p.returncode != 0:
                    raise RuntimeError(f"trivy exited {p.returncode}: {p.stderr[:500]}")
                art, vulns = parsers.parse_trivy(json.loads(p.stdout))
                summary = pipeline.ingest_trivy(db, scan, art or scan.target, vulns,
                                                asset_id=(scan.summary or {}).get("asset_id"))
            else:
                raise ValueError(f"unknown tool {scan.tool}")
            scan.status, scan.summary = "completed", summary
            trends.record_snapshot(db, scan.org_id)
        except Exception as e:
            db.rollback()
            scan = db.get(Scan, scan_id)
            scan.status, scan.error = "failed", str(e)[:1000]
        scan.finished_at = utcnow()
        db.commit()
    finally:
        db.close()
