"""Fix guidance for a finding: target version, ordered steps, workarounds, references.

Sources, in order of trust: Trivy's FixedVersion, the fixed version implied by the advisory's affected
range (versionEndExcluding), then a curated note for well-known CVEs. Nothing here is invented: when no
fixed version can be derived, the advice says to move to the latest supported release.
"""
from . import versions

KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
VENDOR = {
    "http_server": ("Apache httpd security advisories", "https://httpd.apache.org/security/vulnerabilities_24.html"),
    "openssh": ("OpenSSH security", "https://www.openssh.com/security.html"),
    "nginx": ("nginx security advisories", "https://nginx.org/en/security_advisories.html"),
    "log4j": ("Apache Log4j security", "https://logging.apache.org/log4j/2.x/security.html"),
    "samba": ("Samba security releases", "https://www.samba.org/samba/security/"),
    "tomcat": ("Apache Tomcat security", "https://tomcat.apache.org/security.html"),
}

CURATED = {
    "CVE-2021-41773": {"fixed_in": "2.4.51 or later (2.4.50 was an incomplete fix)",
        "workarounds": ["Make sure the filesystem root is protected: <Directory /> must say 'Require all denied'.",
                        "Disable mod_cgi / mod_cgid if CGI is not needed."]},
    "CVE-2021-42013": {"fixed_in": "2.4.51 or later",
        "workarounds": ["Make sure the filesystem root is protected: <Directory /> must say 'Require all denied'.",
                        "Disable mod_cgi / mod_cgid if CGI is not needed."]},
    "CVE-2019-0211": {"fixed_in": "2.4.39 or later",
        "workarounds": ["Do not allow untrusted users to run scripts (PHP, CGI) on the server until patched."]},
    "CVE-2024-6387": {"fixed_in": "9.8p1 or later",
        "workarounds": ["Set 'LoginGraceTime 0' in sshd_config and restart sshd. This stops the race but makes sshd "
                        "easier to exhaust with connections, so treat it as temporary."]},
    "CVE-2023-38408": {"fixed_in": "9.3p2 or later",
        "workarounds": ["Do not forward ssh-agent to hosts you do not fully control.",
                        "Avoid loading PKCS#11 providers from untrusted paths."]},
    "CVE-2018-15473": {"fixed_in": "7.8 or later",
        "workarounds": ["Lower exposure: restrict SSH to trusted networks or a VPN/bastion. This bug only reveals which usernames exist."]},
    "CVE-2011-2523": {"fixed_in": "2.3.5 or later, installed from your distribution's repository, not the 2.3.4 source tarball",
        "steps": ["This version shipped with a backdoor. Treat the host as potentially compromised: check for the "
                  "unexpected listener on port 6200 and review the host before trusting it again."],
        "workarounds": ["Block inbound port 21 (and 6200) until upgraded, or disable FTP if it is not needed."]},
    "CVE-2017-7494": {"workarounds": ["Add 'nt pipe support = no' to the [global] section of smb.conf and restart smbd.",
                                       "Make sure no share is writable by anonymous or untrusted users."]},
    "CVE-2021-23017": {"fixed_in": "1.20.1 (stable) or 1.21.0 (mainline) or later",
        "workarounds": ["Only configurations that use the 'resolver' directive are exposed. If you do not use it, "
                        "exposure is lower, but still upgrade."]},
    "CVE-2021-44228": {"fixed_in": "2.17.1 or later (2.15.0 was the first fix; later releases close follow-on issues)",
        "workarounds": ["Remove the JndiLookup class from the jar: "
                        "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
                        "Block outbound LDAP/RMI/DNS from application servers to the internet."]},
    "CVE-2020-1938": {"workarounds": ["Disable the AJP connector if it is not used, or bind it to localhost and set a required secret.",
                                       "Never expose port 8009 to untrusted networks."]},
}


def _bound(r):
    return r.end_excl, r.end_incl


def derived_fix(rows, product, installed):
    """Fixed version implied by the advisory range that contains the installed version."""
    pool = [r for r in rows if r.product == product] or list(rows)
    hits = [r for r in pool if versions.in_range(installed, r.version_exact, r.start_incl, r.start_excl, r.end_incl, r.end_excl)]
    fixes = sorted({r.end_excl for r in hits if r.end_excl}, key=lambda v: versions.vtuple(v) or ())
    if fixes:
        return f"{fixes[0]} or later"
    after = sorted({r.end_incl for r in hits if r.end_incl}, key=lambda v: versions.vtuple(v) or ())
    if after:
        return f"a release newer than {after[-1]}"
    return None


def fix_target(f, rows):
    ev = f.evidence or {}
    sw, m = ev.get("software", {}), ev.get("matching", {})
    if sw.get("fixed_version"):
        return str(sw["fixed_version"]) + " or later"
    cur = CURATED.get(f.cve_id, {})
    if cur.get("fixed_in"):
        return cur["fixed_in"]
    prod = (m.get("advisory_product") or ":").split(":")[-1]
    return derived_fix(rows, prod, sw.get("version"))


def fix_hint(f, rows) -> str:
    t = fix_target(f, rows)
    return f"Upgrade to {t}" if t else "Update to the latest supported release"


def build(f, vuln, rows, asset, ips) -> dict:
    ev = f.evidence or {}
    sw, m = ev.get("software", {}), ev.get("matching", {})
    name, installed, port = sw.get("name") or "the software", sw.get("version") or "the installed version", sw.get("port")
    target = fix_target(f, rows)
    cur = CURATED.get(f.cve_id, {})
    steps = []
    if sw.get("source") == "trivy":
        steps.append(f"Update package '{name}' from {installed} to {target or 'a patched version'} "
                     f"(scan target: {sw.get('target') or 'unknown'}), then rebuild and redeploy.")
    else:
        steps.append(f"Upgrade {name} on {asset.name} from {installed} to {target or 'the latest supported release'}.")
    steps += cur.get("steps", [])
    if any("backport" in n for n in m.get("notes", [])):
        steps.append("This is a distribution package. Update through the package manager (apt, dnf, yum) and check the "
                     "distribution's security tracker: the fix may be backported without the version number changing. "
                     "If the vendor confirms your build is patched, record the finding as 'accepted risk' with that note.")
    steps.append("Restart the service and confirm the new version is the one running.")
    steps.append("Back in ASIVM, mark the finding fixed, then click 'Verify by re-scan'. It closes only when the issue is "
                 "no longer observed.")
    work = list(cur.get("workarounds", []))
    where = f"{port}/{sw.get('protocol') or 'tcp'}" if port else "the affected service"
    work.append(f"If you cannot patch yet, limit access to {where} to trusted hosts with a firewall rule, "
                "or stop the service if it is not needed.")
    if asset.exposure == "internet":
        work.insert(0, "This asset is internet-facing: apply the access restriction first, then patch.")
    refs = [{"title": f"NVD: {f.cve_id}", "url": f"https://nvd.nist.gov/vuln/detail/{f.cve_id}"}]
    prod = (m.get("advisory_product") or ":").split(":")[-1]
    if prod in VENDOR:
        refs.append({"title": VENDOR[prod][0], "url": VENDOR[prod][1]})
    if vuln.kev:
        refs.append({"title": "CISA Known Exploited Vulnerabilities catalog", "url": KEV_URL})
    urgency = None
    if vuln.kev:
        urgency = "Exploited in the wild (CISA KEV)" + (f"; CISA's remediation due date is {vuln.kev_due}" if vuln.kev_due else "") + "."
    return {"fixed_version": target, "headline": fix_hint(f, rows), "urgency": urgency, "steps": steps,
            "workarounds": work, "references": refs,
            "sla": f"Target fix date: {f.due_at.date()}" if f.due_at else None}
