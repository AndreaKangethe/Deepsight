import xml.etree.ElementTree as _ET  # noqa: F401  (types only)
from dataclasses import dataclass, field

from defusedxml import ElementTree as ET


@dataclass
class ParsedService:
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpe: str | None = None


@dataclass
class ParsedHost:
    ips: list = field(default_factory=list)
    mac: str | None = None
    hostnames: list = field(default_factory=list)
    os: str | None = None
    services: list = field(default_factory=list)
    scanned_ports: dict | None = None  # {"tcp": "1-1000,3306"}

    def identifiers(self) -> dict:
        d = {"ip": self.ips, "hostname": self.hostnames}
        if self.mac:
            d["mac"] = [self.mac]
        return d


def port_in_spec(port: int, spec: str | None) -> bool:
    if not spec:
        return False
    for part in spec.split(","):
        part = part.strip()
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                if int(a) <= port <= int(b):
                    return True
            elif int(part) == port:
                return True
        except ValueError:
            continue
    return False


def parse_nmap_xml(text: str) -> list[ParsedHost]:
    root = ET.fromstring(text)
    scanned: dict = {}
    for si in root.findall("scaninfo"):
        proto, svc = si.get("protocol", "tcp"), si.get("services", "")
        scanned[proto] = (scanned.get(proto, "") + "," + svc).strip(",")
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ph = ParsedHost(scanned_ports=scanned or None)
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t in ("ipv4", "ipv6"):
                ph.ips.append(a.get("addr"))
            elif t == "mac":
                ph.mac = a.get("addr")
        ph.hostnames = [x.get("name") for x in h.findall("hostnames/hostname") if x.get("name")]
        om = h.find("os/osmatch")
        if om is not None:
            ph.os = om.get("name")
        for p in h.findall("ports/port"):
            s = p.find("state")
            if s is None or s.get("state") != "open":
                continue
            sv = p.find("service")
            ps = ParsedService(port=int(p.get("portid")), protocol=p.get("protocol", "tcp"))
            if sv is not None:
                ps.service, ps.product = sv.get("name"), sv.get("product")
                ps.version, ps.extrainfo = sv.get("version"), sv.get("extrainfo")
                c = sv.find("cpe")
                ps.cpe = c.text if c is not None else None
            ph.services.append(ps)
        hosts.append(ph)
    return hosts


def parse_trivy(data: dict):
    """-> (artifact_name, [vuln dicts])"""
    out = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            score = None
            cv = v.get("CVSS") or {}
            for src in ("nvd", *cv.keys()):
                s = (cv.get(src) or {}).get("V3Score") or (cv.get(src) or {}).get("V2Score")
                if s:
                    score = float(s)
                    break
            out.append({"id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion"),
                        "severity": (v.get("Severity") or "").lower() or None,
                        "title": v.get("Title"), "description": v.get("Description"),
                        "cvss": score, "target": res.get("Target"), "type": res.get("Type"),
                        "published": v.get("PublishedDate")})
    return data.get("ArtifactName"), [v for v in out if v["id"] and v["pkg"]]
