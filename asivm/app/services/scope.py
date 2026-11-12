"""Scope validator: nothing is scanned unless an allow rule covers it and no deny rule touches it."""
import fnmatch
import ipaddress
import re
import socket
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import ScopeRule

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


@dataclass
class Decision:
    allowed: bool
    reason: str
    kind: str | None = None  # ip|cidr|hostname


def validate_target(db: Session, org_id: int, target: str) -> Decision:
    target = (target or "").strip()
    if not target or target.startswith("-") or any(c.isspace() for c in target):
        return Decision(False, "invalid target syntax")
    rules = db.scalars(select(ScopeRule).where(ScopeRule.org_id == org_id)).all()
    allow = [r for r in rules if r.action == "allow"]
    deny = [r for r in rules if r.action == "deny"]
    if not allow:
        return Decision(False, "no allow rules defined: scope is empty, so nothing may be scanned")

    def nets(rs):
        out = []
        for r in rs:
            if r.kind == "cidr":
                try:
                    out.append(ipaddress.ip_network(r.value, strict=False))
                except ValueError:
                    pass
        return out

    allow_n, deny_n = nets(allow), nets(deny)

    def check_net(net, label):
        if net.num_addresses > settings.max_scan_hosts:
            return Decision(False, f"target too large ({net.num_addresses} addresses; max {settings.max_scan_hosts})")
        for d in deny_n:
            if net.version == d.version and net.overlaps(d):
                return Decision(False, f"{label} overlaps deny rule {d}")
        for a in allow_n:
            if net.version == a.version and net.subnet_of(a):
                return Decision(True, f"covered by allow rule {a}", "cidr" if net.num_addresses > 1 else "ip")
        return Decision(False, f"{label} is not fully inside any allow rule")

    try:
        net = ipaddress.ip_network(target, strict=False)
        return check_net(net, str(net))
    except ValueError:
        pass

    if not HOST_RE.match(target):
        return Decision(False, "target is neither an IP/CIDR nor a valid hostname")
    host = target.lower()
    if any(fnmatch.fnmatch(host, r.value.lower()) for r in deny if r.kind == "hostname"):
        return Decision(False, "hostname matches a deny rule")
    host_allowed = any(fnmatch.fnmatch(host, r.value.lower()) for r in allow if r.kind == "hostname")
    try:
        addrs = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)}
    except OSError:
        return Decision(False, "hostname cannot be resolved")
    for ip in addrs:
        n = ipaddress.ip_network(ip)
        if any(n.version == d.version and n.overlaps(d) for d in deny_n):
            return Decision(False, f"resolved address {ip} is inside a deny rule")
    if host_allowed:
        return Decision(True, "hostname matches an allow rule", "hostname")
    if all(any(ip.version == a.version and ip in a for a in allow_n) for ip in addrs):
        return Decision(True, "all resolved addresses are inside allow rules", "hostname")
    return Decision(False, "hostname is not covered by any allow rule")


def deny_cidrs(db: Session, org_id: int) -> list[str]:
    return [r.value for r in db.scalars(select(ScopeRule).where(
        ScopeRule.org_id == org_id, ScopeRule.action == "deny", ScopeRule.kind == "cidr"))]
