#!/usr/bin/env python3
"""Stand-in for nmap in tests: prints nmap-style XML for the hosts listed in $FAKE_NMAP_STATE that fall inside the
target. Lets the live-scan path (scope -> scan -> ingest) be tested without a network or the real binary."""
import ipaddress
import json
import os
import sys

argv = sys.argv[1:]
target = argv[argv.index("--") + 1]
state = json.load(open(os.environ["FAKE_NMAP_STATE"]))
net = ipaddress.ip_network(target, strict=False)
out = ['<?xml version="1.0"?><nmaprun><scaninfo type="connect" protocol="tcp" services="1-1000"/>']
for h in state["hosts"]:
    if ipaddress.ip_address(h["ip"]) not in net:
        continue
    ports = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="http" product="{pr}" version="{v}">'
        + "".join(f"<cpe>{c}</cpe>" for c in cpes[:1]) + "</service></port>"
        for p, pr, v, cpes in h["services"])
    out.append(f'<host><status state="up"/><address addr="{h["ip"]}" addrtype="ipv4"/><ports>{ports}</ports></host>')
out.append("</nmaprun>")
print("".join(out))
