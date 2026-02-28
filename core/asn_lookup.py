#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Dict

ENCODED_STR = "wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
VERSION = "1.0.0"
IPV4_RE = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$")


def run_cmd(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return ""
    return proc.stdout


def parse_asn_line(line: str) -> Dict[str, str]:
    parts = line.split("|")
    if len(parts) < 7:
        return {"asn": "", "country": "", "owner": ""}
    asn = parts[0].strip()
    country = parts[3].strip()
    owner = parts[6].strip()
    return {"asn": asn, "country": country, "owner": owner}


def lookup_reverse_host(ip: str) -> str:
    out = run_cmd(["host", ip])
    if not out:
        return ""
    m = re.search(r"pointer\s+([^\s.]+(?:\.[^\s.]+)*)\.?", out)
    return m.group(1) if m else ""


def main() -> int:
    parser = argparse.ArgumentParser(description="ASN lookup for an IPv4 address")
    parser.add_argument("ip", help="IPv4 address or m")
    parser.add_argument("--json", "-j", action="store_true", help="Output JSON")
    parser.add_argument("--version", "-v", action="store_true", help="Show version")
    args = parser.parse_args()

    if args.version:
        print(f"asn_lookup.py {VERSION}")
        return 0

    if args.ip == "m":
        import base64

        print(base64.b64decode(ENCODED_STR).decode("utf-8", errors="replace"), end="")
        return 0

    ip = args.ip.strip()
    if not IPV4_RE.match(ip):
        print("Invalid IPv4 address")
        return 1

    asn_out = run_cmd(["whois", "-h", "v4.whois.cymru.com", f" -v {ip}"])
    if not asn_out.strip():
        print(f"ASN not found for IP address: {ip}")
        return 1

    lines = [ln for ln in asn_out.splitlines() if ln.strip()]
    asn_line = lines[1] if len(lines) > 1 else ""
    parsed = parse_asn_line(asn_line)

    reverse_host = ""
    if subprocess.run(["bash", "-lc", "command -v host >/dev/null 2>&1"]).returncode == 0:
        reverse_host = lookup_reverse_host(ip)

    if args.json:
        print(
            json.dumps(
                {
                    "ip": ip,
                    "asn": parsed["asn"],
                    "country": parsed["country"],
                    "owner": parsed["owner"],
                    "reverse_host": reverse_host,
                }
            )
        )
        return 0

    print()
    print(asn_out.rstrip())
    print()
    if reverse_host:
        print(f"Reverse host: {reverse_host}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
