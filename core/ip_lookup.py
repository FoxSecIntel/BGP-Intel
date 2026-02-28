#!/usr/bin/env python3
"""
IP Intel lookup utility for BGP-Intel.

This script uses the RIPEstat Data API for reliable prefix and country intelligence.
It also includes automated risk flagging for sanctioned or high-threat regions.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

import requests

USER_AGENT = "IP-Lookup-Intel-Tool/1.1"
TIMEOUT_SECONDS = 5
PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
RIR_STATS_COUNTRY_URL = "https://stat.ripe.net/data/rir-stats-country/data.json"
HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP", "SY"}


def fetch_json(url: str, ip: str) -> Dict[str, Any]:
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, params={"resource": ip}, headers=headers, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def extract_rir(block_desc: str) -> str:
    known = ["AFRINIC", "APNIC", "ARIN", "LACNIC", "RIPE"]
    upper = block_desc.upper()
    for rir in known:
        if rir in upper:
            return rir
    return "UNKNOWN"


def analyse_ip(ip: str) -> Dict[str, Any]:
    # Initialising RIPEstat intelligence collection, Analysing prefix and country data.
    prefix_payload = fetch_json(PREFIX_OVERVIEW_URL, ip)
    country_payload = fetch_json(RIR_STATS_COUNTRY_URL, ip)

    prefix_data = prefix_payload.get("data", {})
    asns = prefix_data.get("asns", [])

    asn_value: str = "UNKNOWN"
    holder: str = "UNKNOWN"
    if isinstance(asns, list) and asns:
        first = asns[0] if isinstance(asns[0], dict) else {}
        asn_raw = first.get("asn")
        holder = str(first.get("holder") or "UNKNOWN")
        if asn_raw is not None:
            asn_value = str(asn_raw)

    block = prefix_data.get("block", {})
    block_desc = str(block.get("desc") or "") if isinstance(block, dict) else ""
    rir = extract_rir(block_desc)

    country_code = "UNKNOWN"
    country_data = country_payload.get("data", {})
    located = country_data.get("located_resources", [])
    if isinstance(located, list) and located:
        first_loc = located[0] if isinstance(located[0], dict) else {}
        code = first_loc.get("location")
        if isinstance(code, str) and code:
            country_code = code.upper()

    is_high_risk = country_code in HIGH_RISK_COUNTRIES

    return {
        "ip": ip,
        "asn": asn_value,
        "holder": holder,
        "country_code": country_code,
        "rir": rir,
        "is_high_risk": is_high_risk,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialising IP Intel lookup using RIPEstat")
    parser.add_argument("ip", help="IP address to lookup")
    parser.add_argument("--json", action="store_true", help="Output flat JSON only")
    args = parser.parse_args()

    try:
        result = analyse_ip(args.ip)
    except requests.exceptions.RequestException as exc:
        msg = "Authorised network request failed, the RIPEstat service is unreachable."
        if args.json:
            print(json.dumps({"error": msg, "details": str(exc)}))
        else:
            print(msg)
            print(f"Details: {exc}")
        return 1
    except Exception as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"Lookup failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(result, separators=(",", ":")))
        return 0

    print("Analysing complete, result summary:")
    print(f"IP: {result['ip']}")
    print(f"Holder: {result['holder']}")
    print(f"ASN: {result['asn']}")
    print(f"Location: {result['country_code']} ({result['rir']})")
    if result["is_high_risk"]:
        print("[⚠️ WARNING: HIGH-RISK JURISDICTION DETECTED]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
