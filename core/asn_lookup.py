#!/usr/bin/env python3
"""
ASN Network Integrity Auditor for BGP-Intel.

This standalone script analyses ASN intelligence using RIPEstat Data API endpoints.
It evaluates entity context, routing scope, upstream transit posture, and risk signals.
"""

from __future__ import annotations

import argparse
import json
import ipaddress
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import requests

USER_AGENT = "ASN-Intel-Audit/1.1"
TIMEOUT_SECONDS = 5

AS_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json"
ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
ASN_NEIGHBOURS_URL = "https://stat.ripe.net/data/asn-neighbours/data.json"
RIS_FIRST_LAST_SEEN_URL = "https://stat.ripe.net/data/ris-first-last-seen/data.json"
PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"

HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP", "SY"}
COUNTRY_TAIL_RE = re.compile(r",\s*([A-Z]{2})\s*$")

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"


def normalise_asn(value: str) -> str:
    v = value.strip().upper()
    return v if v.startswith("AS") else f"AS{v}"


def is_ip_resource(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def resolve_asn_from_ip(ip: str) -> str:
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(PREFIX_OVERVIEW_URL, params={"resource": ip}, headers=headers, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    data = response.json().get("data", {})
    asns = data.get("asns", [])
    if isinstance(asns, list) and asns:
        first = asns[0] if isinstance(asns[0], dict) else {}
        asn = first.get("asn")
        if asn is not None:
            return normalise_asn(str(asn))
    raise RuntimeError(f"No ASN mapping found for IP: {ip}")


def parse_iso_time(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def fetch_json(url: str, asn: str) -> Dict[str, Any]:
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, params={"resource": asn}, headers=headers, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json().get("data", {})


def infer_registration_country(holder: str) -> str:
    match = COUNTRY_TAIL_RE.search(holder or "")
    if match:
        return match.group(1)
    return "UNKNOWN"


def get_upstreams(neighbours: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    left = [n for n in neighbours if str(n.get("type", "")).lower() == "left"]
    left.sort(key=lambda x: int(x.get("power", 0)), reverse=True)
    out: List[Dict[str, Any]] = []
    for n in left[:3]:
        out.append(
            {
                "asn": normalise_asn(str(n.get("asn", "UNKNOWN"))),
                "power": int(n.get("power", 0)),
                "v4_peers": int(n.get("v4_peers", 0)),
                "v6_peers": int(n.get("v6_peers", 0)),
            }
        )
    return out


def analyse_asn(resource_input: str) -> Dict[str, Any]:
    raw = resource_input.strip()
    resolved_from_ip = is_ip_resource(raw)
    asn = resolve_asn_from_ip(raw) if resolved_from_ip else normalise_asn(raw)

    # Initialising data collection, Analysing RIPEstat sources.
    overview = fetch_json(AS_OVERVIEW_URL, asn)
    announced = fetch_json(ANNOUNCED_PREFIXES_URL, asn)
    neighbours = fetch_json(ASN_NEIGHBOURS_URL, asn)
    first_last_seen = fetch_json(RIS_FIRST_LAST_SEEN_URL, asn)

    holder = str(overview.get("holder") or "UNKNOWN")
    announced_status = bool(overview.get("announced", False))

    prefixes = announced.get("prefixes", [])
    prefix_count = len(prefixes) if isinstance(prefixes, list) else 0

    neigh_list = neighbours.get("neighbours", [])
    neigh_list = neigh_list if isinstance(neigh_list, list) else []
    upstreams_top3 = get_upstreams(neigh_list)

    resources = first_last_seen.get("resources", [])
    first_seen_time = "UNKNOWN"
    last_seen_time = "UNKNOWN"

    if isinstance(resources, list) and resources:
        times = []
        for r in resources:
            if not isinstance(r, dict):
                continue
            first = str((r.get("first") or {}).get("time") or "")
            last = str((r.get("last") or {}).get("time") or "")
            if first:
                times.append(("first", first))
            if last:
                times.append(("last", last))

        first_candidates = [t for k, t in times if k == "first"]
        last_candidates = [t for k, t in times if k == "last"]
        if first_candidates:
            first_seen_time = min(first_candidates)
        if last_candidates:
            last_seen_time = max(last_candidates)

    registration_country = infer_registration_country(holder)
    is_high_risk = registration_country in HIGH_RISK_COUNTRIES

    newly_established = False
    first_seen_dt = parse_iso_time(first_seen_time) if first_seen_time != "UNKNOWN" else None
    if first_seen_dt is not None:
        now = datetime.now(timezone.utc)
        newly_established = first_seen_dt >= (now - timedelta(days=365))

    return {
        "input": raw,
        "resolved_from_ip": resolved_from_ip,
        "asn": asn,
        "holder": holder,
        "registration_country": registration_country,
        "announced": announced_status,
        "managed_prefix_count": prefix_count,
        "upstreams_top3": upstreams_top3,
        "first_seen": first_seen_time,
        "last_seen": last_seen_time,
        "is_high_risk": is_high_risk,
        "is_newly_established": newly_established,
    }


def colour_line(line: str, red: bool) -> str:
    colour = ANSI_RED if red else ANSI_GREEN
    return f"{colour}{line}{ANSI_RESET}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialising ASN Network Integrity Auditor")
    parser.add_argument("resource", help="ASN or IP value, for example AS15169, 15169, or 8.8.8.8")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    try:
        result = analyse_asn(args.resource)
    except requests.exceptions.RequestException as exc:
        message = "Authorised request failed, network or RIPEstat service is unreachable."
        if args.json:
            print(json.dumps({"error": message, "details": str(exc)}, separators=(",", ":")))
        else:
            print(message)
            print(f"Details: {exc}")
        return 1
    except Exception as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, separators=(",", ":")))
        else:
            print(f"Analysis failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(result, separators=(",", ":")))
        return 0

    border = "==============================================================="
    sep = "---------------------------------------------------------------"

    print(border)
    print(f"ASN NETWORK INTEGRITY AUDITOR: {ANSI_BOLD}{result['asn']}{ANSI_RESET}")
    print(border)
    if result["resolved_from_ip"]:
        print(f"Input Resource      : {result['input']} (resolved to {result['asn']})")
    else:
        print(f"Input Resource      : {result['input']}")
    print()

    print("🏢 ENTITY INFO")
    print(sep)
    print(f"Holder              : {ANSI_BOLD}{result['holder']}{ANSI_RESET}")
    print(f"Registration Country: {result['registration_country']}")
    print(f"Announced Status    : {result['announced']}")
    print()

    print("🌐 ROUTING & PEERING")
    print(sep)
    print(f"Managed Prefixes: {result['managed_prefix_count']}")
    if result["upstreams_top3"]:
        print("Top 3 Upstreams (Left Neighbours):")
        for idx, up in enumerate(result["upstreams_top3"], start=1):
            print(f"  {idx}. {up['asn']} | power={up['power']} | v4={up['v4_peers']} | v6={up['v6_peers']}")
    else:
        print("Top 3 Upstreams (Left Neighbours): none found")
    print(f"First Seen: {result['first_seen']}")
    print(f"Last Seen : {result['last_seen']}")
    print()

    print("📊 RISK AUDIT")
    print(sep)
    risk_line = f"Jurisdiction Risk: {result['registration_country']}"
    print(colour_line(risk_line, red=result["is_high_risk"]))
    if result["is_high_risk"]:
        print(f"{ANSI_RED}{ANSI_BOLD}[⚠️ HIGH-RISK JURISDICTION]{ANSI_RESET}")

    if result["is_newly_established"]:
        print(f"{ANSI_BOLD}[🆕 NEWLY ESTABLISHED]{ANSI_RESET}")
    else:
        print("[OK] Longevity check: not newly established")

    print(border)
    return 0


if __name__ == "__main__":
    sys.exit(main())
