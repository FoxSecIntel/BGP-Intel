#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import time
from typing import Any, Dict, List

import requests

RETRY_DELAY_SECONDS = 1
TIMEOUT_SECONDS = 5
USER_AGENT = "AS-Path-Finder/2.2"

PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
BGP_STATE_URL = "https://stat.ripe.net/data/bgp-state/data.json"
ASN_NEIGHBOURS_URL = "https://stat.ripe.net/data/asn-neighbours/data.json"
AS_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json"

HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP", "SY"}
COUNTRY_TAIL_RE = re.compile(r",\s*([A-Z]{2})\s*$")


def request_json(url: str, resource: str, *, verbose: bool = True) -> Dict[str, Any]:
    headers = {"User-Agent": USER_AGENT}
    params = {"resource": resource}

    response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)
    if response.status_code == 429:
        if verbose:
            print(f"[!] API rate limit hit for {resource}. Waiting {RETRY_DELAY_SECONDS} second before retrying...")
        time.sleep(RETRY_DELAY_SECONDS)
        response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)

    response.raise_for_status()
    return response.json().get("data", {})


def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}") from exc


def normalise_asn(value: Any) -> str:
    text = str(value)
    return text if text.upper().startswith("AS") else f"AS{text}"


def infer_country_from_holder(holder: str) -> str:
    m = COUNTRY_TAIL_RE.search(holder or "")
    return m.group(1) if m else "UNKNOWN"


def get_prefix_and_origin(ip: str, *, verbose: bool) -> Dict[str, str]:
    if verbose:
        print(f"Initialising prefix lookup for IP: {ip}")
    data = request_json(PREFIX_OVERVIEW_URL, ip, verbose=verbose)

    prefix = str(data.get("resource") or "Unknown")
    asns = data.get("asns", [])
    if not isinstance(asns, list) or not asns:
        return {"prefix": prefix, "origin_asn": "Unknown", "origin_holder": "Unknown"}

    first = asns[0] if isinstance(asns[0], dict) else {}
    origin_asn = normalise_asn(first.get("asn", "Unknown"))
    origin_holder = str(first.get("holder") or "Unknown")
    return {"prefix": prefix, "origin_asn": origin_asn, "origin_holder": origin_holder}


def get_live_as_path(prefix: str, *, verbose: bool) -> List[str]:
    if prefix == "Unknown":
        return []
    if verbose:
        print(f"Analysing live BGP state for prefix: {prefix}")

    data = request_json(BGP_STATE_URL, prefix, verbose=verbose)
    states = data.get("bgp_state", [])
    if not isinstance(states, list) or not states:
        return []

    first_entry = states[0] if isinstance(states[0], dict) else {}
    path = first_entry.get("path", [])
    if not isinstance(path, list):
        return []

    # RIPE usually returns path from collector-neighbour towards origin AS.
    # We keep this order to show source-to-destination flow.
    return [normalise_asn(x) for x in path]


def get_top_upstreams(origin_asn: str, *, verbose: bool) -> List[Dict[str, Any]]:
    if origin_asn == "Unknown":
        return []
    if verbose:
        print(f"Analysing upstream neighbours for: {origin_asn}")

    data = request_json(ASN_NEIGHBOURS_URL, origin_asn, verbose=verbose)
    neighbours = data.get("neighbours", [])
    if not isinstance(neighbours, list):
        return []

    left = [n for n in neighbours if isinstance(n, dict) and str(n.get("type", "")).lower() == "left"]
    left.sort(key=lambda n: int(n.get("power", 0) or 0), reverse=True)

    top3: List[Dict[str, Any]] = []
    for n in left[:3]:
        top3.append(
            {
                "asn": normalise_asn(n.get("asn", "Unknown")),
                "power": int(n.get("power", 0) or 0),
                "v4_peers": int(n.get("v4_peers", 0) or 0),
                "v6_peers": int(n.get("v6_peers", 0) or 0),
            }
        )
    return top3


def enrich_path_jurisdictions(path_asns: List[str], *, verbose: bool) -> List[Dict[str, str]]:
    seen: Dict[str, Dict[str, str]] = {}
    for asn in path_asns:
        if asn in seen:
            continue
        try:
            data = request_json(AS_OVERVIEW_URL, asn, verbose=False)
            holder = str(data.get("holder") or "Unknown")
            country = infer_country_from_holder(holder)
        except Exception:
            holder = "Unknown"
            country = "UNKNOWN"
        seen[asn] = {"asn": asn, "holder": holder, "country": country}
    return [seen[a] for a in path_asns if a in seen]


def analyse(ip: str, *, verbose: bool) -> Dict[str, Any]:
    base = get_prefix_and_origin(ip, verbose=verbose)
    time.sleep(RETRY_DELAY_SECONDS)

    path_asns = get_live_as_path(base["prefix"], verbose=verbose)
    time.sleep(RETRY_DELAY_SECONDS)

    top_upstreams = get_top_upstreams(base["origin_asn"], verbose=verbose)
    path_details = enrich_path_jurisdictions(path_asns, verbose=verbose)

    high_risk_hits = [p for p in path_details if p.get("country") in HIGH_RISK_COUNTRIES]
    visual_path = " -> ".join(path_asns) if path_asns else "Not available"

    return {
        "ip": ip,
        "prefix": base["prefix"],
        "origin_asn": base["origin_asn"],
        "origin_holder": base["origin_holder"],
        "as_path": path_asns,
        "visual_path": visual_path,
        "path_asn_details": path_details,
        "top_upstreams": top_upstreams,
        "path_contains_high_risk_jurisdiction": len(high_risk_hits) > 0,
        "high_risk_path_entries": high_risk_hits,
        "note": "Path is derived from RIPEstat bgp-state first entry and formatted source-to-destination.",
    }


def print_report(report: Dict[str, Any]) -> None:
    print("\n===============================================================")
    print(f"Routing Analysis Report: {report['ip']}")
    print("===============================================================")
    print(f"Prefix: {report['prefix']}")
    print(f"Origin ASN: {report['origin_asn']} ({report['origin_holder']})")
    print()
    print("Live AS-Path:")
    print(report["visual_path"])
    print()

    print("Top 3 Upstreams (Left Neighbours):")
    if report["top_upstreams"]:
        for idx, up in enumerate(report["top_upstreams"], start=1):
            print(f"  {idx}. {up['asn']} | power={up['power']} | v4={up['v4_peers']} | v6={up['v6_peers']}")
    else:
        print("  none found")

    print()
    if report["path_contains_high_risk_jurisdiction"]:
        print("[⚠️ PATH CONTAINS HIGH-RISK JURISDICTION]")
        for entry in report["high_risk_path_entries"]:
            print(f"  - {entry['asn']} | country={entry['country']} | holder={entry['holder']}")
    else:
        print("[OK] No high-risk jurisdiction detected in path analysis")

    print(f"\nNote: {report['note']}")
    print("===============================================================")


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialising RIPEstat routing path analysis for a target IP")
    parser.add_argument("ip", type=validate_ip, help="IP address to inspect")
    parser.add_argument("--json", action="store_true", help="Output full path and neighbour data as JSON")
    args = parser.parse_args()

    try:
        report = analyse(args.ip, verbose=not args.json)
        if args.json:
            print(json.dumps(report, separators=(",", ":")))
        else:
            print_report(report)
        return 0
    except requests.exceptions.RequestException as exc:
        print(f"Network error: {exc}")
        return 1
    except Exception as exc:
        print(f"Unexpected analysis error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
