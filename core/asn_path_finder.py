#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import time
from typing import Any, Dict, List

import requests

RETRY_DELAY_SECONDS = 1
TIMEOUT_SECONDS = 5
USER_AGENT = "AS-Path-Finder/2.0"

PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
ASN_NEIGHBOURS_URL = "https://stat.ripe.net/data/asn-neighbours/data.json"


def request_json(url: str, resource: str) -> Dict[str, Any]:
    headers = {"User-Agent": USER_AGENT}
    params = {"resource": resource}

    response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)
    if response.status_code == 429:
        print(
            f"[!] API rate limit hit for {resource}. Waiting {RETRY_DELAY_SECONDS} second before retrying..."
        )
        time.sleep(RETRY_DELAY_SECONDS)
        response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)

    response.raise_for_status()
    return response.json()


def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}") from exc


def get_origin_from_ip(ip: str, *, verbose: bool = True) -> Dict[str, str]:
    if verbose:
        print(f"Querying RIPEstat Prefix Overview for IP: {ip}")
    body = request_json(PREFIX_OVERVIEW_URL, ip)
    data = body.get("data", {})

    prefix = str(data.get("resource") or "Unknown")
    asns = data.get("asns", [])
    if not isinstance(asns, list) or not asns:
        return {"prefix": prefix, "asn": "Unknown", "holder": "Unknown"}

    first = asns[0] if isinstance(asns[0], dict) else {}
    asn = str(first.get("asn") or "Unknown")
    holder = str(first.get("holder") or "Unknown")
    return {"prefix": prefix, "asn": asn, "holder": holder}


def get_direct_upstreams(asn: str, *, verbose: bool = True) -> List[Dict[str, Any]]:
    if asn == "Unknown":
        return []

    resource = f"AS{asn}" if not str(asn).upper().startswith("AS") else str(asn).upper()
    if verbose:
        print(f"Querying RIPEstat ASN Neighbours for: {resource}")
    body = request_json(ASN_NEIGHBOURS_URL, resource)
    neighbours = body.get("data", {}).get("neighbours", [])

    if not isinstance(neighbours, list):
        return []

    left = [n for n in neighbours if isinstance(n, dict) and str(n.get("type", "")).lower() == "left"]
    left.sort(key=lambda n: int(n.get("power", 0) or 0), reverse=True)

    out: List[Dict[str, Any]] = []
    for n in left[:5]:
        out.append(
            {
                "asn": f"AS{n.get('asn')}",
                "power": int(n.get("power", 0) or 0),
                "v4_peers": int(n.get("v4_peers", 0) or 0),
                "v6_peers": int(n.get("v6_peers", 0) or 0),
            }
        )
    return out


def analyse_ip_path(ip: str, *, verbose: bool = True) -> Dict[str, Any]:
    origin = get_origin_from_ip(ip, verbose=verbose)
    time.sleep(RETRY_DELAY_SECONDS)
    upstreams = get_direct_upstreams(origin["asn"], verbose=verbose)

    return {
        "ip": ip,
        "most_specific_prefix": origin["prefix"],
        "origin_asn": f"AS{origin['asn']}" if origin["asn"] != "Unknown" else "Unknown",
        "origin_holder": origin["holder"],
        "direct_upstreams": upstreams,
        "note": "Shows direct upstream neighbours from RIPEstat, not a full internet AS path.",
    }


def print_report(report: Dict[str, Any]) -> None:
    ip = report["ip"]
    print(f"\n--- BGP Information for {ip} ---")
    print(f"IP Address: {ip}")
    print(f"Most Specific Prefix: {report['most_specific_prefix']}")
    print(f"Origin ASN: {report['origin_asn']} ({report['origin_holder']})")

    upstreams = report.get("direct_upstreams", [])
    if upstreams:
        print("Origin AS and Direct Upstream ASNs:")
        for idx, upstream in enumerate(upstreams, start=1):
            print(
                f"  {idx}. {upstream['asn']} | power={upstream['power']} | "
                f"v4={upstream['v4_peers']} | v6={upstream['v6_peers']}"
            )
    else:
        print("Origin AS and Direct Upstream ASNs: none found")

    print(f"Note: {report['note']}")
    print("-" * (len(ip) + 29))


def main() -> int:
    parser = argparse.ArgumentParser(description="Find origin ASN and direct upstream ASN relationships for an IP")
    parser.add_argument("ip", type=validate_ip, help="IP address to inspect")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    try:
        report = analyse_ip_path(args.ip, verbose=not args.json)
        if args.json:
            print(json.dumps(report, separators=(",", ":")))
        else:
            print_report(report)
        return 0

    except requests.exceptions.RequestException as exc:
        print(f"Network error: {exc}")
        return 1
    except ValueError:
        print("JSON parsing error: Invalid API response format.")
        return 1
    except IndexError:
        print(
            f"Error: Could not determine most specific prefix or parse data for {args.ip}. "
            "API response structure might have changed or data is missing."
        )
        return 1
    except Exception as exc:
        print(f"An unexpected error occurred: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
