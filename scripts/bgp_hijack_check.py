#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Set

import requests

USER_AGENT = "BGP-Intel-Audit-Tool/1.1"
RIPESTAT_ANNOUNCED_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPESTAT_RIS_PREFIXES = "https://stat.ripe.net/data/ris-prefixes/data.json"


def normalise_asn(value: str) -> str:
    v = value.strip().upper()
    return v if v.startswith("AS") else f"AS{v}"


def parse_expected_file(path: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split(",")]
        if len(parts) < 2:
            continue
        prefix, asn = parts[0], normalise_asn(parts[1])
        mapping[prefix] = asn
    return mapping


def extract_prefixes_from_payload(payload: dict) -> Set[str]:
    data = payload.get("data", {})
    prefixes = data.get("prefixes", [])
    out: Set[str] = set()

    if isinstance(prefixes, list):
        for item in prefixes:
            if isinstance(item, dict):
                p = item.get("prefix")
                if isinstance(p, str) and p:
                    out.add(p)
            elif isinstance(item, str) and item:
                out.add(item)

    return out


def fetch_prefixes_for_asn(asn: str, timeout: int = 12) -> tuple[Set[str], str]:
    headers = {"User-Agent": USER_AGENT}

    # Primary: Announced Prefixes
    try:
        r = requests.get(
            RIPESTAT_ANNOUNCED_PREFIXES,
            params={"resource": asn},
            headers=headers,
            timeout=timeout,
        )
        r.raise_for_status()
        prefixes = extract_prefixes_from_payload(r.json())
        if prefixes:
            return prefixes, "announced-prefixes"
    except requests.exceptions.RequestException as exc:
        # Continue to fallback endpoint
        primary_error = str(exc)
    except Exception as exc:
        primary_error = str(exc)

    # Fallback: RIS Prefixes
    try:
        r = requests.get(
            RIPESTAT_RIS_PREFIXES,
            params={"resource": asn, "list_prefixes": "true"},
            headers=headers,
            timeout=timeout,
        )
        r.raise_for_status()
        prefixes = extract_prefixes_from_payload(r.json())
        if prefixes:
            return prefixes, "ris-prefixes"
        raise RuntimeError("RIS Prefixes endpoint returned no prefixes")
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(
            f"Network unreachable while contacting RIPEstat endpoints: {exc}. "
            f"Primary endpoint error: {primary_error if 'primary_error' in locals() else 'none'}"
        )


def evaluate(prefix: str, expected_asn: str, observed_prefixes: Set[str], source: str) -> dict:
    if prefix in observed_prefixes:
        return {
            "prefix": prefix,
            "expected_asn": expected_asn,
            "status": "ok",
            "reason": "expected_asn_announces_prefix",
            "source": source,
        }

    return {
        "prefix": prefix,
        "expected_asn": expected_asn,
        "status": "alert",
        "reason": "expected_asn_does_not_announce_prefix_possible_hijack_or_reassignment",
        "source": source,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialising BGP origin consistency check using RIPEstat")
    parser.add_argument("--prefix", help="Single prefix, for example 8.8.8.0/24")
    parser.add_argument("--expected-asn", help="Expected origin ASN for --prefix, for example AS15169")
    parser.add_argument("--baseline", help="CSV baseline file: prefix,asn")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    targets: List[tuple[str, str]] = []

    if args.baseline:
        b = parse_expected_file(Path(args.baseline))
        targets.extend((p, a) for p, a in b.items())

    if args.prefix and args.expected_asn:
        # Validate prefix format
        ipaddress.ip_network(args.prefix, strict=False)
        targets.append((args.prefix, normalise_asn(args.expected_asn)))

    if not targets:
        parser.error("Provide --prefix + --expected-asn, or --baseline")

    print("Initialising checks, Analysing prefix to ASN consistency...")

    results = []
    exit_code = 0

    # Cache API lookups by ASN for efficiency
    asn_prefix_cache: Dict[str, tuple[Set[str], str]] = {}

    for prefix, expected in targets:
        try:
            if expected not in asn_prefix_cache:
                asn_prefix_cache[expected] = fetch_prefixes_for_asn(expected)
            observed_prefixes, source = asn_prefix_cache[expected]
            row = evaluate(prefix, expected, observed_prefixes, source)
        except Exception as exc:
            row = {
                "prefix": prefix,
                "expected_asn": expected,
                "status": "error",
                "reason": f"Authorised check failed: {exc}",
                "source": "ripe-fallback",
            }

        if row["status"] in {"alert", "error"}:
            exit_code = 2
        results.append(row)

    if args.json:
        print(json.dumps(results, indent=2))
        return exit_code

    print("PREFIX\tEXPECTED\tSTATUS\tSOURCE\tREASON")
    for r in results:
        print(f"{r['prefix']}\t{r['expected_asn']}\t{r['status']}\t{r['source']}\t{r['reason']}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
