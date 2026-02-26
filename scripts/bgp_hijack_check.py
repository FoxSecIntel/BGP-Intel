#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Set

import requests


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


def fetch_current_origins(prefix: str, timeout: int = 12) -> Set[str]:
    url = f"https://api.bgpview.io/prefix/{prefix}"
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    body = r.json()
    data = body.get("data", {})

    origins: Set[str] = set()

    # Common shape: data.asns = [{asn: 15169, ...}, ...]
    asns = data.get("asns", [])
    if isinstance(asns, list):
        for a in asns:
            if isinstance(a, dict) and a.get("asn") is not None:
                origins.add(normalise_asn(str(a.get("asn"))))

    # Fallback shape: top-level asn
    if not origins and data.get("asn") is not None:
        origins.add(normalise_asn(str(data.get("asn"))))

    return origins


def evaluate(prefix: str, expected_asn: str, observed: Set[str]) -> dict:
    if not observed:
        return {
            "prefix": prefix,
            "expected_asn": expected_asn,
            "observed_asns": [],
            "status": "unknown",
            "reason": "no_origin_data",
        }

    if expected_asn in observed:
        return {
            "prefix": prefix,
            "expected_asn": expected_asn,
            "observed_asns": sorted(observed),
            "status": "ok",
            "reason": "expected_origin_present",
        }

    return {
        "prefix": prefix,
        "expected_asn": expected_asn,
        "observed_asns": sorted(observed),
        "status": "alert",
        "reason": "origin_mismatch_possible_hijack_or_leak",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check prefix origin ASN mismatches (possible hijack/leak signal)")
    parser.add_argument("--prefix", help="Single prefix, e.g. 8.8.8.0/24")
    parser.add_argument("--expected-asn", help="Expected origin ASN for --prefix, e.g. AS15169")
    parser.add_argument("--baseline", help="CSV baseline file: prefix,asn")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    targets: List[tuple[str, str]] = []

    if args.baseline:
        b = parse_expected_file(Path(args.baseline))
        targets.extend((p, a) for p, a in b.items())

    if args.prefix and args.expected_asn:
        # validate prefix
        ipaddress.ip_network(args.prefix, strict=False)
        targets.append((args.prefix, normalise_asn(args.expected_asn)))

    if not targets:
        parser.error("Provide --prefix + --expected-asn, or --baseline")

    results = []
    exit_code = 0

    for prefix, expected in targets:
        try:
            observed = fetch_current_origins(prefix)
            row = evaluate(prefix, expected, observed)
        except Exception as exc:
            row = {
                "prefix": prefix,
                "expected_asn": expected,
                "observed_asns": [],
                "status": "error",
                "reason": str(exc),
            }

        if row["status"] in {"alert", "error"}:
            exit_code = 2
        results.append(row)

    if args.json:
        print(json.dumps(results, indent=2))
        return exit_code

    print("PREFIX\tEXPECTED\tOBSERVED\tSTATUS\tREASON")
    for r in results:
        print(
            f"{r['prefix']}\t{r['expected_asn']}\t{','.join(r['observed_asns']) or '-'}\t{r['status']}\t{r['reason']}"
        )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
