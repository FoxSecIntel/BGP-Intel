#!/usr/bin/env python3
"""Batch IP report runner for BGP-Intel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.lookup import is_valid_ip, lookup_ip


def load_ips(path: Path) -> list[str]:
    lines = [l.strip() for l in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
    return [l for l in lines if l and not l.startswith("#")]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run batch IP enrichment report")
    parser.add_argument("-f", "--file", required=True, help="Input file with one IP per line")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"Input file not found: {path}", file=sys.stderr)
        return 1

    ips = load_ips(path)
    results = []

    for ip in ips:
        if not is_valid_ip(ip):
            results.append({"ip": ip, "status": "error", "error": "invalid_ip"})
            continue
        try:
            data = lookup_ip(ip)
            results.append(
                {
                    "ip": ip,
                    "status": "ok",
                    "country": data.get("country_name"),
                    "asn": data.get("asn"),
                    "org": data.get("org"),
                }
            )
        except Exception as exc:
            results.append({"ip": ip, "status": "error", "error": str(exc)})

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    print("IP\tStatus\tASN\tCountry\tOrg")
    for r in results:
        print(
            f"{r.get('ip')}\t{r.get('status')}\t{r.get('asn','-')}\t{r.get('country','-')}\t{r.get('org','-')}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
