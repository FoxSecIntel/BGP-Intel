#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Dict, List

import requests


def normalise_asn(value: str) -> str:
    v = value.strip().upper()
    return v if v.startswith("AS") else f"AS{v}"


def parse_baseline(path: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split(",")]
        if len(parts) < 2:
            continue
        mapping[parts[0]] = normalise_asn(parts[1])
    return mapping


def query_rpki(prefix: str, asn: str, timeout: int = 12) -> dict:
    # RIPEstat endpoint expects both prefix and ASN(resource)
    url = "https://stat.ripe.net/data/rpki-validation/data.json"
    r = requests.get(url, params={"prefix": prefix, "resource": asn}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def extract_state(payload: dict) -> str:
    data = payload.get("data", {})

    # Common response shape
    state = data.get("status")
    if isinstance(state, str) and state:
        return state.lower()

    validity = data.get("validity")
    if isinstance(validity, dict):
        s = validity.get("state")
        if isinstance(s, str) and s:
            return s.lower()

    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check RPKI validation state for prefix/ASN origin pair")
    parser.add_argument("--prefix", help="Prefix to validate, e.g. 8.8.8.0/24")
    parser.add_argument("--asn", help="Origin ASN, e.g. AS15169")
    parser.add_argument("--baseline", help="CSV baseline file: prefix,asn")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    targets: List[tuple[str, str]] = []

    if args.baseline:
        b = parse_baseline(Path(args.baseline))
        targets.extend((p, a) for p, a in b.items())

    if args.prefix and args.asn:
        ipaddress.ip_network(args.prefix, strict=False)
        targets.append((args.prefix, normalise_asn(args.asn)))

    if not targets:
        parser.error("Provide --prefix + --asn, or --baseline")

    out = []
    exit_code = 0

    for prefix, asn in targets:
        try:
            payload = query_rpki(prefix, asn)
            state = extract_state(payload)
            row = {
                "prefix": prefix,
                "asn": asn,
                "rpki_state": state,
                "source": "RIPEstat",
            }
            if state in {"invalid", "error"}:
                exit_code = 2
        except Exception as exc:
            row = {
                "prefix": prefix,
                "asn": asn,
                "rpki_state": "error",
                "error": str(exc),
                "source": "RIPEstat",
            }
            exit_code = 2

        out.append(row)

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("PREFIX\tASN\tRPKI_STATE")
        for r in out:
            print(f"{r['prefix']}\t{r['asn']}\t{r['rpki_state']}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
