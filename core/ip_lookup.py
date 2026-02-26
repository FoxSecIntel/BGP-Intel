#!/usr/bin/env python3
from __future__ import annotations

import argparse
from core.lookup import lookup_ip_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Lookup IP metadata")
    parser.add_argument("ip", help="IP address to lookup")
    args = parser.parse_args()

    try:
        print(lookup_ip_json(args.ip))
        return 0
    except Exception as exc:
        print(f"Lookup failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
