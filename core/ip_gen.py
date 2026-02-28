#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import random
import sys

MALICIOUS_TEST_PREFIXES = [
    "5.8.0.0/16",      # RU sample range
    "36.0.0.0/8",      # CN sample range
    "5.160.0.0/11",    # IR sample range
    "175.45.176.0/22", # KP sample range
]


def parse_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Count must be an integer.") from exc
    if count <= 0:
        raise argparse.ArgumentTypeError("Count must be greater than zero.")
    return count


def random_global_unicast_ip() -> str:
    while True:
        candidate = ipaddress.IPv4Address(random.getrandbits(32))
        if candidate.is_global:
            return str(candidate)


def random_ip_from_prefix(prefix: str) -> str:
    net = ipaddress.ip_network(prefix, strict=False)

    if net.prefixlen >= 31:
        return str(net.network_address)

    first_host = int(net.network_address) + 1
    last_host = int(net.broadcast_address) - 1
    pick = random.randint(first_host, last_host)
    return str(ipaddress.IPv4Address(pick))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialising IP generator for SOC testing and Analysing pipeline inputs"
    )
    parser.add_argument(
        "--count",
        required=True,
        type=parse_count,
        help="Number of IP addresses to generate",
    )
    parser.add_argument(
        "--malicious",
        action="store_true",
        help="Authorised testing mode: generate IPs from RU, CN, IR, KP sample ranges",
    )
    args = parser.parse_args()

    for _ in range(args.count):
        if args.malicious:
            prefix = random.choice(MALICIOUS_TEST_PREFIXES)
            print(random_ip_from_prefix(prefix))
        else:
            print(random_global_unicast_ip())

    return 0


if __name__ == "__main__":
    sys.exit(main())
