#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import ipaddress
import random
import sys

ENCODED_STR = "wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="

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
        description="Initialising IP generator for SOC testing and Analysing pipeline inputs",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Help section:\n"
            "  Standard mode: generates random global unicast IPv4 addresses.\n"
            "  Malicious mode: generates IPs from RU, CN, IR, KP sample ranges for Authorised testing.\n\n"
            "Examples:\n"
            "  python3 core/ip_gen.py --count 5\n"
            "  python3 core/ip_gen.py --count 5 --malicious\n"
            "  python3 core/ip_gen.py -m"
        ),
    )
    parser.add_argument(
        "-m",
        "--message",
        action="store_true",
        help="Print the hidden message and exit",
    )
    parser.add_argument(
        "--count",
        type=parse_count,
        help="Number of IP addresses to generate",
    )
    parser.add_argument(
        "--malicious",
        action="store_true",
        help="Authorised testing mode: generate IPs from RU, CN, IR, KP sample ranges",
    )
    args = parser.parse_args()

    if args.message:
        print(base64.b64decode(ENCODED_STR).decode("utf-8", errors="replace"), end="")
        return 0

    if args.count is None:
        parser.error("the following arguments are required: --count")

    for _ in range(args.count):
        if args.malicious:
            prefix = random.choice(MALICIOUS_TEST_PREFIXES)
            print(random_ip_from_prefix(prefix))
        else:
            print(random_global_unicast_ip())

    return 0


if __name__ == "__main__":
    sys.exit(main())
