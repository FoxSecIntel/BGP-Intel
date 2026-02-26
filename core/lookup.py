#!/usr/bin/env python3
"""Core lookup helpers for BGP-Intel."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

import requests


IPAPI_URL = "https://ipapi.co/{ip}/json/"


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def lookup_ip(ip: str, timeout: int = 10) -> dict[str, Any]:
    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    resp = requests.get(IPAPI_URL.format(ip=ip), timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def lookup_ip_json(ip: str, timeout: int = 10) -> str:
    return json.dumps(lookup_ip(ip, timeout=timeout), indent=2)
