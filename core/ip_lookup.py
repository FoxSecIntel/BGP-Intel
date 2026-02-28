#!/usr/bin/env python3
"""
Enriched IP Triage Script for BGP-Intel.

This SOC intelligence auditor uses RIPEstat Data API endpoints for ASN, holder,
country, and abuse-contact intelligence. It applies automated risk profiling,
including high-risk jurisdiction checks, cloud or data-centre indicators,
and anonymiser detection signals.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

import requests

USER_AGENT = "IP-Intel-Audit/1.1"
TIMEOUT_SECONDS = 5
PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
RIR_STATS_COUNTRY_URL = "https://stat.ripe.net/data/rir-stats-country/data.json"
ABUSE_CONTACT_URL = "https://stat.ripe.net/data/abuse-contact-finder/data.json"

HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP", "SY"}
CLOUD_INDICATORS = ("AWS", "AMAZON", "GOOGLE", "AZURE", "HETZNER", "DIGITALOCEAN", "OVH")
ANONYMISER_INDICATORS = ("VPN", "PROXY", "TOR", "MULLVAD")

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"


def fetch_json(url: str, ip: str) -> Dict[str, Any]:
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, params={"resource": ip}, headers=headers, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def contains_indicator(text: str, indicators: tuple[str, ...]) -> bool:
    upper = text.upper()
    return any(indicator in upper for indicator in indicators)


def bold(text: str) -> str:
    return f"{ANSI_BOLD}{text}{ANSI_RESET}"


def colour(text: str, *, red: bool) -> str:
    c = ANSI_RED if red else ANSI_GREEN
    return f"{c}{text}{ANSI_RESET}"


def analyse_ip(ip: str) -> Dict[str, Any]:
    # Initialising collection, Analysing RIPEstat intelligence sources.
    prefix_payload = fetch_json(PREFIX_OVERVIEW_URL, ip)
    country_payload = fetch_json(RIR_STATS_COUNTRY_URL, ip)
    abuse_payload = fetch_json(ABUSE_CONTACT_URL, ip)

    prefix_data = prefix_payload.get("data", {})
    asns = prefix_data.get("asns", [])

    asn_value = "UNKNOWN"
    holder = "UNKNOWN"
    if isinstance(asns, list) and asns:
        first = asns[0] if isinstance(asns[0], dict) else {}
        asn_raw = first.get("asn")
        holder = str(first.get("holder") or "UNKNOWN")
        if asn_raw is not None:
            asn_value = str(asn_raw)

    country = "UNKNOWN"
    country_data = country_payload.get("data", {})
    located = country_data.get("located_resources", [])
    if isinstance(located, list) and located:
        first_loc = located[0] if isinstance(located[0], dict) else {}
        code = first_loc.get("location")
        if isinstance(code, str) and code:
            country = code.upper()

    abuse_email = "UNKNOWN"
    abuse_data = abuse_payload.get("data", {})
    abuse_contacts = abuse_data.get("abuse_contacts", [])
    if isinstance(abuse_contacts, list) and abuse_contacts:
        first_contact = abuse_contacts[0]
        if isinstance(first_contact, str) and first_contact.strip():
            abuse_email = first_contact.strip()

    usage_type = str(prefix_data.get("type") or "unknown")
    detection_text = f"{holder} {usage_type}"

    is_high_risk = country in HIGH_RISK_COUNTRIES
    is_cloud = contains_indicator(holder, CLOUD_INDICATORS)
    is_anonymised = contains_indicator(detection_text, ANONYMISER_INDICATORS)

    return {
        "ip": ip,
        "asn": asn_value,
        "holder": holder,
        "country": country,
        "is_high_risk": is_high_risk,
        "is_cloud": is_cloud,
        "is_anonymised": is_anonymised,
        "abuse_email": abuse_email,
    }


def print_block(title: str, lines: list[str]) -> None:
    print("+----------------------------------------------------------------+")
    print(f"| {title}")
    print("+----------------------------------------------------------------+")
    for line in lines:
        print(line)


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialising SOC IP intelligence auditor")
    parser.add_argument("ip", help="IP address to analyse")
    parser.add_argument("--json", action="store_true", help="Output a single JSON object")
    args = parser.parse_args()

    try:
        result = analyse_ip(args.ip)
    except requests.exceptions.RequestException as exc:
        message = "Authorised request failed, network or RIPEstat service is unreachable."
        if args.json:
            print(json.dumps({"error": message, "details": str(exc)}, separators=(",", ":")))
        else:
            print(message)
            print(f"Details: {exc}")
        return 1
    except Exception as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, separators=(",", ":")))
        else:
            print(f"Analysis failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(result, separators=(",", ":")))
        return 0

    print("==================================================================")
    print(f"🔍 SOC IP Intelligence Auditor: {bold(result['ip'])}")
    print("==================================================================")

    jurisdiction_line = f"Jurisdiction: {result['country']}"
    jurisdiction_coloured = colour(jurisdiction_line, red=result["is_high_risk"])

    risk_flags = []
    if result["is_high_risk"]:
        risk_flags.append("[⚠️ HIGH-RISK JURISDICTION]")
    if result["is_cloud"]:
        risk_flags.append("[☁️ CLOUD/DATA CENTRE]")
    if result["is_anonymised"]:
        risk_flags.append("[🕵️ ANONYMISER DETECTED]")
    if not risk_flags:
        risk_flags.append("[OK: NO HIGH-RISK FLAG TRIGGERED]")

    print_block(
        "📊 Risk Profile",
        [
            "Analysing complete, risk classification follows:",
            jurisdiction_coloured,
            f"High-Risk: {result['is_high_risk']}",
            f"Cloud Footprint: {result['is_cloud']}",
            f"Anonymised: {result['is_anonymised']}",
            *risk_flags,
        ],
    )

    print_block(
        "🏢 Network Identity",
        [
            f"IP: {bold(result['ip'])}",
            f"Holder: {bold(result['holder'])}",
            f"ASN: {result['asn']}",
        ],
    )

    print_block(
        "📩 Incident Response",
        [
            f"Abuse Contact: {result['abuse_email']}",
            "Action: Use this mailbox for Authorised abuse escalation when required.",
        ],
    )

    print("+----------------------------------------------------------------+")
    return 0


if __name__ == "__main__":
    sys.exit(main())
