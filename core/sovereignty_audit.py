#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

TIMEOUT_SECONDS = 5
USER_AGENT = "Euro-Sovereignty-Audit/1.0"

PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
BGP_STATE_URL = "https://stat.ripe.net/data/bgp-state/data.json"
ASN_NEIGHBOURS_URL = "https://stat.ripe.net/data/asn-neighbours/data.json"
AS_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json"
ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
RPKI_VALIDATION_URL = "https://stat.ripe.net/data/rpki-validation/data.json"

EU_EEA_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT",
    "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO",
}

HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP", "SY"}
FOREIGN_INTEL_KEYWORDS = ["ARVANCLOUD", "AMAZON", "GOOGLE", "TCI", "BEZEQ"]
COUNTRY_TAIL_RE = re.compile(r",\s*([A-Z]{2})\s*$")

BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BOLD = "\033[1m"
RESET = "\033[0m"


def get_json(url: str, params: Dict[str, str]) -> Dict[str, Any]:
    resp = requests.get(url, params=params, timeout=TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    return resp.json().get("data", {})


def normalise_asn(value: Any) -> str:
    text = str(value).strip().upper()
    return text if text.startswith("AS") else f"AS{text}"


def infer_country_from_holder(holder: str) -> str:
    m = COUNTRY_TAIL_RE.search(holder or "")
    return m.group(1) if m else "UNKNOWN"


def resolve_final_url_and_ip(url_or_host: str) -> tuple[str, str]:
    value = url_or_host.strip()
    if not value:
        raise ValueError("Empty URL input")

    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    r = requests.get(value, timeout=TIMEOUT_SECONDS, allow_redirects=True, headers={"User-Agent": USER_AGENT})
    final_url = r.url
    parsed = urlparse(final_url)
    host = parsed.hostname
    if not host:
        raise RuntimeError("Could not resolve hostname from URL")

    infos = socket.getaddrinfo(host, None)
    for info in infos:
        ip = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                return final_url, ip
        except ValueError:
            continue
    raise RuntimeError("Could not resolve IPv4 address from final URL")


def find_prefix_and_origin_from_ip(ip: str) -> tuple[str, str, str]:
    data = get_json(PREFIX_OVERVIEW_URL, {"resource": ip})
    prefix = str(data.get("resource") or "Unknown")
    asns = data.get("asns", [])
    if not isinstance(asns, list) or not asns:
        return prefix, "Unknown", "Unknown"
    first = asns[0] if isinstance(asns[0], dict) else {}
    origin_asn = normalise_asn(first.get("asn", "Unknown"))
    origin_holder = str(first.get("holder") or "Unknown")
    return prefix, origin_asn, origin_holder


def find_prefix_from_asn(asn: str) -> str:
    data = get_json(ANNOUNCED_PREFIXES_URL, {"resource": asn})
    prefixes = data.get("prefixes", [])
    if not isinstance(prefixes, list) or not prefixes:
        return "Unknown"
    first = prefixes[0] if isinstance(prefixes[0], dict) else {}
    return str(first.get("prefix") or "Unknown")


def get_path_from_prefix(prefix: str) -> List[str]:
    data = get_json(BGP_STATE_URL, {"resource": prefix})
    states = data.get("bgp_state", [])
    if not isinstance(states, list) or not states:
        return []
    first = states[0] if isinstance(states[0], dict) else {}
    path = first.get("path", [])
    if not isinstance(path, list):
        return []
    return [normalise_asn(a) for a in path]


def get_top_upstreams(origin_asn: str) -> List[Dict[str, Any]]:
    if origin_asn == "Unknown":
        return []
    data = get_json(ASN_NEIGHBOURS_URL, {"resource": origin_asn})
    neighbours = data.get("neighbours", [])
    if not isinstance(neighbours, list):
        return []
    left = [n for n in neighbours if isinstance(n, dict) and str(n.get("type", "")).lower() == "left"]
    left.sort(key=lambda n: int(n.get("power", 0) or 0), reverse=True)
    out = []
    for n in left[:3]:
        out.append(
            {
                "asn": normalise_asn(n.get("asn", "Unknown")),
                "power": int(n.get("power", 0) or 0),
                "v4_peers": int(n.get("v4_peers", 0) or 0),
                "v6_peers": int(n.get("v6_peers", 0) or 0),
            }
        )
    return out


def get_asn_entity(asn: str) -> Dict[str, str]:
    data = get_json(AS_OVERVIEW_URL, {"resource": asn})
    holder = str(data.get("holder") or "Unknown")
    country = infer_country_from_holder(holder)
    return {"asn": asn, "holder": holder, "country": country}


def rpki_state(prefix: str, origin_asn: str) -> str:
    if prefix == "Unknown" or origin_asn == "Unknown":
        return "unknown"
    data = get_json(RPKI_VALIDATION_URL, {"prefix": prefix, "resource": origin_asn})
    status = data.get("status")
    if isinstance(status, str) and status:
        return status.lower()
    validity = data.get("validity")
    if isinstance(validity, dict):
        state = validity.get("state")
        if isinstance(state, str) and state:
            return state.lower()
    return "unknown"


def collect_entities(path_asns: List[str]) -> List[Dict[str, str]]:
    out = []
    cache: Dict[str, Dict[str, str]] = {}
    for asn in path_asns:
        if asn not in cache:
            try:
                cache[asn] = get_asn_entity(asn)
            except Exception:
                cache[asn] = {"asn": asn, "holder": "Unknown", "country": "UNKNOWN"}
        out.append(cache[asn])
    return out


def audit(resource: str, *, from_url: bool = False) -> Dict[str, Any]:
    final_url = ""
    target_ip = ""
    target_asn = ""
    origin_holder = "Unknown"

    if from_url:
        final_url, target_ip = resolve_final_url_and_ip(resource)
        prefix, target_asn, origin_holder = find_prefix_and_origin_from_ip(target_ip)
    else:
        try:
            ipaddress.ip_address(resource)
            target_ip = resource
            prefix, target_asn, origin_holder = find_prefix_and_origin_from_ip(target_ip)
        except ValueError:
            target_asn = normalise_asn(resource)
            prefix = find_prefix_from_asn(target_asn)

    if target_asn == "" or target_asn == "Unknown":
        if prefix != "Unknown":
            _, target_asn, origin_holder = find_prefix_and_origin_from_ip(prefix.split("/")[0])
        else:
            target_asn = "Unknown"

    path = get_path_from_prefix(prefix) if prefix != "Unknown" else []
    entities = collect_entities(path)
    upstreams = get_top_upstreams(target_asn)
    rpki = rpki_state(prefix, target_asn)

    extra_eu = [e for e in entities if e.get("country") not in EU_EEA_COUNTRIES and e.get("country") != "UNKNOWN"]
    high_risk = [e for e in entities if e.get("country") in HIGH_RISK_COUNTRIES]

    intel_dependency_hits = []
    for e in entities:
        holder_upper = e.get("holder", "").upper()
        for kw in FOREIGN_INTEL_KEYWORDS:
            if kw in holder_upper:
                intel_dependency_hits.append({"asn": e["asn"], "holder": e["holder"], "keyword": kw})
                break

    sovereignty_score = "Sovereign (EU-Only)" if not extra_eu else "Fragmented (Extra-EU Path)"

    return {
        "input": resource,
        "final_url": final_url,
        "target_ip": target_ip,
        "target_asn": target_asn,
        "origin_holder": origin_holder,
        "prefix": prefix,
        "as_path": path,
        "visual_path": " -> ".join(path) if path else "Not available",
        "path_entities": entities,
        "upstreams_top3": upstreams,
        "rpki_state": rpki,
        "foreign_hijack_risk": rpki == "invalid",
        "extra_eu_detour": len(extra_eu) > 0,
        "extra_eu_entries": extra_eu,
        "path_contains_high_risk_jurisdiction": len(high_risk) > 0,
        "high_risk_entries": high_risk,
        "foreign_intel_dependency_hits": intel_dependency_hits,
        "sovereignty_score": sovereignty_score,
    }


def print_report(r: Dict[str, Any]) -> None:
    is_sovereign = r["sovereignty_score"].startswith("Sovereign")
    verdict_colour = BLUE if is_sovereign else RED
    path_colour = GREEN if is_sovereign else YELLOW

    print("================================================================")
    print(f"Initialising Euro Sovereignty Audit: {r['input']}")
    print("================================================================")
    if r["final_url"]:
        print(f"Resolved URL: {r['final_url']}")
    if r["target_ip"]:
        print(f"Target IP: {r['target_ip']}")
    print(f"Prefix: {r['prefix']}")
    print(f"Origin ASN: {r['target_asn']} ({r['origin_holder']})")
    print()

    print("Analysing route path:")
    print(f"{path_colour}{r['visual_path']}{RESET}")
    print()

    print("Top 3 Upstreams (Left neighbours):")
    if r["upstreams_top3"]:
        for i, up in enumerate(r["upstreams_top3"], start=1):
            print(f"  {i}. {up['asn']} | power={up['power']} | v4={up['v4_peers']} | v6={up['v6_peers']}")
    else:
        print("  none found")
    print()

    print("Routing Integrity (RPKI):")
    if r["foreign_hijack_risk"]:
        print(f"{BOLD}{RED}State: {r['rpki_state']} | Potential Foreign Hijack Risk{RESET}")
    else:
        print(f"State: {r['rpki_state']}")
    print()

    if r["extra_eu_detour"]:
        print(f"{BOLD}{YELLOW}[🚩 EXTRA-EU DATA DETOUR]{RESET}")
        for entry in r["extra_eu_entries"]:
            print(f"  - {entry['asn']} | {entry['country']} | {entry['holder']}")
    else:
        print(f"{GREEN}[OK] Path remains within known EU/EEA jurisdictions{RESET}")

    if r["path_contains_high_risk_jurisdiction"]:
        print(f"{BOLD}{RED}[⚠️ PATH CONTAINS HIGH-RISK JURISDICTION]{RESET}")
        for entry in r["high_risk_entries"]:
            print(f"  - {entry['asn']} | {entry['country']} | {entry['holder']}")

    if r["foreign_intel_dependency_hits"]:
        print(f"{BOLD}{YELLOW}Non-European Infrastructure Dependency Indicators:{RESET}")
        for hit in r["foreign_intel_dependency_hits"]:
            print(f"  - {hit['asn']} | {hit['keyword']} | {hit['holder']}")

    print()
    print(f"Authorised Sovereignty Verdict: {verdict_colour}{BOLD}{r['sovereignty_score']}{RESET}")
    print("================================================================")


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialising sovereignty audit for IP, ASN, or piped URL")
    parser.add_argument("resource", nargs="?", help="Target IP, ASN, or URL")
    parser.add_argument("--json", action="store_true", help="Output full audit JSON")
    parser.add_argument("--url", action="store_true", help="Treat input as URL and resolve final destination")
    args = parser.parse_args()

    resource = args.resource
    from_url = args.url

    if resource is None and not sys.stdin.isatty():
        piped = sys.stdin.read().strip().splitlines()
        if piped:
            resource = piped[-1].strip()
            if resource.startswith(("http://", "https://")):
                from_url = True

    if not resource:
        parser.error("Provide IP, ASN, URL, or pipe URL input from un-shorten.sh")

    try:
        result = audit(resource, from_url=from_url)
        if args.json:
            print(json.dumps(result, separators=(",", ":")))
        else:
            print_report(result)
        return 0
    except requests.exceptions.RequestException as exc:
        print(f"Network error: {exc}")
        return 1
    except Exception as exc:
        print(f"Audit error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
