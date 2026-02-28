![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

# BGP-Intel

**BGP-Intel** is a lightweight IP and ASN intelligence toolkit for Tier 1 SOC analysts.

It is designed for fast triage, routing integrity checks, and repeatable analyst workflows.

## Features

- Enriched IP triage with risk profiling
- BGP origin mismatch checks for hijack or leak signals
- RPKI validation checks for prefix and origin pairs
- Batch report runner for IP lists
- Lightweight utilities for analyst workflows

## Repository structure

- `core/` core Python logic
- `core/archive/` archived shell utilities
- `scripts/` routing checks and automation entrypoints
- `tests/` unit tests
- `config/` example configuration files
- `docs/` future documentation

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Enriched IP Triage Script

Primary script: `core/ip_lookup.py`

This script is intended to give SOC analysts an immediate risk profile for any suspicious IP.
It combines multiple RIPEstat data sources and applies practical detection heuristics in one pass.

Data sources:

- RIPEstat Prefix Overview: ASN and holder intelligence
- RIPEstat RIR Stats Country: country attribution
- RIPEstat Abuse Contact Finder: abuse contact intelligence

Intelligence flags:

- High-risk jurisdiction: `RU`, `CN`, `IR`, `KP`, `SY`
- Cloud or data-centre footprint: `AWS`, `Amazon`, `Google`, `Azure`, `Hetzner`, `DigitalOcean`, `OVH`
- Anonymiser indicators: `VPN`, `Proxy`, `Tor`, `Mullvad`

Example usage:

```bash
python3 core/ip_lookup.py 8.8.8.8
python3 core/ip_lookup.py 8.8.8.8 --json
```

Example text output:

```text
===============================================================
🔍 IP INTEL REPORT: 193.38.113.3
===============================================================

📊 RISK PROFILE
---------------------------------------------------------------
[✅] JURISDICTION: GB (United Kingdom) - Low Risk
[🏠] TYPE        : Residential / Consumer ISP
[🛡️] PRIVACY     : No Proxy/VPN detected

🏢 NETWORK IDENTITY
---------------------------------------------------------------
HOLDER: NTL - Virgin Media Limited
ASN   : 5089
RIR   : RIPE NCC

📩 INCIDENT RESPONSE
---------------------------------------------------------------
ABUSE : abuse@virginmediao2.co.uk

===============================================================
```

Example JSON output:

```json
{"ip":"8.8.8.8","asn":"15169","holder":"GOOGLE - Google LLC","country":"US","country_name":"United States","rir":"ARIN","is_high_risk":false,"is_cloud":true,"is_anonymised":false,"abuse_email":"network-abuse@google.com"}
```

## ASN Integrity Audit Script

Primary script: `core/asn_integrity_audit.py`

This script performs ASN-centric network integrity analysis using RIPEstat, with structured checks for entity context, upstream relationships, routing scope, and risk posture.

Key capabilities:

- Resolves ASN input directly, and accepts IP input with automatic ASN resolution.
- Validates announcement status and holder context.
- Counts announced prefixes to estimate network scope.
- Extracts top upstream transit neighbours from Left-side peer data.
- Flags high-risk jurisdictions and newly established ASNs.

Example usage:

```bash
python3 core/asn_integrity_audit.py AS15169
python3 core/asn_integrity_audit.py 8.8.8.8
python3 core/asn_integrity_audit.py AS15169 --json
```

Example text output:

```text
===============================================================
ASN NETWORK INTEGRITY AUDITOR: AS15169
===============================================================
Input Resource      : 8.8.8.8 (resolved to AS15169)

🏢 ENTITY INFO
---------------------------------------------------------------
Holder              : GOOGLE - Google LLC
Registration Country: UNKNOWN
Announced Status    : True

🌐 ROUTING & PEERING
---------------------------------------------------------------
Managed Prefixes: 1277
Top 3 Upstreams (Left Neighbours):
  1. AS6453 | power=469 | v4=39513 | v6=1808
  2. AS1299 | power=430 | v4=42492 | v6=6977
  3. AS6939 | power=379 | v4=8988 | v6=14457
First Seen: 2000-08-18T08:00:00
Last Seen : 2024-09-23T16:00:00

📊 RISK AUDIT
---------------------------------------------------------------
Jurisdiction Risk: UNKNOWN
[OK] Longevity check: not newly established
===============================================================
```

Example JSON output:

```json
{"input":"AS15169","resolved_from_ip":false,"asn":"AS15169","holder":"GOOGLE - Google LLC","registration_country":"UNKNOWN","announced":true,"managed_prefix_count":1277,"upstreams_top3":[{"asn":"AS6453","power":469,"v4_peers":39513,"v6_peers":1808},{"asn":"AS1299","power":430,"v4_peers":42492,"v6_peers":6977},{"asn":"AS6939","power":379,"v4_peers":8988,"v6_peers":14457}],"first_seen":"2000-08-18T08:00:00","last_seen":"2024-09-23T16:00:00","is_high_risk":false,"is_newly_established":false}
```

## AS Path Finder Script

Primary script: `core/asn_path_finder.py`

This script performs high-fidelity routing path analysis using RIPEstat live BGP state and neighbour intelligence.
It is intended for network security specialists who need immediate path visibility and upstream context.

Key capabilities:

- Resolves most specific prefix and origin ASN from target IP.
- Extracts live AS path from RIPEstat bgp-state data.
- Formats a clear source-to-destination visual path using `->` arrows.
- Identifies top 3 upstream providers from Left-side ASN neighbours by power.
- Flags paths containing high-risk jurisdiction indicators.

Example usage:

```bash
python3 core/asn_path_finder.py 8.8.8.8
python3 core/asn_path_finder.py 8.8.8.8 --json
```

Example text output:

```text
===============================================================
Routing Analysis Report: 8.8.8.8
===============================================================
Prefix: 8.8.8.0/24
Origin ASN: AS15169 (GOOGLE - Google LLC)

Live AS-Path:
AS328840 -> AS327727 -> AS15169

Top 3 Upstreams (Left Neighbours):
  1. AS6453 | power=469 | v4=39513 | v6=1808
  2. AS1299 | power=430 | v4=42492 | v6=6977
  3. AS6939 | power=379 | v4=8988 | v6=14457

[OK] No high-risk jurisdiction detected in path analysis

Note: Path is derived from RIPEstat bgp-state first entry and formatted source-to-destination.
===============================================================
```

Example JSON output:

```json
{"ip":"8.8.8.8","prefix":"8.8.8.0/24","origin_asn":"AS15169","origin_holder":"GOOGLE - Google LLC","as_path":["AS328840","AS327727","AS15169"],"visual_path":"AS328840 -> AS327727 -> AS15169","path_asn_details":[{"asn":"AS328840","holder":"ST-Digital-AS","country":"UNKNOWN"},{"asn":"AS327727","holder":"C-SQUARED","country":"UNKNOWN"},{"asn":"AS15169","holder":"GOOGLE - Google LLC","country":"UNKNOWN"}],"top_upstreams":[{"asn":"AS6453","power":469,"v4_peers":39513,"v6_peers":1808},{"asn":"AS1299","power":430,"v4_peers":42492,"v6_peers":6977},{"asn":"AS6939","power":379,"v4_peers":8988,"v6_peers":14457}],"path_contains_high_risk_jurisdiction":false,"high_risk_path_entries":[],"note":"Path is derived from RIPEstat bgp-state first entry and formatted source-to-destination."}
```

## IP Generation Script

Primary script: `core/ip_gen.py`

This utility generates newline-delimited IPv4 samples for analyst pipelines.
It supports normal mode for random global unicast addresses, and a malicious testing mode for controlled risk-flag validation.

Example usage:

```bash
python3 core/ip_gen.py --count 5
python3 core/ip_gen.py --count 5 --malicious
python3 core/ip_gen.py --count 5 --json
python3 core/ip_gen.py -m
```

Example output, malicious command:

```text
$ python3 core/ip_gen.py --count 5 --malicious
175.45.178.166
5.184.0.27
36.112.44.201
5.160.22.114
175.45.176.93
```

## Routing Integrity Checks

### BGP hijack or leak signal check

```bash
python3 scripts/bgp_hijack_check.py --prefix 8.8.8.0/24 --expected-asn AS15169
# or baseline CSV with lines: prefix,asn
python3 scripts/bgp_hijack_check.py --baseline baseline.csv --json
```

Data source notes:

- Primary source: RIPEstat Announced Prefixes endpoint
- Fallback source: RIPEstat RIS Prefixes endpoint
- Requests use a custom user agent for stable API handling

Example baseline file:

- `baseline.csv.example`

### RPKI validation check

```bash
python3 scripts/rpki_check.py --prefix 8.8.8.0/24 --asn AS15169
python3 scripts/rpki_check.py --baseline baseline.csv --json
```

## Batch reporting

```bash
python3 scripts/run_report.py -f ip_addresses.txt
python3 scripts/run_report.py -f ip_addresses.txt --json
```

## Python Tooling Index

| Script | Primary Use Case | Input | Output | JSON Flag |
|---|---|---|---|---|
| `core/ip_lookup.py` | Enriched IP triage with risk profile flags | Single IPv4/IPv6 | Structured text or flat JSON profile | Yes |
| `core/asn_integrity_audit.py` | ASN network integrity auditing with upstream and risk analysis | ASN or IPv4/IPv6 | Structured audit report or JSON object | Yes |
| `scripts/bgp_hijack_check.py` | Expected origin ASN mismatch detection | Prefix+ASN or baseline file | Signal status table or JSON | Yes |
| `scripts/rpki_check.py` | Route Origin Authorisation validation | Prefix+ASN or baseline file | Validity status table or JSON | Yes |
| `scripts/run_report.py` | Batch enrichment workflow for IP lists | File of IPs | Batch report output, optional JSON | Yes |
| `core/asn_path_finder.py` | Live AS-path and upstream routing analysis via RIPEstat | IPv4/IPv6 target IP | Structured report or JSON object | Yes |
| `core/ip_gen.py` | Generate global unicast IP samples, includes malicious test mode | `--count` with optional `--malicious` or `--json` | Newline IP list or JSON object | Yes |

## Current caveats

- Public API rate limits may affect high-volume runs.

## Security notes

- Do not commit real API keys.
- Keep secrets in local config only.

## Licence

MIT
