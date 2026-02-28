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
| `core/asn_path_finder.py` | ASN path and relationship analysis utility | ASN input | Console analysis output | No |
| `core/random-ip-generator.py` | Generate random IP samples for testing | Optional count or defaults | Generated IP list | No |

## Current caveats

- Public API rate limits may affect high-volume runs.

## Security notes

- Do not commit real API keys.
- Keep secrets in local config only.

## Licence

MIT
