![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

# BGP-Intel

**BGP-Intel** is a lightweight IP and ASN analysis toolkit for Tier 1 SOC analysts.

It supports fast enrichment, simple batch reporting, and modular extension for routing and ASN workflows.

## Features

- IP validation and metadata lookup
- ASN-focused shell helpers
- Batch report runner for IP lists
- Optional enrichment via public APIs
- Basic unit tests for lookup validation

## Repository structure

- `core/` core lookup logic and shell helpers
- `scripts/` batch and automation entrypoints
- `tests/` unit tests
- `config/` example configuration files
- `docs/` future documentation

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Single IP lookup:

```bash
python3 core/ip_lookup.py 8.8.8.8
python3 core/ip_lookup.py 8.8.8.8 --json
```

IP lookup data source notes:

- Uses RIPEstat Prefix Overview for ASN and holder intelligence.
- Uses RIPEstat RIR Stats Country for country attribution.
- Includes automated high-risk jurisdiction warning for: RU, CN, IR, KP, SY.

Batch report from file:

```bash
python3 scripts/run_report.py -f ip_addresses.txt
python3 scripts/run_report.py -f ip_addresses.txt --json
```

Prefix origin mismatch check (hijack or leak signal):

```bash
python3 scripts/bgp_hijack_check.py --prefix 8.8.8.0/24 --expected-asn AS15169
# or baseline CSV with lines: prefix,asn
python3 scripts/bgp_hijack_check.py --baseline baseline.csv --json
```

Data source notes for hijack checks:

- Primary source: RIPEstat Announced Prefixes endpoint
- Fallback source: RIPEstat RIS Prefixes endpoint
- Requests include a custom user agent for stable API handling

Example baseline file:

- `baseline.csv.example`

RPKI validation check (prefix and origin ASN pair):

```bash
python3 scripts/rpki_check.py --prefix 8.8.8.0/24 --asn AS15169
python3 scripts/rpki_check.py --baseline baseline.csv --json
```

Run tests:

```bash
pytest -q
```

## Core Shell Utilities

These shell utilities are actively maintained for fast command-line enrichment and analyst workflows.

| Script | Primary Use Case | Input | Output | JSON Flag |
|---|---|---|---|---|
| `core/archive/asn-lookup.sh` | Resolve ASN details for an IPv4 address | Single IPv4 | WHOIS lookup output + optional reverse host | Yes |
| `core/archive/asn-cidr.sh` | Retrieve announced IPv4 and IPv6 prefixes for an ASN | Single ASN | Prefix list file + prefix-length summary | Yes |
| `core/archive/asn-ip-asn-distribution.sh` | Build ASN distribution from a list of IPv4 addresses | Text file of IPv4s | Counted ASN distribution table | Yes |
| `core/archive/ip_lookup.sh` | Quick IP geodata enrichment from public API | Single IPv4/IPv6 | Formatted metadata or JSON | Yes |

## Current caveats

- Public API rate limits may affect high-volume runs.

## Security notes

- Do not commit real API keys.
- Keep secrets in local config only.

## Licence

MIT
