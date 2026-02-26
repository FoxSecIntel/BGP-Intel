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
```

Batch report from file:

```bash
python3 scripts/run_report.py -f ip_addresses.txt
python3 scripts/run_report.py -f ip_addresses.txt --json
```

Run tests:

```bash
pytest -q
```

## Legacy shell helpers

These scripts are available for quick command-line tasks:

- `core/asn-lookup.sh`
- `core/asn-cidr.sh`
- `core/asn-ip-asn-distribution.sh`
- `core/ip_lookup.sh`

## Current caveats

- Public API rate limits may affect high-volume runs.

## Security notes

- Do not commit real API keys.
- Keep secrets in local config only.

## Licence

MIT
