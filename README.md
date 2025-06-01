![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

# BGP-Intel

**BGP-Inteal** is a lightweight IP & ASN analysis toolkit built for Tier 1 SOC analysts. It supports fast lookups, threat enrichment, and optional integration with AbuseIPDB and other APIs.

## 🚀 Features
- IP to ASN lookups
- ASN org and prefix data
- Optional enrichment via public APIs
- AbuseIPDB integration (via script)
- Modular structure, easy to extend

## 🛠 Folder Structure
core/ → Core lookup logic
utils/ → Helper utilities
scripts/ → Automation scripts
tests/ → Basic tests
docs/ → Future documentation
config/ → Config templates

## 📦 Usage
Paste IPs into `core/lookup.py`, or use `scripts/run_report.py` to parse IP lists.

## 🔧 Setup
1. Copy `config/config.ini.example` to `config/config.ini`
2. Populate API keys if required
3. Run scripts via GitHub Codespaces or locally

## 🔐 Disclaimer
Never commit real credentials. Always use `.gitignore` and `config.ini.example`.
