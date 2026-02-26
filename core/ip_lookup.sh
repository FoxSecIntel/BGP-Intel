#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: ip_lookup.sh <IP_ADDRESS>"
}

[[ $# -eq 1 ]] || { usage; exit 1; }
ip="$1"

[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|: ]] || { echo "Invalid IP format"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl command not found"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq command not found"; exit 1; }

geo="$(curl -sS --max-time 10 "https://ipapi.co/${ip}/json/" || true)"
[[ -n "$geo" ]] || { echo "Lookup failed"; exit 1; }

printf '%s\n' "$geo" | jq .
