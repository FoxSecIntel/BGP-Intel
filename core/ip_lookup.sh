#!/bin/bash
set -euo pipefail

VERSION="1.2.0"

usage() {
  echo "Usage: ip_lookup.sh [--json|-j] <IP_ADDRESS>"
}

json=false
ip=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json|-j) json=true; shift ;;
    -v|--version) echo "ip_lookup.sh $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) ip="$1"; shift ;;
  esac
done

[[ -n "$ip" ]] || { usage; exit 1; }
[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|: ]] || { echo "Invalid IP format"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl command not found"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq command not found"; exit 1; }

geo="$(curl -sS --max-time 10 "https://ipapi.co/${ip}/json/" || true)"
[[ -n "$geo" ]] || { echo "Lookup failed"; exit 1; }

if $json; then
  printf '%s\n' "$geo" | jq .
else
  country="$(printf '%s' "$geo" | jq -r '.country_name // "unknown"')"
  asn="$(printf '%s' "$geo" | jq -r '.asn // "unknown"')"
  org="$(printf '%s' "$geo" | jq -r '.org // "unknown"')"
  city="$(printf '%s' "$geo" | jq -r '.city // "unknown"')"
  echo "IP: $ip"
  echo "Country: $country"
  echo "ASN: $asn"
  echo "Organisation: $org"
  echo "City: $city"
fi
