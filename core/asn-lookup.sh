#!/bin/bash
set -euo pipefail

encoded_str="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="

usage() {
  cat <<'EOF'
Usage: asn-lookup.sh <IPv4|m>

Examples:
  asn-lookup.sh 8.8.8.8
  asn-lookup.sh m
EOF
}

[[ $# -eq 1 ]] || { usage; exit 1; }

if [[ "$1" == "m" ]]; then
  echo "$encoded_str" | base64 --decode
  exit 0
fi

ip_address="$1"
[[ "$ip_address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Invalid IPv4 address"; exit 1; }
command -v whois >/dev/null 2>&1 || { echo "whois command not found"; exit 1; }

asn_out="$(whois -h v4.whois.cymru.com " -v $ip_address" 2>/dev/null || true)"
if [[ -z "$asn_out" ]]; then
  echo "ASN not found for IP address: $ip_address"
  exit 1
fi

echo
printf '%s\n' "$asn_out"
echo

if command -v host >/dev/null 2>&1; then
  host "$ip_address" || true
fi
