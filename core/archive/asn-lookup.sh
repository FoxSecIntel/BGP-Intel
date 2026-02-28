#!/bin/bash
set -euo pipefail

encoded_str="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
VERSION="1.2.0"

usage() {
  cat <<'EOF'
Usage: asn-lookup.sh [--json] <IPv4|m>

Examples:
  asn-lookup.sh 8.8.8.8
  asn-lookup.sh --json 8.8.8.8
  asn-lookup.sh m
EOF
}

json=false
arg=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json|-j) json=true; shift ;;
    -v|--version) echo "asn-lookup.sh $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) arg="$1"; shift ;;
  esac
done

[[ -n "$arg" ]] || { usage; exit 1; }

if [[ "$arg" == "m" ]]; then
  echo "$encoded_str" | base64 --decode
  exit 0
fi

ip_address="$arg"
[[ "$ip_address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Invalid IPv4 address"; exit 1; }
command -v whois >/dev/null 2>&1 || { echo "whois command not found"; exit 1; }

asn_out="$(whois -h v4.whois.cymru.com " -v $ip_address" 2>/dev/null || true)"
[[ -n "$asn_out" ]] || { echo "ASN not found for IP address: $ip_address"; exit 1; }

asn_line="$(printf '%s\n' "$asn_out" | sed -n '2p' || true)"
asn="$(echo "$asn_line" | awk '{print $1}')"
cc="$(echo "$asn_line" | awk '{print $3}')"
owner="$(echo "$asn_line" | awk '{$1=$2=$3=$4=""; print $0}' | xargs)"

host_name=""
if command -v host >/dev/null 2>&1; then
  host_name="$(host "$ip_address" 2>/dev/null | sed -n 's/.*pointer \(.*\)\./\1/p' | head -n1 || true)"
fi

if $json; then
  jq -n --arg ip "$ip_address" --arg asn "$asn" --arg cc "$cc" --arg owner "$owner" --arg host "$host_name" \
    '{ip:$ip, asn:$asn, country:$cc, owner:$owner, reverse_host:$host}'
else
  echo
  printf '%s\n' "$asn_out"
  echo
  [[ -n "$host_name" ]] && echo "Reverse host: $host_name"
fi
