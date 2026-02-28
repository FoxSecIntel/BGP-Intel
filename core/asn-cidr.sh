#!/bin/bash
set -euo pipefail

VERSION="1.2.0"

usage() {
  cat <<'EOF'
Usage: asn-cidr.sh [--json] <ASN>

Example:
  asn-cidr.sh AS15169
  asn-cidr.sh --json 15169
EOF
}

json=false
asn_input=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json|-j) json=true; shift ;;
    -v|--version) echo "asn-cidr.sh $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) asn_input="$1"; shift ;;
  esac
done

[[ -n "$asn_input" ]] || { usage; exit 1; }
command -v whois >/dev/null 2>&1 || { echo "whois command not found"; exit 1; }

asn_num="${asn_input#AS}"
[[ "$asn_num" =~ ^[0-9]+$ ]] || { echo "Invalid ASN: $asn_input"; exit 1; }
asn="AS${asn_num}"

raw="$(whois -h whois.radb.net -- "-i origin ${asn}" 2>/dev/null || true)"
ipv4_prefixes="$(printf '%s\n' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | sort -u || true)"
ipv6_prefixes="$(printf '%s\n' "$raw" | grep -Eo '([0-9a-fA-F:]+)/[0-9]+' | grep ':' | sort -u || true)"

if $json; then
  printf '%s\n' "$ipv4_prefixes" > /tmp/asn_cidr_v4.$$ || true
  printf '%s\n' "$ipv6_prefixes" > /tmp/asn_cidr_v6.$$ || true
  jq -n --arg asn "$asn" \
    --argjson ipv4 "$(jq -R . /tmp/asn_cidr_v4.$$ | jq -s 'map(select(length>0))')" \
    --argjson ipv6 "$(jq -R . /tmp/asn_cidr_v6.$$ | jq -s 'map(select(length>0))')" \
    '{asn:$asn, ipv4_prefixes:$ipv4, ipv6_prefixes:$ipv6}'
  rm -f /tmp/asn_cidr_v4.$$ /tmp/asn_cidr_v6.$$
  exit 0
fi

out_file="asn_${asn_num}.txt"
{
  printf '# Prefixes for %s\n' "$asn"
  [[ -n "$ipv4_prefixes" ]] && printf '%s\n' "$ipv4_prefixes"
  [[ -n "$ipv6_prefixes" ]] && printf '%s\n' "$ipv6_prefixes"
} > "$out_file"

echo "Summary of prefixes for $asn"
if [[ -z "$ipv4_prefixes" && -z "$ipv6_prefixes" ]]; then
  echo "No prefixes found"
  exit 0
fi

printf '%s\n%s\n' "$ipv4_prefixes" "$ipv6_prefixes" \
  | sed '/^$/d' \
  | awk -F/ '{print $2}' \
  | sort -n \
  | uniq -c \
  | awk '{printf "/%s: %s\n", $2, $1}'

echo "Saved prefixes to: $out_file"
