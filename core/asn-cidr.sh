#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: asn-cidr.sh <ASN>

Example:
  asn-cidr.sh AS15169
  asn-cidr.sh 15169
EOF
}

[[ $# -eq 1 ]] || { usage; exit 1; }
command -v whois >/dev/null 2>&1 || { echo "whois command not found"; exit 1; }

asn_input="$1"
asn_num="${asn_input#AS}"
[[ "$asn_num" =~ ^[0-9]+$ ]] || { echo "Invalid ASN: $asn_input"; exit 1; }
asn="AS${asn_num}"

raw="$(whois -h whois.radb.net -- "-i origin ${asn}" 2>/dev/null || true)"

ipv4_prefixes="$(printf '%s\n' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | sort -u || true)"
ipv6_prefixes="$(printf '%s\n' "$raw" | grep -Eo '([0-9a-fA-F:]+)/[0-9]+' | grep ':' | sort -u || true)"

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
