#!/bin/bash
set -euo pipefail

VERSION="1.2.0"

usage() {
  cat <<'EOF'
Usage: asn-ip-asn-distribution.sh [-f ip_addresses.txt] [--json]

Default input file: ./ip_addresses.txt
EOF
}

input_file="./ip_addresses.txt"
json=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) shift; input_file="${1:-}"; shift ;;
    --json|-j) json=true; shift ;;
    -v|--version) echo "asn-ip-asn-distribution.sh $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

[[ -f "$input_file" ]] || { echo "Input file not found: $input_file"; exit 1; }
command -v whois >/dev/null 2>&1 || { echo "whois command not found"; exit 1; }

declare -a asns=()

while IFS= read -r line || [[ -n "$line" ]]; do
  ip="$(echo "$line" | xargs)"
  [[ -z "$ip" || "$ip" =~ ^# ]] && continue
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue

  asn="$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | awk 'NR==2 {print $1}' | sed 's/^AS//')"
  [[ -n "$asn" && "$asn" =~ ^[0-9]+$ ]] && asns+=("$asn")
done < "$input_file"

if [[ ${#asns[@]} -eq 0 ]]; then
  echo "No ASN results produced"
  exit 0
fi

if $json; then
  tmp=/tmp/asn_dist.$$
  while read -r count asn; do
    asn_name="$(whois -h whois.cymru.com " -v AS${asn}" 2>/dev/null | awk 'NR==2 {$1=$2=$3=$4=""; print $0}' | xargs)"
    jq -n --arg asn "AS${asn}" --argjson count "$count" --arg name "${asn_name:-unknown}" '{asn:$asn,count:$count,name:$name}'
  done < <(printf '%s\n' "${asns[@]}" | sort | uniq -c | awk '{print $1, $2}' | sort -rn) > "$tmp"
  jq -s '.' "$tmp"
  rm -f "$tmp"
  exit 0
fi

printf "%-10s | %-10s | %-30s\n" "ASN" "Count" "ASN Name"
echo "----------------------------------------------------------------"
while read -r count asn; do
  asn_name="$(whois -h whois.cymru.com " -v AS${asn}" 2>/dev/null | awk 'NR==2 {$1=$2=$3=$4=""; print $0}' | xargs)"
  printf "%-10s | %-10s | %-30s\n" "AS${asn}" "$count" "${asn_name:-unknown}"
done < <(printf '%s\n' "${asns[@]}" | sort | uniq -c | awk '{print $1, $2}' | sort -rn)
