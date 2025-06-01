#!/bin/bash

if [ -z "$1" ]; then
  echo "Please provide an ASN number as an argument."
  exit 1
fi

# Fetch the IPv4 and IPv6 prefixes for the given ASN number
asn=$1
ipv4_prefixes=$(whois -h whois.radb.net -- "-i origin $asn" | grep -Eo "([0-9]+\.){3}[0-9]+/[0-9]+")
#ipv6_prefixes=$(whois -h whois.radb.net -- "-i origin $asn" | grep -Eo "([0-9a-fA-F:]+)\/[0-9]+")

# Save the prefixes to a file
file="asn_$asn"
printf "%s\n" $ipv4_prefixes $ipv6_prefixes > $file

# Summarize the prefixes by CIDR notation
echo "Summary of prefixes for ASN $asn:"
#printf "%s\n" $ipv4_prefixes $ipv6_prefixes | awk -F/ '{print $2}' | sort | uniq -c | awk '{print $2 ": " $1}'
printf "%s\n" $ipv4_prefixes $ipv6_prefixes | awk -F/ '{print $2}' | sort | uniq -c | awk '{print $2 ": " $1}'
