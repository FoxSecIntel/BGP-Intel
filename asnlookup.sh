#!/bin/bash

# Find the ASN of an IP address

if [ -z "$1" ]; then
  echo "Error: Please provide an ip address"
  exit 1
fi

ip_address=$1

# Check if the input is a valid IP address
if [[ $ip_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  # Query the ASN
  asn=$(whois -h v4.whois.cymru.com " -c -p $ip_address")
  if [ -z "$asn" ]
   then
    echo "ASN not found for IP address: $1"
    else
    echo -e "\n$asn"
    host $ip_address 
   fi
else
  # Print an error message if the input is not a valid IP address
  echo "Invalid IP address"
fi
