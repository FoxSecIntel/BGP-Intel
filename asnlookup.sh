#!/bin/bash

# Find the ASN of an IP address

# Prompt the user for an IP address
read -p "Enter an IP address: " ip_address

# Check if the input is a valid IP address
if [[ $ip_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  # Query the ASN
  asn=$(whois -h v4.whois.cymru.com " -c -p $ip_address")
  if [ -z "$ASN" ]
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
