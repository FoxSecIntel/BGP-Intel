#!/bin/bash
#set -x

# Check if an IP address argument was provided
if [ $# -eq 0 ]
then
    echo "Please provide an IP address as an argument"
    exit 1
fi

# Get the ASN for the IP address using the "whois" command
ASN=$(whois -h v4.whois.cymru.com " -c -p $1")

# Check if the ASN was found
if [ -z "$ASN" ]
then
    echo "ASN not found for IP address: $1"
else
    echo -e "\n$ASN"
    host $1
fi
