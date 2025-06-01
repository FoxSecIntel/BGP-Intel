#!/bin/bash
encoded_str="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="

if [ -z "$1" ]; then
  echo "Error: Please provide an IP address"
  exit 1
fi

decode_base64() {
    echo "$encoded_str" | base64 --decode
    echo 
}

find_asn() {
    ip_address=$1

if [[ $ip_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  asn=$(whois -h v4.whois.cymru.com " -v $ip_address")
  if [ -z "$asn" ]
   then
    echo "ASN not found for IP address: $1"
    else
    echo -e "\n$asn\n"
    host $ip_address 
   fi
else
  echo "Invalid IP address"
fi
}

if [ "$1" == "m" ]; then
    decode_base64
else
    find_asn "$1"
fi
