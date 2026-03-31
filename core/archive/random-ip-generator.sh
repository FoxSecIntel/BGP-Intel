#!/bin/bash
if [[ "${1:-}" == "-a" || "${1:-}" == "--author" ]]; then
  echo "Author: FoxSecIntel"
  echo "Repository: https://github.com/FoxSecIntel/BGP-Intel
  echo "Tool: random-ip-generator.sh"
  exit 0
fi


__r17q_blob="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$__r17q_blob" | base64 --decode
  exit 0
fi


# Take input from command line
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 number_of_ips"
    exit 1
fi
num_ips=$1

# Loop to generate the specified number of IP addresses
for ((i=1; i<=$num_ips; i++))
do
  # Generate random IP address
  while :
  do
    ip="$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))"
    if [[ $ip =~ ^(10|172|192)\. ]]; then
        continue
    else
        break
    fi
  done
  # Print the generated IP address
  echo $ip
done
