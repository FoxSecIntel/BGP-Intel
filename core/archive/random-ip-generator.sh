#!/bin/bash

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
