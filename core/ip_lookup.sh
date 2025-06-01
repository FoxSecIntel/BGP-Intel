#!/bin/bash

# Check if an IP address is provided as a command-line argument
if [ -z "$1" ]; then
  echo "Please provide an IP address as an argument."
  exit 1
fi

# Fetch the geolocation information for the given IP address
ip=$1
geo=$(curl -s https://ipapi.co/$ip/json/)

# Extract and print all the information from the JSON response
echo $geo | jq -r '.'
