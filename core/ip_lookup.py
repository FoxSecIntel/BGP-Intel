#!/usr/bin/env python3
encoded_str = "wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="

import sys
import requests
import json
import base64

def decode_and_print(encoded):
    decoded_bytes = base64.b64decode(encoded)
    decoded_str = decoded_bytes.decode('utf-8')
    print(decoded_str)

if '-m' in sys.argv:
    decode_and_print(encoded_str)
    sys.exit(0)

if len(sys.argv) != 2:
    print("Please provide an IP address as an argument.")
    sys.exit(1)

ip = sys.argv[1]
response = requests.get(f'https://ipapi.co/{ip}/json/')

if response.status_code == 200:
    geo = response.json()
    print(json.dumps(geo, indent=2))
else:
    print("Failed to fetch the geolocation information.")
