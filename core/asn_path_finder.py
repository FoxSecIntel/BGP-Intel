import requests
import sys
import time

# Define a delay between API requests to avoid hitting rate limits
RETRY_DELAY_SECONDS = 1

def get_as_path(ip):
    try:
        print(f"Querying BGPView.io for IP: {ip}")

        # Step 1: Get most specific prefix info from /ip/{ip}
        ip_url = f"https://api.bgpview.io/ip/{ip}"
        print(f"Requesting IP info from: {ip_url}")
        ip_resp = requests.get(ip_url, timeout=10)

        if ip_resp.status_code == 429:
            print(f"[!] IP API Error: 429 Too Many Requests. Waiting for {RETRY_DELAY_SECONDS} seconds before retrying...")
            time.sleep(RETRY_DELAY_SECONDS)
            ip_resp = requests.get(ip_url, timeout=10) # Retry after delay

        if ip_resp.status_code != 200:
            print(f"[!] IP API Error: {ip_resp.status_code}")
            print(f"Response body (first 200 chars): {ip_resp.text[:200]}")
            return

        ip_data = ip_resp.json()

        prefixes = ip_data.get("data", {}).get("prefixes", [])
        if not prefixes:
            print(f"No BGP data found for {ip}")
            return

        # Sort by CIDR length to get the most specific prefix
        def get_cidr_length(prefix_item):
            prefix_str = prefix_item.get("prefix", "")
            if '/' in prefix_str:
                try:
                    return int(prefix_str.split('/')[1])
                except ValueError:
                    return 0
            return 0

        most_specific = sorted(prefixes, key=get_cidr_length, reverse=True)[0]
        prefix_str = most_specific.get("prefix", "Unknown")
        asn_info = most_specific.get("asn", {})
        asn = asn_info.get("asn", "Unknown")
        asn_name = asn_info.get("name", "Unknown")
        asn_country = asn_info.get("country_code", "N/A")

        # Introduce a delay before the next API request
        time.sleep(RETRY_DELAY_SECONDS)

        # Step 2: Get prefix details from /prefix/{prefix_str}
        # This endpoint doesn't give a full AS path from origin to you,
        # but rather details about the prefix and its immediate upstreams.
        prefix_url = f"https://api.bgpview.io/prefix/{prefix_str}"
        print(f"Requesting Prefix info from: {prefix_url}")
        prefix_resp = requests.get(prefix_url, timeout=10)

        if prefix_resp.status_code == 429:
            print(f"[!] Prefix API Error: 429 Too Many Requests. Waiting for {RETRY_DELAY_SECONDS} seconds before retrying...")
            time.sleep(RETRY_DELAY_SECONDS)
            prefix_resp = requests.get(prefix_url, timeout=10) # Retry after delay

        if prefix_resp.status_code != 200:
            print(f"[!] Prefix API Error: {prefix_resp.status_code}")
            print(f"Response body (first 200 chars): {prefix_resp.text[:200]}")
            return

        prefix_data = prefix_resp.json()

        # --- CRITICAL FIX HERE ---
        # The AS Path information as a sequence of ASNs (like in traceroute)
        # is NOT directly available from the /prefix/{prefix_str} endpoint.
        # This endpoint provides the origin ASN and its immediate 'prefix_upstreams'.
        # We will extract and display these upstreams.

        as_path_display = []
        origin_asn_display = f"AS{asn}"

        # Add the origin ASN itself to the path if it's available
        if asn != "Unknown":
            as_path_display.append(origin_asn_display)

        # Extract and add upstream ASNs
        prefix_upstreams = []
        # Check if asns list exists and has items
        if 'asns' in prefix_data.get('data', {}) and prefix_data['data']['asns']:
            # The 'asns' list within data.asns[0] holds the origin ASN's details for this prefix
            # And within it, the 'prefix_upstreams' are listed.
            # Assuming the first ASN in the list is the primary origin for the prefix.
            origin_asn_details = prefix_data['data']['asns'][0]
            prefix_upstreams = origin_asn_details.get('prefix_upstreams', [])

        if prefix_upstreams:
            for upstream in prefix_upstreams:
                upstream_asn = upstream.get('asn')
                upstream_name = upstream.get('name')
                if upstream_asn:
                    as_path_display.append(f"AS{upstream_asn} ({upstream_name})")
        # --- END CRITICAL FIX ---


        # Output
        print(f"\n--- BGP Information for {ip} ---")
        print(f"IP Address: {ip}")
        print(f"Most Specific Prefix: {prefix_str}")
        print(f"Origin ASN: AS{asn} ({asn_name}, {asn_country})")

        # Clarify what the "AS Path" represents here given API limitations
        if len(as_path_display) > 1:
            print("Origin AS and Direct Upstream ASNs: " + " → ".join(as_path_display))
            print("(Note: This shows direct upstreams from the origin AS, not a full internet path.)")
        elif len(as_path_display) == 1:
            print(f"Origin AS: {as_path_display[0]}")
            print("(Note: No direct upstream ASNs found via this API endpoint.)")
        else:
            print("AS Path: Not available or unable to retrieve AS Path from API.")

        print("-" * (len(ip) + 29)) # Dynamic separator length

    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
    except ValueError:
        print("JSON parsing error: Invalid API response format.")
    except IndexError:
        print(f"Error: Could not determine most specific prefix or parse data for {ip}. API response structure might have changed or data is missing.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test.py <IP_ADDRESS>")
        print("Example: python test.py 8.8.8.8")
    else:
        get_as_path(sys.argv[1])
