# Bash scripts to help you gather OSINT from ASN and IP addresses 

ASN stands for "Autonomous System Number." In the context of networking, an ASN is a unique number assigned to a network or group of networks that operate together as a single entity. This number is used to identify the network and its associated routes on the global internet.

ASNs are typically assigned by regional internet registries (RIRs) such as ARIN (American Registry for Internet Numbers), RIPE (Réseaux IP Européens), and APNIC (Asia-Pacific Network Information Centre). These RIRs are responsible for managing the allocation of IP addresses and ASNs within their respective regions.

ASNs are used in a variety of network protocols and technologies, including Border Gateway Protocol (BGP) and Multiprotocol Label Switching (MPLS). They are also used to identify and differentiate between different networks on the internet.

<PRE>
ASN-lookup.sh  - Use this script to identify which ASN the IP is on 
$ ./asn-lookup.sh [insert IP address]

ASN-cdir.sh - Use this script to work out which IP exist within an ASN
$ ./asn-cdir.sh [AS Name]

ip_lookup.sh - Use this script to gather IP Geolocation information

random_ip_generator.sh - Use this script to generate random public IPv4 addresses

</PRE>
