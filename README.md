# Determining the ASN of an IP Address with a Bash Script

ASN stands for "Autonomous System Number." In the context of networking, an ASN is a unique number assigned to a network or group of networks that operate together as a single entity. This number is used to identify the network and its associated routes on the global internet.

ASNs are typically assigned by regional internet registries (RIRs) such as ARIN (American Registry for Internet Numbers), RIPE (Réseaux IP Européens), and APNIC (Asia-Pacific Network Information Centre). These RIRs are responsible for managing the allocation of IP addresses and ASNs within their respective regions.

ASNs are used in a variety of network protocols and technologies, including Border Gateway Protocol (BGP) and Multiprotocol Label Switching (MPLS). They are also used to identify and differentiate between different networks on the internet.

Use this script to identify which ASN the IP is on

$ ASN-lookup.sh 93.184.216.35

AS      | IP               | BGP Prefix          | CC | AS Name <br>
15133   | 93.184.216.34    | 93.184.216.0/24     | US | EDGECAST, US <br>
Host 34.216.184.93.in-addr.arpa. not found: 3(NXDOMAIN)<br>
