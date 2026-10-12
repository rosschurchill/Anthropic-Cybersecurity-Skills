---
name: analyzing-network-packets-with-scapy
description: Use Scapy to craft, send, sniff, and dissect TCP/UDP/ICMP/DNS packets,
  analyze pcap files, implement SYN scans, and detect anomalous traffic such as fragmented
  or malformed packets. Use when performing authorized network reconnaissance, protocol-level
  forensic analysis, or building traffic anomaly detection during security testing.
  Do not use for interactive pcap analysis in Wireshark - use analyzing-network-traffic-with-wireshark.
domain: cybersecurity
subdomain: network-security
tags:
- scapy
- packet-analysis
- network-forensics
- protocol-dissection
- pcap
- traffic-analysis
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1040
- T1071
- T1046
- T1557
---

# Analyzing Network Packets with Scapy

## Overview

Scapy is a Python packet manipulation library that enables crafting, sending, sniffing, and dissecting network packets at granular protocol layers. This skill covers using Scapy for security-relevant tasks including TCP/UDP/ICMP packet crafting, pcap file analysis, protocol field extraction, SYN scan implementation, DNS query analysis, and detecting anomalous traffic patterns such as unusually fragmented packets or malformed headers.


## When to Use

- Use when analyzing a pcap/pcapng offline with `rdpcap()` to extract IP/TCP/UDP/DNS layers and compute top talkers, protocol distribution, and port frequency.
- Use when detecting SYN flood patterns by analyzing TCP flag ratios across a capture.
- Use when identifying DNS exfiltration indicators via query-length and entropy analysis.
- Use when crafting and sending custom probe packets (e.g. a SYN scan) during authorized network testing.
- Use when spotting anomalous traffic such as unusually fragmented packets or malformed headers at the protocol-field level.

## Prerequisites

- Python 3.8+ with `scapy` library installed (`pip install scapy`)
- Root/administrator privileges for raw socket operations (sniffing, sending)
- Npcap (Windows) or libpcap (Linux) for packet capture
- Authorization to perform packet operations on target network

## Steps

1. Read and parse pcap/pcapng files with `rdpcap()` for offline analysis
2. Extract protocol layers (IP, TCP, UDP, DNS, HTTP) and field values
3. Compute traffic statistics: top talkers, protocol distribution, port frequency
4. Detect SYN flood patterns by analyzing TCP flag ratios
5. Identify DNS exfiltration indicators via query length and entropy analysis
6. Craft custom probe packets for authorized network testing
7. Export findings as structured JSON report

## Expected Output

JSON report containing packet statistics, protocol distribution, top source/destination IPs, detected anomalies (SYN floods, DNS tunneling indicators, fragmentation attacks), and per-flow summaries.

## Example

Read a pcap offline and surface top talkers plus SYN-flood candidates (hosts sending many SYNs with few returning SYN-ACKs):

```python
#!/usr/bin/env python3
"""Scapy pcap triage: top talkers and SYN-flood detection."""
import sys
from collections import Counter, defaultdict
from scapy.all import rdpcap, IP, TCP


def analyze(pcap_path):
    packets = rdpcap(pcap_path)
    talkers = Counter()
    syn = defaultdict(int)
    synack = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        talkers[pkt[IP].src] += 1
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            # SYN set, ACK clear = connection initiation
            if flags & 0x02 and not flags & 0x10:
                syn[pkt[IP].src] += 1
            # SYN+ACK = server response
            elif flags & 0x12 == 0x12:
                synack[pkt[IP].dst] += 1

    print("[+] Top talkers:")
    for ip, count in talkers.most_common(10):
        print(f"    {ip}: {count} packets")

    print("[+] SYN-flood candidates (SYN >> SYN-ACK):")
    for ip, s in sorted(syn.items(), key=lambda x: -x[1]):
        responses = synack.get(ip, 0)
        if s > 100 and responses < s * 0.1:
            print(f"    {ip}: {s} SYN, {responses} SYN-ACK -> possible SYN flood")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    analyze(sys.argv[1])
```
