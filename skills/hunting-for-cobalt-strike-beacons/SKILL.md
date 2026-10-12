---
name: hunting-for-cobalt-strike-beacons
description: Detect Cobalt Strike beacon command-and-control traffic using default TLS certificate
  signatures (serial 8BB00EE), JA3/JA3S/JARM fingerprints, HTTP malleable C2 profile pattern matching,
  and beacon jitter/interval analysis, built with Zeek network logs, Suricata IDS rules, and Python
  PCAP analysis. Use when hunting for Cobalt Strike beacon callbacks in network traffic or building
  detection rules for this C2 framework. Do not use for statically decoding a recovered beacon's
  configuration - use analyzing-cobalt-strike-beacon-configuration.
domain: cybersecurity
subdomain: threat-hunting
tags:
- cobalt-strike
- beacon
- threat-hunting
- c2
- zeek
- suricata
- ja3
- jarm
- network-forensics
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1071
---

# Hunting for Cobalt Strike Beacons

## Overview

Cobalt Strike is the most prevalent command-and-control framework used by both red teams and threat actors. Beacon, its primary payload, communicates with team servers using configurable HTTP/HTTPS/DNS profiles that can mimic legitimate traffic. However, default configurations and behavioral patterns remain detectable through TLS certificate analysis (default serial 8BB00EE), JA3/JA3S fingerprinting, beacon interval jitter analysis, and HTTP malleable profile pattern matching. This skill covers building detection capabilities using Zeek network logs, Suricata IDS rules, and Python-based PCAP analysis to identify beacon callbacks in network traffic.


## When to Use

- Use when hunting Cobalt Strike beacon callbacks in Zeek ssl.log via the default certificate serial `8BB00EE` or known JA3S/JARM fingerprints.
- Use when analyzing connection timing in PCAP or Zeek conn.log for regular callback intervals with jitter (e.g. with RITA beacon scoring).
- Use when matching HTTP request URIs, headers, and user-agents against known malleable C2 profiles.
- Use when combining TLS, timing, and HTTP-profile indicators into a composite beacon confidence score during a network hunt.
- Use when writing Suricata rules to alert on Cobalt Strike C2 in live traffic.

## Prerequisites

- Zeek 6.0+ with JA3 and HASSH packages installed
- Suricata 7.0+ with Emerging Threats ruleset
- Python 3.9+ with scapy and dpkt libraries
- Network traffic captures (PCAP) or live Zeek logs
- RITA (Real Intelligence Threat Analytics) for beacon scoring
- Threat intelligence feeds with known Cobalt Strike IOCs

## Steps

### Step 1: TLS Certificate Analysis
Detect default Cobalt Strike certificates using JA3S fingerprints, certificate serial numbers, and JARM fingerprints in Zeek ssl.log.

### Step 2: Beacon Interval Analysis
Analyze connection timing patterns to identify regular callback intervals with configurable jitter, characteristic of beacon behavior.

### Step 3: HTTP Profile Detection
Match HTTP request patterns (URI paths, headers, user-agents) against known malleable C2 profiles.

### Step 4: Correlate and Score
Combine multiple indicators (TLS + timing + HTTP profile) into a composite beacon confidence score.

## Example

Hunt Zeek `ssl.log` for the default Cobalt Strike certificate serial (`8BB00EE...`) and
score beacon jitter from `conn.log` connection intervals:

```bash
# 1. TLS certificate analysis: default Cobalt Strike cert serial in Zeek ssl.log
#    (Zeek records the serial as a hex string; the default team-server cert starts 8BB00EE)
zeek-cut -d ts id.orig_h id.resp_h server_name < ssl.log \
  | grep -i "8bb00ee" || true
```

```python
# 2. Beacon interval/jitter analysis from Zeek conn.log (TSV)
import statistics
from collections import defaultdict

conns = defaultdict(list)
with open("conn.log") as f:
    for line in f:
        if line.startswith("#"):
            continue
        fields = line.rstrip("\n").split("\t")
        ts, orig, resp = float(fields[0]), fields[2], fields[4]
        conns[(orig, resp)].append(ts)

for (orig, resp), times in conns.items():
    if len(times) < 8:
        continue
    times.sort()
    intervals = [b - a for a, b in zip(times, times[1:])]
    mean = statistics.mean(intervals)
    if mean == 0:
        continue
    # Low coefficient of variation = regular callbacks = likely beacon
    cov = statistics.pstdev(intervals) / mean
    if cov < 0.25 and mean > 5:
        print(f"BEACON? {orig} -> {resp} interval~{mean:.0f}s jitter(cov)={cov:.2f} "
              f"callbacks={len(times)}")
```

## Expected Output

JSON report containing detected beacon candidates with confidence scores, TLS fingerprints, timing analysis, HTTP profile matches, and recommended response actions.
