---
name: analyzing-ransomware-network-indicators
description: Identify ransomware-related network indicators, including C2 beaconing
  patterns, TOR exit node connections, data exfiltration flows, and encryption key
  exchange, by analyzing Zeek conn.log and NetFlow data. Use when threat hunting for
  active ransomware network activity or investigating suspected pre-encryption exfiltration
  during incident response. Do not use for host-side encryption-behavior detection
  - use detecting-ransomware-encryption-behavior.
domain: cybersecurity
subdomain: threat-hunting
tags:
- ransomware
- c2-beaconing
- zeek
- netflow
- tor
- exfiltration
- network-forensics
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Certificate Analysis
- Application Protocol Command Analysis
- Content Format Conversion
- File Content Analysis
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1071.001
- T1573
- T1048
- T1567.002
- T1486
mitre_f3:
  version: '1.1'
  tactics:
  - positioning
  - monetization
  techniques:
  - id: T1219
    name: Remote Access Tools
    tactic: positioning
    source: attack
  - id: F1018
    name: Convert to Cryptocurrency
    tactic: monetization
    source: f3
  - id: F1047
    name: Transfer of funds
    tactic: monetization
    source: f3
---

# Analyzing Ransomware Network Indicators

## Overview

Before and during ransomware execution, adversaries establish C2 channels, exfiltrate data, and download encryption keys. This skill analyzes Zeek conn.log and NetFlow data to detect beaconing patterns (regular-interval callbacks), connections to known TOR exit nodes, large outbound data transfers, and suspicious DNS activity associated with ransomware families.


## When to Use

- Use when threat hunting Zeek conn.log or NetFlow for C2 beaconing (regular-interval callbacks detected via low coefficient of variation on connection intervals).
- Use when investigating suspected pre-encryption exfiltration as large outbound byte-ratio flows to external IPs.
- Use when cross-referencing destination IPs against a current TOR exit-node list for anonymized C2 or payment traffic.
- Use when detecting DGA-like domain queries or high-entropy subdomains associated with ransomware families.
- Use when producing a composite ransomware risk score with MITRE mapping (T1071, T1573, T1048) during incident response.

## Prerequisites

- Zeek conn.log files or NetFlow CSV/JSON exports
- Python 3.8+ with standard library
- TOR exit node list (fetched from Tor Project or threat intel feeds)
- Optional: Known ransomware C2 IOC list

## Steps

1. **Parse Connection Logs** — Ingest Zeek conn.log (TSV) or NetFlow records into structured format
2. **Detect Beaconing Patterns** — Calculate connection interval statistics (mean, stddev, coefficient of variation) to identify periodic callbacks
3. **Check TOR Exit Node Connections** — Cross-reference destination IPs against current TOR exit node list
4. **Identify Data Exfiltration** — Flag connections with unusually high outbound byte ratios to external IPs
5. **Analyze DNS Patterns** — Detect DGA-like domain queries and high-entropy subdomains
6. **Score and Correlate** — Apply composite risk scoring across all indicator types
7. **Generate Report** — Produce structured report with timeline and MITRE ATT&CK mapping

## Expected Output

- JSON report with beaconing detections and interval statistics
- TOR exit node connection alerts
- Data exfiltration flow analysis
- Composite ransomware risk score with MITRE mapping (T1071, T1573, T1041)

## Example

Detect beaconing from a Zeek `conn.log` (TSV) using the interval coefficient-of-variation approach described in the steps:

```python
#!/usr/bin/env python3
"""Detect C2 beaconing in a Zeek conn.log via connection-interval regularity."""
import sys
import statistics
from collections import defaultdict


def load_conn_log(path):
    """Parse a Zeek conn.log (TSV). Returns rows as dicts keyed by #fields header."""
    fields, rows = [], []
    with open(path) as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.strip().split("\t")[1:]
            elif not line.startswith("#"):
                values = line.strip().split("\t")
                rows.append(dict(zip(fields, values)))
    return rows


def detect_beaconing(rows, min_conns=8, cv_threshold=0.1):
    """Flag src->dst pairs whose connection intervals are suspiciously regular."""
    timeline = defaultdict(list)
    for r in rows:
        try:
            ts = float(r["ts"])
        except (KeyError, ValueError):
            continue
        timeline[(r["id.orig_h"], r["id.resp_h"], r.get("id.resp_p", ""))].append(ts)

    findings = []
    for (src, dst, dport), times in timeline.items():
        if len(times) < min_conns:
            continue
        times.sort()
        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(intervals)
        if mean == 0:
            continue
        cv = statistics.pstdev(intervals) / mean  # low CV = highly periodic
        if cv < cv_threshold:
            findings.append({
                "src": src, "dst": dst, "dport": dport,
                "connections": len(times),
                "mean_interval_s": round(mean, 1),
                "cv": round(cv, 3),
                "verdict": "likely C2 beacon",
            })
    return sorted(findings, key=lambda x: x["cv"])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <conn.log>")
        sys.exit(1)
    for f in detect_beaconing(load_conn_log(sys.argv[1])):
        print(f"[!] {f['src']} -> {f['dst']}:{f['dport']} "
              f"({f['connections']} conns, interval ~{f['mean_interval_s']}s, CV={f['cv']})")
```
