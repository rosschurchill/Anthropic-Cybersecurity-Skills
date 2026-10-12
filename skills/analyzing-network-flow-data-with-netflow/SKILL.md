---
name: analyzing-network-flow-data-with-netflow
description: >-
  Parses NetFlow v9 and IPFIX records with the Python netflow library to detect volumetric
  anomalies, port scanning, data exfiltration, and C2 beaconing, building traffic baselines and
  statistical analysis of byte counts, durations, and periodic timing. Use when hunting anomalies
  in flow records without packet payloads, baselining east-west traffic, or spotting beaconing
  from NetFlow/IPFIX exports. Keywords: NetFlow v9, IPFIX, flow records, beaconing, port scan,
  exfiltration, baseline. Do not use for full packet-payload inspection of a capture - use
  analyzing-network-traffic-with-wireshark.
domain: cybersecurity
subdomain: network-security
tags:
- analyzing
- network
- flow
- data
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1071
- T1048
- T1046
- T1095
---


# Analyzing Network Flow Data with Netflow


## When to Use

- Use when hunting anomalies in NetFlow v9 or IPFIX records where no packet payloads are available, parsing exports with the Python `netflow` library.
- Use when detecting port scanning from flow data (a single source reaching many destinations on the same port).
- Use when spotting data exfiltration as high byte-count outbound flows to unusual destinations.
- Use when identifying C2 beaconing through periodic connections with consistent intervals.
- Use when baselining east-west traffic and flagging volumetric spikes beyond threshold.

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install netflow`
2. Collect NetFlow/IPFIX data from routers or use the built-in collector: `python -m netflow.collector -p 9995`
3. Parse captured flow data using `netflow.parse_packet()`.
4. Analyze flows for:
   - Port scanning: single source to many destinations on same port
   - Data exfiltration: high byte-count outbound flows to unusual destinations
   - C2 beaconing: periodic connections with consistent intervals
   - Volumetric anomalies: traffic spikes beyond baseline thresholds
5. Generate a prioritized findings report.

```bash
python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json
```

## Examples

### Parse NetFlow v9 Packet
```python
import netflow
data, _ = netflow.parse_packet(raw_bytes, templates={})
for flow in data.flows:
    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)
```
