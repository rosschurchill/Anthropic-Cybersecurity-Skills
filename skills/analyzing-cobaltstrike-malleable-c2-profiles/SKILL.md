---
name: analyzing-cobaltstrike-malleable-c2-profiles
description: 'Parse and analyze Cobalt Strike Malleable C2 profiles with dissect.cobaltstrike (profiles and beacon-payload configs) and pyMalleableC2 (AST parsing) to extract HTTP/DNS transforms, URIs, headers, sleep/jitter, and injection behavior, then generate network detection signatures. Use when reverse-engineering a captured malleable profile or building detections against Cobalt Strike Beacon traffic. Do not use for extracting beacon configuration from PE files or memory dumps - use analyzing-cobalt-strike-beacon-configuration.'
domain: cybersecurity
subdomain: malware-analysis
tags:
- cobalt-strike
- malleable-c2
- c2-detection
- beacon-analysis
- network-signatures
- threat-hunting
- red-team-tools
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
mitre_attack:
- T1071.001
- T1573.002
- T1001.003
- T1090.004
- T1102
---
# Analyzing CobaltStrike Malleable C2 Profiles

## Overview

Cobalt Strike Malleable C2 profiles are domain-specific language scripts that customize how Beacon communicates with the team server, defining HTTP request/response transformations, sleep intervals, jitter values, user agents, URI paths, and process injection behavior. Threat actors use malleable profiles to disguise C2 traffic as legitimate services (Amazon, Google, Slack). Analyzing these profiles reveals network indicators for detection: URI patterns, HTTP headers, POST/GET transforms, DNS settings, and process injection techniques. The `dissect.cobaltstrike` library can parse both profile files and extract configurations from beacon payloads, while `pyMalleableC2` provides AST-based parsing using Lark grammar for programmatic profile manipulation and validation.


## When to Use

- Use when reverse-engineering a captured .profile to extract HTTP GET/POST URIs, headers, user agents, and metadata transforms.
- Use when you need the sleep time, jitter percentage, and DNS beacon settings a profile defines to tune detection thresholds.
- Use when a profile spoofs a legitimate service (Amazon, Google, Slack) and you need the exact indicators to build a Suricata/Snort signature.
- Use when validating captured Beacon traffic in a PCAP against a known malleable profile's transforms.
- Use when asked to "analyze this Cobalt Strike malleable profile" or "generate network detections from this C2 profile."

## Prerequisites

- Python 3.9+ with `dissect.cobaltstrike` and/or `pyMalleableC2`
- Sample Malleable C2 profiles (available from public repositories)
- Understanding of HTTP protocol and Cobalt Strike beacon communication model
- Network monitoring tools (Suricata/Snort) for signature deployment
- PCAP analysis tools for traffic validation

## Steps

1. Install libraries: `pip install dissect.cobaltstrike` or `pip install pyMalleableC2`
2. Parse profile with `C2Profile.from_path("profile.profile")`
3. Extract HTTP GET/POST block configurations (URIs, headers, parameters)
4. Identify user agent strings and spoof targets
5. Extract sleep time, jitter percentage, and DNS beacon settings
6. Analyze process injection settings (spawn-to, allocation technique)
7. Generate Suricata/Snort signatures from extracted network indicators
8. Compare profile against known threat actor profile collections
9. Extract staging URIs and payload delivery mechanisms
10. Produce detection report with IOCs and recommended network signatures

## Example

Parse a profile with `dissect.cobaltstrike` and pull the HTTP-GET URI, spoofed
User-Agent, and sleep/jitter, then emit a Suricata rule from the extracted URI:

```python
from dissect.cobaltstrike.c2profile import C2Profile

profile = C2Profile.from_path("amazon.profile")
cfg = profile.as_dict()

uri = cfg.get("http-get.uri", ["/"])[0]
useragent = cfg.get("useragent", ["<none>"])[0]
sleeptime = cfg.get("sleeptime", ["<none>"])[0]
jitter = cfg.get("jitter", ["<none>"])[0]

print(f"GET URI     : {uri}")
print(f"User-Agent  : {useragent}")
print(f"Sleep/Jitter: {sleeptime} ms / {jitter}%")

# Turn the URI + UA into a Suricata signature for the GET beacon
sid = 9000001
print(
    f'alert http any any -> any any (msg:"Cobalt Strike malleable C2 GET"; '
    f'flow:established,to_server; http.method; content:"GET"; '
    f'http.uri; content:"{uri}"; '
    f'http.user_agent; content:"{useragent}"; '
    f'classtype:trojan-activity; sid:{sid}; rev:1;)'
)
```

## Expected Output

A JSON report containing extracted C2 URIs, HTTP headers, user agents, sleep/jitter settings, process injection config, spawned process paths, DNS settings, and generated Suricata-compatible detection rules.
