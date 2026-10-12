---
name: hunting-for-dns-based-persistence
description: Hunts for DNS-based persistence mechanisms such as DNS hijacking, dangling CNAME
  records enabling subdomain takeover, wildcard DNS abuse, and unauthorized zone or NS delegation
  changes, using passive DNS history (SecurityTrails API), Route53/Azure DNS/Cloudflare audit
  logs, and zone transfer analysis. Use when investigating suspected DNS hijacking or subdomain
  takeover, or when threat hunting for DNS record tampering that persists across credential rotations
  and endpoint reimaging. Do not use for DNS tunneling exfiltration and C2 channel detection -
  use hunting-for-dns-tunneling-with-zeek.
domain: cybersecurity
subdomain: threat-hunting
tags:
- dns
- persistence
- threat-hunting
- passive-dns
- dns-hijacking
- subdomain-takeover
- securitytrails
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
- T1547
---

# Hunting for DNS-based Persistence

## Overview

Attackers establish DNS-based persistence by hijacking DNS records, creating unauthorized subdomains, abusing wildcard DNS entries, or modifying NS delegations to redirect traffic through attacker-controlled infrastructure. These techniques survive credential rotations, endpoint reimaging, and traditional remediation because DNS changes persist independently of compromised hosts. Detection requires passive DNS historical analysis, zone file auditing, and monitoring for unauthorized record modifications. This skill covers hunting methodologies using SecurityTrails passive DNS API, DNS audit logs from Route53/Azure DNS/Cloudflare, and zone transfer analysis.


## When to Use

- Use when investigating suspected DNS hijacking or subdomain takeover via dangling CNAME records pointing at decommissioned services.
- Use when pulling passive DNS history from the SecurityTrails API to find unauthorized new subdomains or changed records.
- Use when auditing Route53/Azure DNS/Cloudflare change logs (or zone transfers) for unauthorized NS delegation, wildcard, or MX modifications.
- Use when hunting persistence that survives credential rotation and endpoint reimaging because it lives in DNS, not on a host.
- Use when diffing current zone records against a historical baseline to surface record tampering.

## Prerequisites

- SecurityTrails API key (free tier provides 50 queries/month)
- Access to DNS provider audit logs (Route53, Azure DNS, Cloudflare, or on-premises DNS)
- Python 3.9+ with requests library
- DNS zone file access or AXFR capability for internal zones
- Historical DNS baseline for comparison

## Steps

### Step 1: Baseline DNS Records

Export current DNS zone records and establish baseline for all authorized A, AAAA, CNAME, MX, NS, and TXT records.

### Step 2: Query Passive DNS History

Use SecurityTrails API to retrieve historical DNS records and identify unauthorized changes, new subdomains, and CNAME records pointing to decommissioned services (dangling CNAMEs).

### Step 3: Detect Anomalies

Compare current records against baseline to identify unauthorized modifications, wildcard records that resolve all subdomains, NS delegation changes, and MX record hijacking.

### Step 4: Investigate Findings

Correlate DNS anomalies with threat intelligence feeds, check resolution targets against known malicious infrastructure, and validate record ownership.

## Example

Query SecurityTrails passive DNS history for a domain and flag CNAMEs that point at
decommissioned services (dangling CNAME = subdomain-takeover risk):

```python
import os
import requests

API = "https://api.securitytrails.com/v1"
headers = {"APIKEY": os.environ["SECURITYTRAILS_API_KEY"]}

# Hosting suffixes that commonly become dangling after a service is torn down
TAKEOVER_SUFFIXES = (
    ".s3.amazonaws.com", ".cloudfront.net", ".azurewebsites.net",
    ".github.io", ".herokuapp.com", ".trafficmanager.net",
)

domain = "example.com"
resp = requests.get(f"{API}/domain/{domain}/subdomains", headers=headers)
subdomains = resp.json().get("subdomains", [])

for sub in subdomains:
    fqdn = f"{sub}.{domain}"
    hist = requests.get(f"{API}/history/{fqdn}/dns/cname", headers=headers).json()
    for record in hist.get("records", []):
        for value in record.get("values", []):
            target = value.get("hostname", "")
            if target.endswith(TAKEOVER_SUFFIXES):
                print(f"[DANGLING?] {fqdn} CNAME -> {target} "
                      f"(first_seen={record.get('first_seen')})")
```

## Expected Output

JSON report listing DNS anomalies with record type, historical changes, risk severity, and remediation recommendations for each finding.
