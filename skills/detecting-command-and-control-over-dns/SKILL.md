---
name: detecting-command-and-control-over-dns
description: >-
  Detect command-and-control (C2) traffic tunneled over DNS from tools like Iodine, dnscat2,
  dns2tcp, and Cobalt Strike DNS beacon, using Shannon entropy analysis of query subdomains,
  ML-based DGA classification, passive DNS correlation, and Zeek/Suricata signatures. Use when
  investigating suspected DNS tunneling, classifying DGA domains, detecting DNS beaconing, or
  building DNS anomaly rules for a SOC/SIEM. Do not use for data exfiltration tunneled over DNS -
  use detecting-exfiltration-over-dns-with-zeek.
domain: cybersecurity
subdomain: network-security
tags:
- dns
- c2
- tunneling
- dga
- network-forensics
- threat-detection
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1095
---

# Detecting Command and Control Over DNS

## When to Use

- Investigating suspected DNS tunneling used for C2 communication or data exfiltration
- Analyzing DNS query logs for signs of encoded payloads in subdomain strings
- Classifying domains as DGA-generated vs. legitimate using statistical or ML methods
- Detecting DNS beaconing patterns (regular intervals, consistent query sizes)
- Hunting for Iodine, dnscat2, dns2tcp, Cobalt Strike DNS, or Sliver DNS traffic
- Monitoring TXT record abuse for command delivery or staged payload download
- Building DNS anomaly detection rules for SOC/SIEM deployment

**Do not use** for general DNS performance monitoring or DNS configuration auditing; use DNS health monitoring tools for those. For HTTP/HTTPS-based C2 detection, use network traffic analysis skills focused on web protocols.

**DISCLAIMER**: DNS tunneling tools referenced in this skill (Iodine, dnscat2, dns2tcp) are dual-use. They have legitimate uses (bypassing captive portals, security research) and malicious uses (C2 channels, exfiltration). Only deploy detection in networks you are authorized to monitor. Testing tunneling tools requires explicit authorization.

## Prerequisites

- DNS query logs from recursive resolver, Zeek/Bro, Suricata, or passive DNS tap
- Python 3.9+ with `numpy`, `scikit-learn`, `pandas`, `tldextract`, and `dnspython`
- Zeek (formerly Bro) with dns.log output or Suricata with DNS EVE JSON logging
- SIEM access (Splunk, Elastic, Microsoft Sentinel) for log correlation
- Passive DNS database access (CIRCL pDNS, Farsight DNSDB, or internal) for enrichment
- Wireshark/tshark for packet-level DNS inspection
- Known-good domain whitelist (Alexa/Tranco top 1M or Majestic Million)

## Workflow

### Step 1: Collect and Parse DNS Query Logs

Ingest DNS traffic from network sensors and parse into analyzable format:

```bash
# Zeek - extract dns.log fields
# Default Zeek dns.log columns:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt query
# qclass qclass_name qtype qtype_name rcode rcode_name AA TC RD RA Z
# answers TTLs rejected

# Filter for potentially suspicious record types
cat dns.log | zeek-cut ts id.orig_h query qtype_name answers rcode_name | \
    grep -E "TXT|NULL|CNAME|MX" > suspicious_qtypes.log

# Extract unique queried domains
cat dns.log | zeek-cut query | sort -u > unique_domains.txt

# Suricata EVE JSON - extract DNS events
cat eve.json | jq -r 'select(.event_type=="dns") |
    [.timestamp, .src_ip, .dns.rrname, .dns.rrtype, .dns.rcode] |
    @tsv' > dns_events.tsv

# tshark - extract DNS queries from pcap
tshark -r capture.pcap -T fields \
    -e frame.time -e ip.src -e ip.dst \
    -e dns.qry.name -e dns.qry.type \
    -e dns.resp.type -e dns.txt \
    -Y "dns" > dns_queries.tsv

# Count queries per domain (find high-volume destinations)
cat dns.log | zeek-cut query | \
    awk -F. '{print $(NF-1)"."$NF}' | \
    sort | uniq -c | sort -rn | head -50
```

### Step 2: Shannon Entropy Analysis of DNS Queries

Calculate entropy of subdomain strings to identify encoded/encrypted data:

See [references/entropy-analysis.md](references/entropy-analysis.md) for the full entropy-analysis code and tool signatures.

### Step 3: TXT Record Payload Detection

Identify C2 commands or staged payloads delivered via DNS TXT records:

See [references/txt-record-detection.md](references/txt-record-detection.md) for the full TXT-record payload detection code.

### Step 4: DGA Domain Classification with Machine Learning

Train a classifier to distinguish DGA-generated domains from legitimate ones:

See [references/dga-classifier.md](references/dga-classifier.md) for the full DGA classifier feature extraction and training code.

### Step 5: DNS Beaconing Pattern Detection

Identify periodic DNS query patterns indicative of C2 check-ins:

See [references/beaconing-detection.md](references/beaconing-detection.md) for the full beaconing-detection code.

### Step 6: Integrated DNS C2 Detection Pipeline

Combine all detection methods into a unified analysis:

See [references/detection-pipeline.md](references/detection-pipeline.md) for the full integrated pipeline architecture diagram.

### Step 7: SIEM Detection Rules

Deploy detection queries in your SIEM platform:

See [references/siem-detection-rules.md](references/siem-detection-rules.md) for the full Splunk SPL, Elastic KQL, and Zeek detection rules.

### Step 8: Suricata Rules for Known DNS C2 Tools

See [references/suricata-rules.md](references/suricata-rules.md) for the full Suricata rules for known DNS C2 tools.

## Key Concepts, Tools, Scenarios, and Output Format

See [references/reference-and-scenarios.md](references/reference-and-scenarios.md) for the Key Concepts glossary, Tools & Systems, Common Scenarios, and the full Output Format example.