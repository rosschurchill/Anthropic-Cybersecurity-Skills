---
name: detecting-pass-the-ticket-attacks
description: >-
  Detect Kerberos Pass-the-Ticket (PtT) attacks by analyzing Windows Event IDs 4768, 4769, and
  4771 for anomalous ticket usage patterns, with detection queries for Splunk and Elastic SIEM.
  Use when investigating incidents involving stolen or replayed Kerberos tickets, building
  detection rules or threat hunting queries for ticket abuse, or validating SOC monitoring
  coverage for credential-theft attack techniques. Do not use for performing an offensive
  Pass-the-Ticket attack - use conducting-pass-the-ticket-attack.
domain: cybersecurity
subdomain: threat-detection
tags:
- kerberos
- pass-the-ticket
- active-directory
- splunk
- elastic
- credential-theft
- windows-security
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Execution Isolation
- Restore Access
- Application Protocol Command Analysis
- Process Termination
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
---

# Detecting Pass-the-Ticket Attacks

## Overview

Pass-the-Ticket (PtT) is a credential theft technique (MITRE ATT&CK T1550.003) where adversaries steal Kerberos tickets (TGT or TGS) from one system and replay them on another to authenticate without knowing the user's password. This skill teaches detection of PtT attacks by correlating Windows Security Event IDs 4768 (TGT request), 4769 (TGS request), and 4771 (pre-authentication failure) for anomalies such as ticket reuse across different hosts, RC4 encryption downgrades, and unusual service ticket request volumes.


## When to Use

- Use when investigating stolen or replayed Kerberos tickets (TGT/TGS) across Active Directory hosts
- Use when writing Splunk or Elastic detection rules over Windows Event IDs 4768, 4769, and 4771
- Use when flagging RC4 encryption downgrades (TicketEncryptionType 0x17) that indicate ticket abuse
- Use when correlating ticket reuse from multiple source IPs or baselining per-user TGS request volume
- Use when validating SOC coverage for credential-theft techniques (MITRE T1550.003)

## Prerequisites

- Windows Domain Controller with advanced audit policy enabled (Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations)
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Sysmon deployed on endpoints for supplementary process telemetry
- Python 3.8+ with `requests` library

## Steps

1. Enable Kerberos audit logging on Domain Controllers via Group Policy
2. Forward Event IDs 4768, 4769, and 4771 to SIEM platform
3. Deploy detection rules for RC4 encryption downgrade (TicketEncryptionType 0x17)
4. Create correlation rule for ticket reuse across multiple source IPs
5. Build baseline of normal TGS request volume per user/host
6. Alert on standard deviation anomalies in ticket request patterns
7. Investigate flagged events with enrichment from Active Directory

## Detection Query

Splunk SPL (Steps 3-5): surface users whose service-ticket requests come from many source IPs or include RC4 downgrades.

```spl
index=wineventlog (EventCode=4768 OR EventCode=4769)
| rename Ticket_Encryption_Type as enc, Client_Address as src_ip, Account_Name as user
| eval rc4_downgrade=if(enc=="0x17",1,0)
| stats dc(src_ip) as distinct_src, values(src_ip) as src_ips,
        sum(rc4_downgrade) as rc4_events, count as tgs_requests by user
| where distinct_src > 3 OR rc4_events > 0
| sort - distinct_src
```

## Expected Output

JSON report containing detected PtT indicators including anomalous ticket requests, RC4 downgrades, cross-host ticket reuse events, and risk-scored users with MITRE ATT&CK technique mapping.
