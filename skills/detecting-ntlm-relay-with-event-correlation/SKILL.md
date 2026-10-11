---
name: detecting-ntlm-relay-with-event-correlation
description: >-
  Detect NTLM relay attacks (T1557.001) by correlating Windows Event 4624 LogonType 3 for
  IP-to-hostname mismatches, identifying Responder/LLMNR poisoning artifacts, auditing SMB/LDAP
  signing, and flagging NTLMv2-to-NTLMv1 downgrades. Use for hunting credential relay in
  NTLM-enabled AD, investigating auth-source anomalies, building SIEM correlation rules, or
  responding to PetitPotam/DFSCoerce/PrinterBug alerts. Do not use for proactive NTLM relay
  threat hunting - use hunting-for-ntlm-relay-attacks.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- NTLM-relay
- event-correlation
- T1557.001
- Event-4624
- Responder
- SMB-signing
- LDAP-signing
- NTLM-downgrade
- PetitPotam
- Active-Directory
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0051
- AML.T0054
- AML.T0056
- AML.T0020
d3fend_techniques:
- Application Protocol Command Analysis
- Network Isolation
- Network Traffic Analysis
- Client-server Payload Profiling
- Network Traffic Community Deviation
nist_ai_rmf:
- MEASURE-2.7
- MEASURE-2.5
- GOVERN-6.1
- MAP-5.1
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
- T1069
---

# Detecting NTLM Relay with Event Correlation

> **Authorized Testing Disclaimer**: The offensive techniques and attack simulations described in this skill are intended exclusively for authorized penetration testing, red team engagements, purple team exercises, and security research conducted with explicit written permission from the system owner. Unauthorized use of these techniques against systems you do not own or have permission to test is illegal and unethical. Always operate within the scope of your engagement and comply with applicable laws and regulations.

## Overview

NTLM relay attacks intercept NTLM authentication messages and forward them to a target service to gain unauthorized access. Attackers use tools like Responder for LLMNR/NBT-NS/mDNS poisoning, ntlmrelayx (Fox-IT/Impacket) for multi-protocol relay, and coercion techniques like PetitPotam (MS-EFSRPC) and DFSCoerce to force authentication from high-value targets like domain controllers. This skill provides a comprehensive event correlation framework using Windows Security Event 4624 LogonType 3 analysis, IP-to-hostname mismatch detection, Responder traffic identification, SMB/LDAP signing audit, and NTLM downgrade detection to identify relay attacks across Active Directory environments.

## When to Use

- Hunting for credential relay activity in Active Directory environments where NTLM authentication is still in use
- Investigating alerts for authentication anomalies where the source IP does not match the expected workstation
- Auditing SMB signing and LDAP signing enforcement to assess exposure to relay attacks
- Detecting NTLM downgrade attacks where NTLMv2 is forced to NTLMv1 for easier offline cracking or relay
- Building SIEM correlation rules for MITRE ATT&CK T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)
- Responding to PetitPotam, DFSCoerce, or PrinterBug coercion alerts that may precede relay attacks
- During purple team exercises validating NTLM relay detection and SMB signing enforcement

**Do not use** without centralized Windows Security Event Log collection, as a substitute for enforcing SMB signing and Extended Protection for Authentication (EPA) which prevent relay attacks at the protocol level, or without an IP-to-hostname inventory for correlation.

## Prerequisites

- Windows Advanced Audit Policy configured to capture Event IDs 4624, 4625, 4648, 4776, and 8004
- Centralized log collection via Windows Event Forwarding (WEF) or agent-based shipping to SIEM
- SIEM platform (Splunk, Elastic, Microsoft Sentinel) with correlation and alerting capability
- IP address to hostname mapping inventory (DHCP logs, DNS records, or CMDB)
- Network monitoring for LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353) traffic
- Understanding of MITRE ATT&CK T1557.001 and T1187 (Forced Authentication)

## Workflow

### Step 1: Understand NTLM Relay Attack Flow

The NTLM relay attack follows a three-phase pattern: coercion/poisoning, interception, and relay.

**Phase 1 -- Coercion or Poisoning**: The attacker forces or tricks a victim into initiating NTLM authentication. Methods include LLMNR/NBT-NS poisoning (Responder), PetitPotam (MS-EFSRPC abuse), PrinterBug (SpoolService), and DFSCoerce.

**Phase 2 -- Interception**: The attacker captures the NTLM Type 1 (Negotiate) and Type 3 (Authenticate) messages from the victim.

**Phase 3 -- Relay**: The attacker forwards the captured NTLM messages to a target service (SMB, LDAP, HTTP, MSSQL) to authenticate as the victim. This succeeds only when message signing is not enforced.

```
Victim ──NTLM Negotiate──> Attacker ──NTLM Negotiate──> Target
Victim <──NTLM Challenge── Attacker <──NTLM Challenge── Target
Victim ──NTLM Authenticate──> Attacker ──NTLM Authenticate──> Target
                                                         ↓
                                              Attacker authenticated
                                              as Victim on Target
```

**Key Detection Insight**: In a relay attack, Event 4624 on the target will show the victim's username but the attacker's IP address. The WorkstationName field may still reflect the victim's machine. This IP-to-hostname mismatch is the primary detection signal.

### Step 2: Event 4624 LogonType 3 Analysis for Relay Detection

See [references/event-4624-queries.md](references/event-4624-queries.md) for the full Splunk SPL and Sentinel KQL Event 4624 relay-detection queries.

### Step 3: Responder Detection via Network and Event Analysis

See [references/responder-detection.md](references/responder-detection.md) for the full Responder LLMNR/NBT-NS detection queries, PowerShell checks, and Sigma rule.

### Step 4: SMB Signing Enforcement Audit

See [references/smb-ldap-signing-audit.md](references/smb-ldap-signing-audit.md) for the full SMB and LDAP signing audit scripts and queries.

### Step 5: NTLM Downgrade Detection

See [references/ntlm-downgrade-detection.md](references/ntlm-downgrade-detection.md) for the full NTLMv1 downgrade detection queries and scripts.

### Step 6: NTLM Audit and Restriction Policy Configuration

See [references/ntlm-audit-policy.md](references/ntlm-audit-policy.md) for the full NTLM auditing and restriction policy configuration.

### Step 7: PetitPotam and Coercion Attack Detection

See [references/coercion-detection.md](references/coercion-detection.md) for the full PetitPotam/coercion detection queries and Sigma rule.

### Step 8: Build Comprehensive Correlation Dashboard

See [references/correlation-dashboard.md](references/correlation-dashboard.md) for the full combined correlation dashboard queries.

## Key Concepts, Tools, Scenarios, and Output Format

See [references/reference-and-scenarios.md](references/reference-and-scenarios.md) for the Key Concepts glossary, Tools & Systems, Common Scenarios, and the full Output Format example.