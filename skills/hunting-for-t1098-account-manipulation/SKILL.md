---
name: hunting-for-t1098-account-manipulation
description: Hunts for MITRE ATT&CK T1098 account manipulation - shadow admin creation, SID history
  injection, group membership changes, and credential modifications - by analyzing Windows Security
  Event Log IDs 4738, 4728, 4732, 4756, 4670, and 5136. Use when investigating suspected privilege
  persistence in Active Directory, after detecting anomalous group/credential changes, or during
  incident response to trace account tampering. Do not use for service-account abuse detection
  - use detecting-service-account-abuse.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- t1098
- account-manipulation
- active-directory
- persistence
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Restore Access
- Application Protocol Command Analysis
- Password Authentication
- Biometric Authentication
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
- T1003
---
# Hunting for T1098 Account Manipulation

## Overview

MITRE ATT&CK T1098 (Account Manipulation) covers adversary actions to maintain or expand access to compromised accounts, including adding credentials, modifying group memberships, SID history injection, and creating shadow admin accounts. This skill covers detecting these techniques through Windows Security Event Log analysis (Event IDs 4738, 4728, 4732, 4756, 4670, 5136), correlating group membership changes with privilege escalation indicators, and identifying anomalous account modification patterns.


## When to Use

- Use when investigating suspected privilege persistence in Active Directory via shadow-admin creation or SID history injection.
- Use when triaging Windows Security Event IDs 4738 (account changed), 4728/4732/4756 (member added to security groups), 4670 (permissions changed), and 5136 (directory object modified).
- Use when flagging additions to Domain Admins, Enterprise Admins, Schema Admins, Administrators, or Backup Operators.
- Use when detecting accounts that gain AdminSDHolder protection or direct privilege assignment after initial access.
- Use when correlating account/credential changes with authentication events to reconstruct the compromise-to-persistence timeline.

## Prerequisites

- Windows Security Event Logs (EVTX format) or SIEM access
- Python 3.9+ with `python-evtx`, `lxml` libraries
- Understanding of Active Directory group structure and SID architecture
- Familiarity with MITRE ATT&CK T1098 sub-techniques

## Steps

### Step 1: Parse Account Modification Events
Extract Event IDs 4738 (user account changed), 4728/4732/4756 (member added to security groups), and 5136 (directory service object modified).

### Step 2: Detect Privileged Group Changes
Flag additions to Domain Admins, Enterprise Admins, Schema Admins, Administrators, and Backup Operators groups.

### Step 3: Identify Shadow Admin Indicators
Detect accounts receiving AdminSDHolder protection, direct privilege assignment, or SID history injection.

### Step 4: Correlate with Attack Timeline
Cross-reference account changes with authentication events to identify initial compromise and persistence establishment.

## Example

Sigma rule that fires when a member is added to a highly privileged group (Event ID 4728/4732/4756):

```yaml
title: Member Added to Privileged Group (T1098)
id: c4e1a9b7-2f36-4d58-8a0e-6b3f1d7c2e90
status: experimental
description: Detects additions to Domain Admins, Enterprise Admins, Schema Admins,
  Administrators, or Backup Operators via Windows Security Event IDs 4728/4732/4756.
references:
  - https://attack.mitre.org/techniques/T1098/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4728   # member added to global security group
      - 4732   # member added to local security group
      - 4756   # member added to universal security group
    TargetUserName:
      - 'Domain Admins'
      - 'Enterprise Admins'
      - 'Schema Admins'
      - 'Administrators'
      - 'Backup Operators'
  condition: selection
falsepositives:
  - Authorized administrative onboarding changes
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1098
```

## Expected Output

JSON report with detected account manipulation events, privileged group changes, shadow admin indicators, and timeline correlation.
