---
name: analyzing-powershell-empire-artifacts
description: Detect PowerShell Empire post-exploitation framework artifacts in Windows
  Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103), including
  the default launcher string, Base64-encoded WebClient/FromBase64String payloads,
  known module invocations (Invoke-Mimikatz, Invoke-Kerberoast), and staging URL patterns.
  Use when hunting for or confirming Empire C2 activity in Windows event logs. Do
  not use for general suspicious-PowerShell detection - use detecting-suspicious-powershell-execution.
domain: cybersecurity
subdomain: threat-hunting
tags:
- PowerShell-Empire
- threat-hunting
- Script-Block-Logging
- base64
- stager
- C2
- MITRE-ATT&CK
- T1059.001
- forensics
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1059.001
- T1071.001
- T1003.001
- T1558.003
- T1027.010
---

# Analyzing PowerShell Empire Artifacts

## Overview

PowerShell Empire is a post-exploitation framework consisting of listeners, stagers, and agents. Its artifacts leave detectable traces in Windows event logs, particularly PowerShell Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103). This skill analyzes event logs for Empire's default launcher string (`powershell -noP -sta -w 1 -enc`), Base64 encoded payloads containing `System.Net.WebClient` and `FromBase64String`, known module invocations (Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation), and staging URL patterns.


## When to Use

- Use when hunting Windows Script Block Logging (Event ID 4104) for the default Empire launcher string `powershell -noP -sta -w 1 -enc` followed by a Base64 blob.
- Use when confirming Empire C2 by decoding Base64 payloads containing `System.Net.WebClient`, `DownloadData`, `DownloadString`, or `FromBase64String`.
- Use when searching Module Logging (Event ID 4103) for known Empire module invocations (Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation, Invoke-PSInject).
- Use when identifying Empire staging URL patterns (e.g. `/login/process.php`, `/admin/get.php`) or default user-agent strings in captured activity.
- Use when triaging exported EVTX from a host suspected of post-exploitation framework activity.

## Prerequisites

- Python 3.9+ with access to Windows Event Log or exported EVTX files
- PowerShell Script Block Logging (Event ID 4104) enabled via Group Policy
- Module Logging (Event ID 4103) enabled for comprehensive coverage

## Key Detection Patterns

1. **Default launcher** — `powershell -noP -sta -w 1 -enc` followed by Base64 blob
2. **Stager indicators** — `System.Net.WebClient`, `DownloadData`, `DownloadString`, `FromBase64String`
3. **Module signatures** — Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation, Invoke-PSInject, Invoke-DCOM
4. **User agent strings** — default Empire user agents in HTTP listener configuration
5. **Staging URLs** — `/login/process.php`, `/admin/get.php` and similar default URI patterns

## Output

JSON report with matched IOCs, decoded Base64 payloads, timeline of suspicious events, MITRE ATT&CK technique mappings, and severity scores.

## Detection Query

Sigma rule matching the Empire launcher and module signatures in Script Block Logging (4104):

```yaml
title: PowerShell Empire Launcher and Module Invocation
id: 9f3d4c21-7a8b-4e16-9c0a-empire-detection
status: experimental
description: Detects PowerShell Empire default launcher string and known module invocations in Script Block Logging
references:
  - https://attack.mitre.org/techniques/T1059/001/
logsource:
  product: windows
  category: ps_script
detection:
  launcher:
    ScriptBlockText|contains:
      - '-noP -sta -w 1 -enc'
      - 'System.Net.WebClient'
      - 'FromBase64String'
  modules:
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Invoke-TokenManipulation'
      - 'Invoke-PSInject'
  condition: launcher or modules
fields:
  - ScriptBlockText
  - Computer
level: high
tags:
  - attack.execution
  - attack.t1059.001
```
