---
name: hunting-for-lateral-movement-via-wmi
description: Detects WMI-based lateral movement (e.g. wmic process call create, Win32_Process.Create())
  by analyzing Windows Event ID 4688 and Sysmon Event ID 1 for WmiPrvSE.exe spawning suspicious
  child processes like cmd.exe or powershell.exe, plus WMI-Activity/Operational events 5857/5860/5861
  for subscription-based persistence. Use when hunting for remote code execution via WMI or investigating
  lateral movement across Windows hosts. Do not use for DCOM-based lateral movement hunting -
  use hunting-for-dcom-lateral-movement.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- lateral-movement
- wmi
- sysmon
- mitre-attack
- process-creation
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
- T1021
---
# Hunting for Lateral Movement via WMI

## Overview

Windows Management Instrumentation (WMI) is commonly abused for lateral movement via `wmic process call create` or Win32_Process.Create() to execute commands on remote hosts. Detection focuses on identifying WmiPrvSE.exe spawning child processes (cmd.exe, powershell.exe) in Windows Security Event ID 4688 and Sysmon Event ID 1 logs, along with WMI-Activity/Operational events (5857, 5860, 5861) for event subscription persistence.


## When to Use

- Use when hunting remote code execution via `wmic process call create` or `Win32_Process.Create()` across Windows hosts.
- Use when flagging WmiPrvSE.exe spawning cmd.exe or powershell.exe in Event ID 4688 or Sysmon Event ID 1.
- Use when triaging WMI-Activity/Operational events 5857/5860/5861 for subscription-based (event consumer) persistence.
- Use when spotting WMI lateral-movement command lines (`cmd.exe /q /c`, output redirection to the ADMIN$ share).
- Use when validating detection coverage for WMI lateral movement during incident response.

## Prerequisites

- Windows Security Event Logs with Process Creation auditing enabled (Event 4688 with command line)
- Sysmon installed with Event ID 1 (Process Creation) configured
- Python 3.9+ with `python-evtx`, `lxml` libraries
- Understanding of WMI architecture and WmiPrvSE.exe behavior

## Steps

### Step 1: Parse Process Creation Events
Extract Event ID 4688 and Sysmon Event 1 entries from EVTX files.

### Step 2: Detect WmiPrvSE Child Processes
Flag processes where ParentImage/ParentProcessName is WmiPrvSE.exe, indicating remote WMI execution.

### Step 3: Analyze Command Line Patterns
Identify suspicious command lines matching WMI lateral movement patterns (cmd.exe /q /c, output redirection to admin$ share).

### Step 4: Check WMI Event Subscriptions
Parse WMI-Activity/Operational log for event consumer creation indicating persistence.

## Example

Sigma rule for WmiPrvSE.exe spawning a command interpreter — the core signal of remote
WMI process creation:

```yaml
title: WMI Lateral Movement - WmiPrvSE Spawns Command Interpreter
id: 9a1c7f2e-5b3d-4a21-9e8c-1f4d2b6a0c11
status: experimental
description: Detects WmiPrvSE.exe spawning cmd.exe or powershell.exe, indicating
  remote process creation via wmic process call create or Win32_Process.Create().
references:
  - https://attack.mitre.org/techniques/T1021/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  suspicious_cmd:
    CommandLine|contains:
      - '/q /c'
      - '\\ADMIN$'
      - '2>&1'
  condition: selection and suspicious_cmd
falsepositives:
  - Legitimate software deployment or monitoring tools that use WMI
level: high
tags:
  - attack.lateral_movement
  - attack.t1021
```

## Expected Output

JSON report with WMI-spawned processes, suspicious command lines, WMI event subscription alerts, and timeline of lateral movement activity.
