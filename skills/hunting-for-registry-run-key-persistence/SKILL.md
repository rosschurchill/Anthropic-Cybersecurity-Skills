---
name: hunting-for-registry-run-key-persistence
description: >-
  Detect MITRE ATT&CK T1547.001 registry Run key persistence by analyzing Sysmon Event ID 13
  logs and registry queries to identify malicious auto-start entries. Use when hunting
  Run/RunOnce auto-start persistence, triaging Sysmon registry-modification events,
  investigating a suspected persistence mechanism after initial access, or validating
  detection coverage for registry-based autostart. Keywords: T1547.001, Run key, RunOnce,
  Sysmon Event ID 13, registry, auto-start, HKCU, HKLM, persistence. Do not use for registry
  persistence beyond Run keys (services, AppInit, image hijacks) — use
  hunting-for-registry-persistence-mechanisms.
domain: cybersecurity
subdomain: threat-hunting
tags:
- persistence
- registry-run-keys
- t1547-001
- sysmon
- threat-hunting
- windows-forensics
- mitre-attack
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
- T1046
- T1057
- T1082
- T1083
- T1547
---
# Hunting for Registry Run Key Persistence

## Overview

Registry Run keys (T1547.001) are one of the most commonly used persistence mechanisms by adversaries. When a program is added to a Run key in the Windows registry, it executes automatically when a user logs in. Attackers abuse keys under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, and their RunOnce counterparts to maintain persistence. Sysmon Event ID 13 (RegistryEvent - Value Set) captures registry value modifications including the target object path, the process that made the change, and the new value. Detection involves monitoring these events for suspicious executables in temp directories, encoded PowerShell commands, LOLBin paths, and processes that do not normally create Run key entries. Chaining Event 13 with Event 1 (Process Creation) and Event 11 (FileCreate) strengthens detection by confirming payload creation and execution.


## When to Use

- Use when hunting T1547.001 Run/RunOnce auto-start persistence in Sysmon Event ID 13 (RegistryEvent - Value Set).
- Use when triaging a Run key whose value points at a temp directory, AppData, or ProgramData, or contains an encoded PowerShell command.
- Use when flagging LOLBin abuse (mshta.exe, rundll32.exe, regsvr32.exe, wscript.exe) registered under a Run key.
- Use when the modifying process (Image) is itself suspicious (cmd.exe, powershell.exe, python.exe) rather than an installer.
- Use when chaining Event 13 with Event 1 (Process Creation) and Event 11 (FileCreate) to confirm a recently dropped payload was registered for autostart.

## Prerequisites

- Windows systems with Sysmon installed and configured to log Event ID 13
- Sysmon config with RegistryEvent rules for Run/RunOnce keys
- Python 3.9+ with `json`, `xml.etree.ElementTree`, `re` modules
- SIEM or log aggregator collecting Sysmon logs (Splunk, Elastic, Sentinel)
- Knowledge of legitimate auto-start programs for baseline comparison

## Steps

1. Collect Sysmon Event ID 13 logs filtered for Run/RunOnce key paths
2. Parse event XML/JSON for TargetObject, Details (value written), Image (modifying process)
3. Flag entries where the value points to temp directories, AppData, or ProgramData
4. Detect encoded PowerShell commands or script interpreters in registry values
5. Identify LOLBin abuse (mshta.exe, rundll32.exe, regsvr32.exe, wscript.exe)
6. Compare against known-good baseline of legitimate auto-start entries
7. Check if the modifying process (Image) is unusual (cmd.exe, powershell.exe, python.exe)
8. Chain with Event ID 1 to verify if the registered binary was recently created
9. Generate detection report with MITRE ATT&CK mapping and severity scores
10. Produce Sigma/Splunk detection rules from findings

## Example

Sigma rule over Sysmon Event ID 13 that fires on a Run/RunOnce value pointing at a
suspicious path or interpreter:

```yaml
title: Suspicious Run Key Value Set (T1547.001)
id: 3f2b8c6d-7a14-4e92-bc05-2d9f1a4e6b78
status: experimental
description: Detects Run/RunOnce registry values written with a payload in a temp path,
  AppData, or an encoded PowerShell/LOLBin command, via Sysmon Event ID 13.
references:
  - https://attack.mitre.org/techniques/T1547/001/
logsource:
  product: windows
  category: registry_set
detection:
  selection_key:
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
  selection_value:
    Details|contains:
      - '\AppData\'
      - '\Temp\'
      - '\ProgramData\'
      - '-enc'
      - '-EncodedCommand'
      - 'mshta'
      - 'rundll32'
      - 'regsvr32'
  condition: selection_key and selection_value
falsepositives:
  - Legitimate installers writing autostart entries
level: high
tags:
  - attack.persistence
  - attack.t1547.001
```

## Expected Output

A JSON report listing suspicious Run key entries with the registry path, value written, modifying process, timestamp, MITRE technique mapping, severity rating, and recommended Sigma detection rules.
