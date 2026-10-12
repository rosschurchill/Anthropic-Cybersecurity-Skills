---
name: detecting-clipboard-data-theft
description: 'Detects clipboard data theft (MITRE T1115) - harvesting copied passwords, MFA codes, and crypto-wallet addresses via clip.exe/Get-Clipboard/GetClipboardData on Windows, pbpaste/pbcopy on macOS, and xclip/xsel/wl-paste on Linux - using an anomalous-context model: clipboard utilities run by non-interactive or abnormal parents, without a terminal session, or tied to launch agents, and chained to staging/exfil (base64, gzip, curl, scp). Uses Sysmon/4688 process-create, PowerShell 4104 script-block logs, clipboard API image loads, macOS ESF exec, and Linux auditd EXECVE. Use when hunting clipboard collection, clipboard scrapers, or crypto-clipper reconnaissance on endpoints. Keywords: clipboard, Get-Clipboard, clip.exe, pbpaste, xclip, xsel, GetClipboardData, OpenClipboard, T1115. Do not use for content-based data-loss monitoring on egress - use detecting-insider-data-exfiltration-via-dlp.'
domain: cybersecurity
subdomain: endpoint-security
tags:
- endpoint-security
- threat-detection
- collection
- clipboard
- credential-theft
- crypto-clipper
- sysmon
- auditd
- t1115
- data-theft
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.DS-01
- PR.PS-01
mitre_attack:
- T1115
- T1056.001
- T1560
- T1074
- T1565.002
---

# Detecting Clipboard Data Theft

## When to Use

Use this skill to detect adversaries **harvesting clipboard contents** — which
frequently carry passwords, MFA codes, crypto-wallet addresses, and copied
secrets (ATT&CK T1115) — via `clip.exe`/`Get-Clipboard`/`GetClipboardData` on
Windows, `pbpaste`/`pbcopy` on macOS, and `xclip`/`xsel`/`wl-paste` on Linux. The
signal is clipboard access from an **anomalous context** (non-interactive or
abnormal parent, no terminal session, tied to a launch agent) and/or **chained
with staging and exfiltration**, rather than ordinary interactive copy/paste.
Reach for it when:

- Hunting clipboard scrapers or crypto-clipper reconnaissance.
- A clipboard utility runs with no TTY or from a service/scheduled-task parent.

For content-based egress data-loss monitoring use
`detecting-insider-data-exfiltration-via-dlp`; keystroke capture (T1056.001) is a
separate keylogging-detection concern.

## Prerequisites

- **Windows**: Sysmon Event ID 1 / Security 4688 for `clip.exe`, `powershell`
  running `Get-Clipboard`, or custom binaries; Sysmon 7 / API telemetry for
  `user32.dll` clipboard APIs (`OpenClipboard`/`GetClipboardData`); PowerShell
  Script Block Logging (4104).
- **macOS**: EndpointSecurity / Unified Log `exec` for `pbpaste`/`pbcopy`.
- **Linux**: `auditd` EXECVE for `xclip`/`xsel`/`wl-paste`.
- Context for all: parent/grandparent process, session/TTY presence, and temporal
  proximity to archive/network activity.
- A **benign baseline** of clipboard use (this detection depends on it).

## Workflow

1. **Baseline benign clipboard use.** Clipboard access is ubiquitous — enumerate
   the normal interactive parents (shells, terminals, clipboard managers) so the
   anomalous-context filter has a reference.
2. **Anomalous-context detection.** Flag clipboard utilities invoked by
   non-interactive/abnormal parents (service, scheduled task, launch agent) or
   **without a terminal session**.
3. **Chaining elevates severity.** Raise severity when the same process tree runs
   `base64`/`gzip`/`curl`/`scp` within a short window (staging/exfil, T1560/T1074).
4. **PowerShell path.** Alert on `Get-Clipboard` in script-block logs (4104),
   especially in encoded or non-interactive scripts.
5. **Clipper handoff (T1565.002).** A process that **both reads and writes** the
   clipboard repeatedly in the background is likely clipper malware swapping
   wallet addresses — flag for handoff (impact tactic), don't fully model here.
6. **Respond** (see *Response*).

## Key Concepts

- **Context is everything:** `Get-Clipboard` from an analyst terminal is benign;
  from a service-spawned, TTY-less process it is collection. The parent/TTY/chain
  filter is what makes this detectable without alert fatigue.
- **Clipboard carries secrets:** password managers and users copy credentials,
  OTPs, and wallet addresses — a single scrape can yield high-value data.
- **Collection vs impact:** reading the clipboard is collection (T1115); *swapping*
  its contents (crypto clipper) is Transmitted Data Manipulation (T1565.002) —
  related fields, different intent.
- **Chaining confirms intent:** clipboard read → archive → egress in one tree is a
  confident collection-to-exfil sequence.

## Tools & Systems

Sysmon + Windows Event Log, PowerShell Script Block Logging, Microsoft Defender
for Endpoint, Sigma, Splunk/Sentinel; macOS EndpointSecurity / `log`; Linux
`auditd`/auditbeat, Falco; osquery; Velociraptor.

## Detection Queries

### Sigma -- clipboard access via CLI (Windows)

```yaml
title: Clipboard Access via Command Line
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  cmd:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'Get-Clipboard'
  clip_exe:
    Image|endswith: '\clip.exe'
  condition: cmd or clip_exe
falsepositives:
  - Interactive admin use (filter by interactive parent / session)
level: medium
```

### KQL -- clipboard tool with no interactive parent (macOS/Linux)

```kql
DeviceProcessEvents
| where FileName in~ ("pbpaste","xclip","xsel","wl-paste")
| where InitiatingProcessFileName !in~ ("bash","zsh","sh","fish","Terminal","iTerm2")
      or isempty(InitiatingProcessFileName)
| project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessFileName
```

### Splunk -- clipboard read chained to staging/exfil

```spl
`sysmon` EventCode=1 (Image="*\\clip.exe" OR CommandLine="*Get-Clipboard*"
    OR Image="*xclip" OR Image="*xsel")
| eval clipTime=_time
| join ParentProcessGuid [ search `sysmon` EventCode=1
    (Image="*base64*" OR Image="*gzip*" OR Image="*curl*" OR Image="*scp*") ]
| where _time>=clipTime AND (_time-clipTime) < 300
| table _time, Computer, User, Image, CommandLine
```

## Common Scenarios

- **Credential scrape:** service-spawned `powershell -enc Get-Clipboard`
  harvests a copied password — anomalous parent fires.
- **Crypto clipper:** background process reads/writes the clipboard to replace
  wallet addresses — flagged for T1565.002 handoff.
- **Linux exfil chain:** `xclip -o | base64 | curl` from a non-TTY process.
- **False positive:** a clipboard manager or an analyst in a terminal — excluded
  by interactive-parent baseline.

## Output Format

```
CLIPBOARD THEFT DETECTION
  Host/user:       <host> / <user>
  Verdict:         <confirmed | suspected | benign-interactive>
  Tool:            <clip.exe | Get-Clipboard | pbpaste | xclip/xsel | clipboard API>
  Context:         <parent process>, TTY <present/absent>
  Chain:           <staging/exfil within Ns | read+write loop (clipper) | none>
  ATT&CK:          T1115[, T1056.001, T1560, T1074, T1565.002]
  Actions taken:   <host isolated | process captured | in-scope secrets rotated>
```

## Response

- **Isolate the host**; capture the collecting process and any staged/exfil
  artifacts; identify what was in scope (credential managers, wallets) and
  **rotate exposed secrets**.
- **Harden:** prefer password managers with auto-type (reduce clipboard
  exposure) and clipboard auto-clear; application control to constrain
  clipboard-reading binaries; restrict clipboard sharing in RDP/VDI and browser
  extensions (NIST CSF PR.DS-01).
- **User guidance:** avoid copying long-lived secrets; enable clipboard-history
  clearing.
