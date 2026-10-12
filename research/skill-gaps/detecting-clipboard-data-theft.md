# Detecting Clipboard Data Theft — research notes

- **Proposed slug:** detecting-clipboard-data-theft
- **ATT&CK:** T1115 Clipboard Data (tactic: collection). Detection strategy: **DET0341** "Clipboard Data Access with Anomalous Context" (created 2025-10-21; analytics AN0965 Windows, AN0966 macOS, AN0967 Linux). No sub-techniques. Related: T1056.001 Keylogging, T1560 Archive Collected Data, T1074 Data Staged, T1565.002 Transmitted Data Manipulation (clipboard hijacking / crypto "clipper" — adjacent, impact-side).
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries harvesting clipboard contents — which frequently carry passwords, MFA codes, crypto-wallet addresses, and copied secrets — via `clip.exe`/`Get-Clipboard`/`GetClipboardData` on Windows, `pbpaste`/`pbcopy` on macOS, and `xclip`/`xsel` on Linux. The signal is clipboard access from an *anomalous context* (non-interactive or abnormal parent process, no terminal session, tied to a launch agent) and/or chained with staging and exfiltration, rather than ordinary interactive copy/paste.

## Data sources / telemetry
- **Windows (AN0965):** Sysmon Event ID **1** / Security **4688** process-create for `clip.exe`, `powershell.exe` running `Get-Clipboard`, or custom binaries; Sysmon **7** (image load) / API telemetry for `user32.dll` clipboard APIs `OpenClipboard`/`GetClipboardData`; parent-process context (service/scheduled-task/non-interactive parent). PowerShell Script Block Logging (Event ID **4104**) for `Get-Clipboard`.
- **macOS (AN0966):** EndpointSecurity / Unified Log `exec` events for `pbpaste`/`pbcopy`, especially with no TTY or launched by a LaunchAgent/LaunchDaemon.
- **Linux (AN0967):** auditd EXECVE for `xclip`/`xsel` (and Wayland `wl-paste`) run outside a user terminal, especially alongside `gzip`, `base64`, `curl`, or `scp`.
- Context for all: parent/grandparent process, session/TTY presence, and temporal proximity to archive/network activity.

## Detection logic / approach
Per DET0341: flag clipboard utilities invoked by non-interactive/abnormal parents or without a terminal session, and raise severity when chained to staging/exfil.

Sigma (Windows, Get-Clipboard via CLI — adapted from community rule):
```yaml
detection:
  cmd:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'Get-Clipboard'
  clip_exe:
    Image|endswith: '\clip.exe'
  condition: cmd or clip_exe
```
KQL (macOS/Linux clipboard tool with no terminal, Defender/syslog):
```kql
DeviceProcessEvents
| where FileName in~ ("pbpaste","xclip","xsel","wl-paste")
| where InitiatingProcessFileName !in~ ("bash","zsh","sh","fish","Terminal","iTerm2")
      or isempty(InitiatingProcessFileName)
```
Elevate when the same process tree subsequently runs `base64`/`gzip`/`curl`/`scp` (T1560/T1041) within a short window. For clipboard *hijacking* (clipper malware swapping copied wallet addresses — T1565.002), monitor processes that both read and write the clipboard repeatedly in the background; this is adjacent and should be flagged for handoff, not fully modeled here.

## Response / mitigation
- Isolate the host; capture the collecting process and any staged/exfil artifacts; identify what was in scope (credential managers, wallets).
- Hardening: prefer password managers with auto-type (reduce clipboard exposure) and clipboard auto-clear; application control / WDAC to constrain clipboard-reading binaries; restrict clipboard sharing in RDP/VDI and browser extensions; EDR rules on anomalous clipboard API use.
- User guidance: avoid copying long-lived secrets; enable clipboard history clearing.

## Real tools
Sysmon + Windows Event Log, PowerShell Script Block Logging, Microsoft Defender for Endpoint (DeviceProcessEvents), Sigma + sigmac, Splunk/Sentinel; macOS EndpointSecurity / `log` + ESF agents; Linux auditd/auditbeat, Falco; osquery process events; Velociraptor for triage.

## Draft frontmatter mappings
- mitre_attack: [T1115, T1056.001, T1560, T1074, T1565.002]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, PR.DS-01, PR.PS-01]
- suggested subdomain: endpoint-security
- nearest existing sibling (for the negative trigger): detecting-insider-data-exfiltration-via-dlp

## Draft description (<=1024 chars)
Detects clipboard data theft (T1115) — harvesting copied passwords, MFA codes, and wallet addresses via clip.exe/Get-Clipboard/GetClipboardData on Windows, pbpaste/pbcopy on macOS, and xclip/xsel/wl-paste on Linux — using DET0341's anomalous-context model: clipboard utilities run by non-interactive or abnormal parents, without a terminal session, or tied to launch agents, and chained to staging/exfil (base64, gzip, curl, scp). Uses Sysmon/4688 process-create, PowerShell 4104 script-block logs, clipboard API image loads, macOS ESF exec, and Linux auditd EXECVE. Use when hunting clipboard collection, clipboard scrapers, or crypto clipper reconnaissance on endpoints. Keywords: clipboard, Get-Clipboard, clip.exe, pbpaste, xclip, xsel, GetClipboardData, OpenClipboard, T1115, DET0341. Do not use for content-based data-loss monitoring on egress (use detecting-insider-data-exfiltration-via-dlp) or keystroke capture (use a keylogging-detection skill).

## Key references
- https://attack.mitre.org/techniques/T1115/
- https://attack.mitre.org/detectionstrategies/DET0341
- https://github.com/SigmaHQ/sigma (community Get-Clipboard / clipboard rules)
- https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-operations (clipboard APIs)

## Open questions / scope boundaries
- Clipboard access is extremely common and benign; the skill lives or dies on the "anomalous context" filter (parent process / TTY / chaining). Author must specify a concrete benign baseline to avoid alert fatigue.
- Decide how much clipboard-*hijacking* (T1565.002 clipper malware) to include vs. hand off — the detection fields overlap but the intent/tactic differs (impact vs. collection).
- Must NOT duplicate DLP egress monitoring (sibling) or keylogging detection (T1056.001); this is the on-host collection step.
- Verify DET0341 analytic IDs (AN0965/0966/0967) are current in v19.2 before citing them in frontmatter.
