---
name: detecting-adversary-log-enumeration
description: 'Detects adversary log enumeration (MITRE T1654) - abnormal use of wevtutil, Get-WinEvent/Get-EventLog, wmic/WMI Win32_NTLogEvent, and Linux reads of /var/log (auth.log, secure, wtmp, journalctl) - by correlating native log-reading tools, sensitive channel targets (Security/System), non-SOC accounts, and follow-on log export or clearing, using Windows Event ID 4688/4104/4663 and auditd telemetry. Use when hunting discovery activity where an attacker inspects event/audit logs to find monitoring coverage, admin activity, or evidence before clearing it. Keywords: log enumeration, wevtutil qe, Get-WinEvent, Win32_NTLogEvent, journalctl, auth.log discovery, Event ID 4663, T1654. Do not use for detecting the actual clearing or tampering of logs after enumeration - use detecting-evasion-techniques-in-endpoint-logs.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- log-enumeration
- discovery
- wevtutil
- powershell
- auditd
- windows-events
- t1654
- endpoint-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-03
- DE.AE-02
- PR.PS-04
- PR.DS-01
mitre_attack:
- T1654
- T1070.001
- T1082
---

# Detecting Adversary Log Enumeration

## When to Use

Use this skill to detect adversaries **enumerating event and audit logs**
(ATT&CK T1654) to find security-tooling coverage, admin activity, credentials in
logs, or evidence to later clear. It flags abnormal use of native log-reading
utilities and APIs — especially against Security/System channels by non-admin or
non-SOC accounts — and correlates enumeration with subsequent export or clearing.
Log enumeration often immediately precedes defense evasion (log clearing) or
targeted lateral movement. Reach for it when:

- Hunting discovery activity on endpoints.
- `wevtutil`/`Get-WinEvent`/`journalctl` runs from an unexpected account or parent.

For detecting the **clearing/tampering** of logs after enumeration, use
`detecting-evasion-techniques-in-endpoint-logs`.

## Prerequisites

- **Windows process creation**: Security Event ID 4688 (and Sysmon Event ID 1)
  with full command line.
- **PowerShell** Script Block (4104) and Module (4103) logging.
- **Windows object/file access auditing**: Event ID 4663/4656/4670 on `.evtx`
  files under `C:\Windows\System32\winevt\Logs\`.
- **Linux**: `auditd` EXECVE/process telemetry and file-access rules on
  `/var/log`.
- A strong **SOC/admin/backup account allowlist** and parent-process baseline
  (this detection is false-positive-prone without it).

## Workflow

1. **Baseline legitimate log readers.** SOC tooling, backup agents, and admins
   read logs constantly — enumerate those accounts, service principals, and their
   normal parent processes first.
2. **Native log-tool invocation with sensitive targets.** Alert on `wevtutil qe`/
   `el`, `wmic nteventlog`, `Get-WinEvent`/`Get-EventLog`, and WMI
   `Win32_NTLogEvent` queries — especially against the **Security** channel.
3. **Actor-baseline correlation.** Raise severity when the invoking account is
   **not** in the allowlist, or the enumerating process has an unusual parent
   (Office, browser, script interpreter).
4. **Enumeration → export chain.** Correlate `wevtutil epl` / `Get-WinEvent |
   Export-Clixml` / a log copy to a staging dir, followed by archive or network
   transfer within a short window.
5. **Enumeration → clearing chain (high confidence).** A read of the Security
   channel shortly before **Event ID 1102** (audit log cleared) or `wevtutil cl`.
6. **Linux.** Watch for non-root interactive reads of `/var/log/wtmp`,
   `auth.log`/`secure`, or `journalctl -u` enumeration.
7. **Respond** (see *Response*).

## Key Concepts

- **Enumeration is reconnaissance of your visibility:** the attacker is checking
  what you log before acting or clearing — catching it is an early warning.
- **The account and parent matter more than the tool:** `Get-WinEvent` is benign
  from SOC automation and suspicious from a macro-spawned shell.
- **Read-before-clear is the strongest sequence:** Security-channel enumeration
  immediately before 1102/`wevtutil cl` is a near-certain malicious chain.
- **Off-host logging defeats the goal:** if logs are already forwarded, local
  enumeration/clearing cannot destroy the evidence.

## Tools & Systems

`wevtutil`, `Get-WinEvent`, `Get-EventLog`, `wmic`, `auditd`/`ausearch`,
`journalctl`, Sysmon, Splunk, Sigma, osquery, Windows Event Forwarding (WEF).

## Detection Queries

### Sigma -- native log enumeration tools (Windows)

```yaml
title: Windows Event Log Enumeration
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection_wevtutil:
    Image|endswith: '\wevtutil.exe'
    CommandLine|contains: ['qe','query-events','el','enum-logs']
  selection_wmic:
    Image|endswith: '\wmic.exe'
    CommandLine|contains: 'nteventlog'
  selection_ps:
    CommandLine|contains: ['Get-WinEvent','Get-EventLog','Win32_NTLogEvent']
  condition: 1 of selection_*
falsepositives:
  - SOC tooling, backup agents, administrators
level: medium
```

### Splunk -- enumeration by a non-allowlisted account, then 1102

```spl
`wineventlog_security` EventCode=4688 (New_Process_Name="*\\wevtutil.exe" OR New_Process_Name="*\\wmic.exe")
| search NOT [ | inputlookup soc_admin_accounts | fields Account_Name ]
| eval enumTime=_time
| join Computer [ search `wineventlog_security` EventCode=1102 | eval clearTime=_time ]
| where clearTime>=enumTime AND (clearTime-enumTime) < 600
| table _time, Computer, Account_Name, enumTime, clearTime
```

### Linux -- auditd for /var/log reads by non-root

```
-w /var/log/auth.log -p r -k log_enum
-w /var/log/wtmp -p r -k log_enum
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/journalctl -k log_enum
```

## Common Scenarios

- **Read-then-clear:** attacker runs `wevtutil qe Security` then `wevtutil cl
  Security` — the join query fires.
- **Creds in logs:** `Get-WinEvent` scraping for plaintext secrets in event data.
- **Linux recon:** a web-shell user `cat /var/log/auth.log` to see who logs in.
- **False positive:** nightly backup agent exporting `.evtx` — allowlisted by
  account.

## Output Format

```
LOG ENUMERATION DETECTION
  Host/user:       <host> / <account>
  Verdict:         <confirmed | suspected | allowlisted-reader>
  Tool:            <wevtutil qe | Get-WinEvent | Win32_NTLogEvent | journalctl | /var/log read>
  Target:          <Security channel | auth.log | wtmp | ...>
  Parent:          <parent process> (expected: <y/n>)
  Follow-on:       <export/transfer | 1102 clearing | none>
  ATT&CK:          T1654[, T1070.001, T1082]
  Actions taken:   <host snapshot | logs preserved off-host | clearing hunted>
```

## Response

- **Forward logs off-host in real time** (WEF/Winlogbeat, rsyslog/syslog-ng to a
  SIEM) so local enumeration/clearing cannot destroy evidence (NIST CSF
  PR.PS-04).
- Restrict read access to the Security channel; enable tamper-resistant/immutable
  log storage.
- **On detection:** snapshot the host, preserve `.evtx`/`/var/log`, hunt for
  follow-on clearing (Event ID 1102) and credential-in-log exposure, and treat as
  discovery preceding further intrusion.
