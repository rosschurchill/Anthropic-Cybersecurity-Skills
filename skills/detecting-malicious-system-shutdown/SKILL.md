---
name: detecting-malicious-system-shutdown
description: 'Detects malicious system shutdown/reboot (MITRE T1529) - forced, remote, unauthorized, or mass shutdowns used to interrupt availability or finalize destructive attacks - by correlating Windows shutdown command execution (shutdown.exe /r /s /f, Restart-Computer, Stop-Computer) and Linux shutdown/reboot/poweroff execve with host-status events (Event ID 1074/6006/6008/41, systemd-logind, wtmp) and cloud power-control API calls (CloudTrail StopInstances/RebootInstances). Flags shutdowns outside change windows and clustered across many hosts. Use when triaging unexpected reboots, mass outages, or shutdown-command alerts, especially alongside wiper or ransomware signals. Keywords: system shutdown, reboot, shutdown.exe, Event ID 1074, Kernel-Power 41, mass shutdown, StopInstances, T1529. Do not use for the disk-wipe or boot-sector destruction that may precede a reboot - use detecting-disk-wipe-and-destruction.'
domain: cybersecurity
subdomain: soc-operations
tags:
- soc-operations
- threat-detection
- system-shutdown
- reboot
- availability
- destructive-attack
- windows-events
- t1529
- incident-response
- cloudtrail
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- RS.MI-01
- PR.AA-05
mitre_attack:
- T1529
- T1490
- T1561
---

# Detecting Malicious System Shutdown

## When to Use

Use this skill to detect and respond to adversaries who **shut down or reboot
systems** to interrupt availability, deny access, or complete a destructive
operation (ATT&CK T1529) — for example, a reboot that finalizes a wiper after the
MBR is corrupted, or a mass shutdown to disrupt operations. Reach for it when:

- Hosts reboot or power off unexpectedly, or a mass outage hits many hosts at
  once.
- A shutdown/reboot command alert fires, especially forced (`/f`) or remote
  (`/m \\host`).
- You are triaging a destructive incident and need to catch the shutdown step.

For the disk-wipe / boot-sector destruction that may *precede* the reboot, use
`detecting-disk-wipe-and-destruction`.

## Prerequisites

- **Windows System log**: Event ID **1074** (clean shutdown/restart initiated —
  records process, user, reason), **6006** (clean shutdown marker), **6008**
  (unexpected/dirty shutdown), **41** (Kernel-Power — rebooted without clean
  shutdown). Confirm the channel in your environment (normally System).
- **Process creation**: Security **4688** (with command line) or Sysmon Event
  ID 1; PowerShell script-block logging (4104).
- **Linux/macOS**: `auditd` execve of `shutdown`/`reboot`/`halt`/`poweroff`/
  `systemctl reboot`/`init 0|6`; `wtmp`/`last`, `auth.log`, systemd-logind.
- **Cloud/virtualization**: CloudTrail `StopInstances`/`RebootInstances`, Azure
  `deallocate`/`restart`, vCenter power-off.
- A **change/maintenance-window** reference to suppress approved reboots.

## Workflow

1. **Record approved reboot context** — patch windows, the patching service
   account, and admin/helpdesk roles allowed to reboot.
2. **Hunt shutdown/reboot execution.** Query process events for `shutdown.exe`
   (`/s`, `/r`, `/f`, `/t`), `Restart-Computer`, `Stop-Computer`,
   `shutdown /r /m \\host`, `wmic os ... reboot`, and Linux shutdown/reboot
   execve.
3. **Authoritative who/why.** Use Event ID **1074** for the initiating process,
   user and reason. Use **6008/41** to catch dirty shutdowns that *no* clean
   command explains (possible forced crash/BSOD).
4. **Weight the severity.** Multipliers: forced (`/f`), remote (`/m \\host`),
   initiated by a non-admin or service account, outside a change window, and —
   highest — **many hosts shutting down in a short window** or shutdown preceded
   by wiper/ransomware indicators.
5. **Cloud control-plane.** Flag `StopInstances`/`deallocate` by unexpected
   principals or at scale.
6. **Respond** (see *Response*) — in a destructive context do **not** auto power
   systems back on until integrity is verified.

## Key Concepts

- **1074 is the key record:** it names the process, user and reason for a clean
  shutdown — the fastest way to separate an admin reboot from an attacker one.
- **Dirty shutdowns (6008/41)** with no matching command can indicate a forced
  crash or power manipulation, not a graceful reboot.
- **Mass + off-hours + forced** is the high-confidence malicious pattern; a lone
  admin reboot in a change window is benign.
- **Co-occurs with destruction:** T1529 frequently pairs with T1490 (Inhibit
  System Recovery) and T1561 (Disk Wipe) — a reboot right after those is the
  destructive payoff.

## Tools & Systems

Windows Event Log (System/Security), Sysmon, Splunk Security Content
(research.splunk.com), Sigma/SigmaHQ, Microsoft Sentinel (KQL), `auditd`,
systemd `journalctl`, AWS CloudTrail / Azure Activity Log, osquery.

## Detection Queries

### Splunk -- suspicious shutdown/reboot command

```spl
(`sysmon` EventCode=1) OR (`wineventlog_security` EventCode=4688)
| eval img=lower(coalesce(Image,New_Process_Name)), cl=coalesce(CommandLine,Process_Command_Line)
| where (img LIKE "%\\shutdown.exe" AND match(cl,"(?i)\s/(s|r)\b"))
     OR match(cl,"(?i)(Restart-Computer|Stop-Computer|ExitWindowsEx|InitiateSystemShutdown)")
| eval forced=if(match(cl,"(?i)\s/f\b"),1,0), remote=if(match(cl,"(?i)/m\s+\\\\"),1,0)
| stats values(cl) as cmd min(_time) as t by host, user, forced, remote
| eval severity=case(remote==1 OR forced==1,"high",1==1,"medium")
```

### KQL -- mass shutdown across hosts (1074) in a short window

```kql
Event
| where EventLog == "System" and EventID == 1074
| extend d = parse_xml(EventData)
| summarize hosts = dcount(Computer), hostList = make_set(Computer, 50)
    by bin(TimeGenerated, 5m)
| where hosts >= 5     // many hosts rebooting together = suspicious
```

### Linux -- auditd for shutdown/reboot

```
-w /sbin/shutdown -p x -k power_change
-w /sbin/reboot   -p x -k power_change
-w /sbin/poweroff -p x -k power_change
-w /bin/systemctl -p x -k power_change
```

### KQL -- cloud power-off by unexpected principal

```kql
AWSCloudTrail
| where EventName in ("StopInstances","RebootInstances","TerminateInstances")
| extend principal = tostring(UserIdentity.arn)
| where principal !has "role/ops-automation"
| summarize instances = count() by principal, EventName, bin(TimeGenerated, 5m)
| where instances >= 3
```

## Common Scenarios

- **Wiper finale:** `shutdown /r /f /t 0` right after MBR corruption — reboot
  completes the brick. Correlate with disk-wipe indicators.
- **Mass remote shutdown:** attacker with admin creds runs `shutdown /r /m \\*`
  across a subnet — 1074 across many hosts in minutes.
- **Cloud disruption:** stolen keys call `StopInstances` on production fleet.
- **False positive:** monthly patch reboot by the patching service account in the
  change window — suppressed by context.

## Output Format

```
SYSTEM SHUTDOWN DETECTION
  Scope:           <single host | N hosts>
  Verdict:         <confirmed | suspected | approved-maintenance>
  Command:         <shutdown.exe /r /f | Restart-Computer | StopInstances | dirty (6008/41)>
  Initiator:       <user/principal> (role: <admin|service|standard>)
  Flags:           [forced][remote][off-hours][mass][post-wiper]
  ATT&CK:          T1529[, T1490, T1561]
  Actions taken:   <alerted | shutdown rights restricted | integrity verified before power-on>
```

## Response

- Restrict **SeRemoteShutdownPrivilege / SeShutdownPrivilege** via GPO to admins;
  remove shutdown rights from standard users (ATT&CK M1018; NIST CSF PR.AA-05).
- Alert in **real time** on mass/remote/forced shutdowns.
- In a **destructive context**, treat as wiper/ransomware IR — do **not** auto
  power systems back on until integrity is verified.
- Keep **out-of-band / BMC power control** under tight access.
