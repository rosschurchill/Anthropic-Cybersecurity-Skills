# Detecting Malicious System Shutdown — research notes

- **Proposed slug:** detecting-malicious-system-shutdown
- **ATT&CK:** T1529 System Shutdown/Reboot (tactic: impact) — no sub-techniques
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to adversaries who shut down or reboot systems to interrupt
availability, deny access to resources, or complete a destructive operation
(e.g. reboot after a wiper corrupts the MBR, or mass shutdown to disrupt
operations). The skill correlates execution of shutdown/reboot commands with
host status/shutdown events and flags shutdowns that are unexpected,
unauthorized, forced, remote, or clustered across many hosts.

## Data sources / telemetry
- **Windows System log** — Event ID **1074** (clean shutdown/restart initiated:
  records initiating process, user, and reason), **6006** (Event Log service
  stopped = clean shutdown marker), **6008** (unexpected/dirty shutdown),
  **41** (Kernel-Power, system rebooted without clean shutdown), **1076**
  (reason follow-up), **109** (Kernel kernel-power shutdown reason).
  Note: MITRE DET0559's table lists 1074 under Security — verify channel;
  1074/6006/6008 are normally in **System**.
- **Process creation — Security 4688 / Sysmon EID 1** — `shutdown.exe`
  (`/s /r /f /t`), `Restart-Computer`, `Stop-Computer`, `shutdown /r /m \\host`
  (remote), `wmic os ... reboot`, `logoff`, `rundll32 ... ExitWindowsEx`,
  `InitiateSystemShutdown` API usage; PowerShell logging (4104).
- **Privilege use** — SeShutdownPrivilege / SeRemoteShutdownPrivilege acquisition.
- **Linux/macOS** — `auditd` execve of `shutdown`, `reboot`, `halt`,
  `poweroff`, `systemctl reboot/poweroff`, `init 0/6`; `wtmp`/`last`,
  `/var/log/auth.log`, systemd-logind `journalctl` shutdown records.
- **Cloud/virtualization** — hypervisor/cloud API stop/restart calls
  (AWS CloudTrail `StopInstances`/`RebootInstances`, Azure `deallocate`/
  `restart`, vCenter power-off) to catch control-plane shutdowns.

## Detection logic / approach
MITRE detection strategy DET0559: correlate process execution of
shutdown/reboot commands with host-status change logs; enrich with whether the
initiating user holds an admin/helpdesk role.

Sigma (process-creation) spirit — Splunk Security Content ships "Windows System
Reboot CommandLine" / "System Shutdown CommandLine" keyed on 4688/EID 1:
```yaml
title: Suspicious System Shutdown/Reboot Command
logsource: {category: process_creation, product: windows}
detection:
  shutdown:
    Image|endswith: ['\shutdown.exe']
    CommandLine|contains: ['/r','/s']
  forced: {CommandLine|contains: '/f'}
  remote: {CommandLine|contains: '/m \\'}
  pwsh: {CommandLine|contains: ['Restart-Computer','Stop-Computer']}
  condition: shutdown or pwsh
level: medium   # raise if forced/remote or outside maintenance window
```
Detection value multipliers: forced flag (`/f`), remote target (`/m \\host`),
execution by a non-admin or service account, execution outside a change window,
and — highest severity — **many hosts shutting down in a short window** (mass
shutdown) or shutdown preceded by wiper/ransomware indicators. Use Event ID
1074 as the authoritative "who/why" record and 6008/41 to catch dirty shutdowns
that no clean-shutdown command explains (possible forced crash/BSOD).

## Response / mitigation
Restrict SeRemoteShutdownPrivilege/SeShutdownPrivilege via GPO to admins only
(M1018 User Account Management / least privilege); remove shutdown rights from
standard users. Alert on mass/remote/forced shutdowns in real time. For
destructive-context shutdowns, treat as part of wiper/ransomware IR: do not auto
power systems back on until integrity is verified. Maintain out-of-band/BMC
power control under tight access.

## Real tools
Windows Event Log (System/Security), Sysmon, Splunk Security Content
(research.splunk.com), Sigma/SigmaHQ, Microsoft Sentinel (KQL), auditd,
systemd `journalctl`, AWS CloudTrail / Azure Activity Log, osquery.

## Draft frontmatter mappings
- mitre_attack: [T1529, T1490, T1561]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, RS.MI-01, PR.AA-05]
- d3fend (optional): D3-PM (Process Monitoring), D3-UGLPA (User Geolocation Logon Pattern Analysis) adjacent, D3-SU (System User-permission hardening)
- suggested subdomain: soc-operations
- nearest existing sibling (for the negative trigger): detecting-disk-wipe-and-destruction

## Draft description (<=1024 chars)
Detects malicious system shutdown/reboot — forced, remote, unauthorized, or
mass shutdowns used to interrupt availability or finalize destructive attacks —
by correlating Windows shutdown command execution (shutdown.exe /r /s /f,
Restart-Computer) and Linux shutdown/reboot execve with host-status events
(Event ID 1074/6006/6008/41, systemd-logind, wtmp) and cloud power-control API
calls (CloudTrail StopInstances). Flags shutdowns outside change windows and
clustered across hosts (ATT&CK T1529). Use when triaging unexpected reboots,
mass outages, or shutdown-command alerts, especially alongside wiper/ransomware
signals. Keywords: system shutdown, reboot, shutdown.exe, Event ID 1074,
Kernel-Power 41, mass shutdown, T1529. Do not use for the disk-wipe/boot-sector
destruction that may precede a reboot — use detecting-disk-wipe-and-destruction.

## Key references
- MITRE ATT&CK T1529 + detection strategy DET0559: https://attack.mitre.org/techniques/T1529/
- Splunk Security Content "Windows System Reboot CommandLine": https://research.splunk.com/
- Microsoft Event ID 1074/6006/6008/41 references (verify channel/IDs): https://learn.microsoft.com/
- SigmaHQ: https://github.com/SigmaHQ/sigma

## Open questions / scope boundaries
- Verify the log *channel* for 1074/6006 (System vs Security) in target env —
  MITRE's table and common practice differ.
- Decide how to suppress legitimate patching/maintenance reboots (change-window
  allowlist) to keep signal-to-noise usable.
- Must NOT include procedures for forcing shutdowns. Keep distinct from
  Inhibit System Recovery (T1490) and disk wipe (T1561) though they co-occur.
