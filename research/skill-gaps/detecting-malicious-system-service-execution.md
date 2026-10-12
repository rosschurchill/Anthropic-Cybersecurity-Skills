# Detecting Malicious System Service Execution — research notes

- **Proposed slug:** detecting-malicious-system-service-execution
- **ATT&CK:** T1569 System Services (tactic: execution). Sub-techniques: **T1569.001 Launchctl** (macOS), **T1569.002 Service Execution** (Windows), **T1569.003 Systemctl** (Linux — detection strategy **DET0073**, created 2025-10-21, current in v19 era; verify against v19.2). Related: T1543 Create or Modify System Process (service *persistence*), T1021.002 SMB/Admin Shares (remote service exec via PsExec), T1053 Scheduled Task/Job.
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries abusing the operating system's service manager to execute code — `sc.exe`/`net start`/PsExec on Windows, `launchctl` on macOS, and `systemctl`/`systemd-run` on Linux — whether to run a payload once under a service context, run as SYSTEM/root, or execute remotely across hosts. The skill focuses on the *execution* act via the service control manager (often with elevated privilege and a parentage that breaks the normal admin workflow), complementing persistence-focused service skills.

## Data sources / telemetry
- **Windows (T1569.002):** Security Event ID **4697** (A service was installed in the system), System Event ID **7045** (new service installed), **7036/7040** (service state/start-type change). Sysmon Event ID **1** (process create) for `services.exe` children, `sc.exe`, `net.exe start`, and `PSEXESVC.exe`; Sysmon **13** (registry) for `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath`. Remote exec: 4624 Logon Type 3 + service install (PsExec/`\\host\ADMIN$`).
- **Linux (T1569.003, DET0073):** auditd **EXECVE** records for `systemctl` subcommands (start/enable/daemon-reload) and `systemd-run`; auditd **SYSCALL/PATH** records for writes/creates of `*.service` unit files under `/etc/systemd/system`, `/run/systemd/system`, `~/.config/systemd/user`; process-creation records for processes `systemd` spawns. Flag units loaded from `/tmp`, `/dev/shm`, `/var/tmp`.
- **macOS (T1569.001):** Unified Log / ESF `exec` events for `launchctl` (`load`/`submit`/`bootstrap`); file events on `LaunchDaemons`/`LaunchAgents` plists.

## Detection logic / approach
Per DET0073, correlate new/changed service units with the service-manager subcommands and flag units executed from unusual paths or created outside expected admin workflows.

Sigma (Windows, suspicious service install — concept):
```yaml
detection:
  svc_install:
    EventID: [4697, 7045]
  susp_path:
    ServiceFileName|contains:
      - '\Temp\'
      - '\Users\Public\'
      - 'powershell'
      - '-enc'
      - 'cmd /c'
  condition: svc_install and susp_path
```
SPL (Windows remote service exec via PsExec):
```
(EventCode=7045 OR EventCode=4697) Service_Name="PSEXESVC" OR Service_File_Name="*PSEXESVC*"
| stats count by host, Service_Name, Service_File_Name, user
```
auditd / KQL (Linux, systemctl from odd path):
```kql
union Syslog, auditd_CL
| where (CommandLine has "systemctl" or CommandLine has "systemd-run")
   and (CommandLine has "/tmp/" or CommandLine has "/dev/shm/")
```
Hunt for service binaries that are LOLBins, unsigned, or written seconds before the service was created; baseline legitimate service-install sources (SCCM/Intune/packagers) and alert on the rest.

## Response / mitigation
- Isolate the host; stop and remove the malicious service/unit; capture the service binary/plist/unit file for analysis.
- Restrict who can create services (least privilege; remove local-admin where possible); disable unused remote-exec paths (restrict SMB admin shares, remote SCM); require signed service binaries via WDAC/AppLocker.
- Linux: lock down write access to systemd unit directories; monitor `daemon-reload`. macOS: restrict LaunchDaemon/Agent writes via profiles.
- Review for persistence vs. one-shot execution (tie to T1543) and lateral-movement origin (PsExec/WinRM).

## Real tools
Windows Event Log + Sysmon (SwiftOnSecurity/Olaf config), Splunk ESCU, Microsoft Sentinel/Defender for Endpoint, Sigma + sigmac; Linux auditd/auditbeat, Falco, osquery (`services`, `startup_items`, `systemd_units` where available); macOS ESF/EndpointSecurity, KnockKnock; Velociraptor; sc.exe/`Get-Service`, `systemctl list-units`, `launchctl list` for triage.

## Draft frontmatter mappings
- mitre_attack: [T1569, T1569.001, T1569.002, T1569.003, T1543, T1021.002]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, PR.PS-01, PR.AA-05]
- suggested subdomain: endpoint-security
- nearest existing sibling (for the negative trigger): hunting-for-unusual-service-installations

## Draft description (<=1024 chars)
Detects execution via the OS service manager (T1569) across Windows Service Execution (T1569.002), Linux Systemctl (T1569.003), and macOS Launchctl (T1569.001): services created to run a payload once or as SYSTEM/root, remote execution via PsExec, and systemd units or launch plists loaded from /tmp, /dev/shm or user paths. Uses Windows Event IDs 4697/7045/7036, Sysmon process+registry events, Linux auditd EXECVE/SYSCALL for systemctl and *.service writes, and macOS ESF launchctl exec events, flagging service installs outside the normal admin/packager workflow. Use when hunting service-based code execution, PsExec, sc.exe, net start, systemd-run, or launchctl abuse. Keywords: 7045, 4697, services.exe, PSEXESVC, sc create, systemctl, systemd unit, launchctl, T1569, DET0073. Do not use for service-based persistence inventory/baselining (use hunting-for-unusual-service-installations) or scheduled-task execution (use detecting-malicious-scheduled-tasks-with-sysmon).

## Key references
- https://attack.mitre.org/techniques/T1569/
- https://attack.mitre.org/techniques/T1569/002/
- https://attack.mitre.org/techniques/T1569/003/
- https://attack.mitre.org/detectionstrategies/DET0073
- https://research.splunk.com/endpoint/ (Windows service installation detections)

## Open questions / scope boundaries
- Verify T1569.003 Systemctl and DET0073 are the current v19.2 IDs (the task flagged this ID to verify); confirm AN analytic numbering if cited.
- Draw the line against **persistence**: T1569 is execution via the service manager; durable auto-start service persistence belongs with T1543 / hunting-for-unusual-service-installations — this skill should reference, not duplicate, them.
- Author must decide single cross-platform skill vs. per-OS, and how to baseline legitimate service-install sources (SCCM/Intune/apt/brew) to keep false positives low.
- Must NOT become a generic PsExec/lateral-movement skill; keep the remote-exec angle scoped to the service-creation signal.
