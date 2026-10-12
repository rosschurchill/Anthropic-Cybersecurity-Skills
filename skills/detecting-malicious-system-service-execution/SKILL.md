---
name: detecting-malicious-system-service-execution
description: 'Detects execution via the OS service manager (MITRE T1569) across Windows Service Execution (T1569.002), Linux Systemctl (T1569.003), and macOS Launchctl (T1569.001): services created to run a payload once or as SYSTEM/root, remote execution via PsExec, and systemd units or launch plists loaded from /tmp, /dev/shm or user paths. Uses Windows Event IDs 4697/7045/7036, Sysmon process+registry events, Linux auditd EXECVE/SYSCALL for systemctl and *.service writes, and macOS ESF launchctl exec events, flagging service installs outside the normal admin/packager workflow. Use when hunting service-based code execution via sc.exe, net start, PsExec, systemd-run, or launchctl. Keywords: Event ID 7045, 4697, services.exe, PSEXESVC, sc create, systemctl, systemd unit, launchctl, T1569. Do not use for service-based persistence inventory/baselining - use hunting-for-unusual-service-installations.'
domain: cybersecurity
subdomain: endpoint-security
tags:
- endpoint-security
- threat-detection
- execution
- system-services
- sc-exe
- systemctl
- launchctl
- psexec
- t1569
- windows-events
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.PS-01
- PR.AA-05
mitre_attack:
- T1569
- T1569.001
- T1569.002
- T1569.003
- T1543
- T1021.002
---

# Detecting Malicious System Service Execution

## When to Use

Use this skill to detect adversaries **abusing the OS service manager to execute
code** (ATT&CK T1569) — `sc.exe`/`net start`/PsExec on Windows, `launchctl` on
macOS, and `systemctl`/`systemd-run` on Linux — to run a payload once under a
service context, run as SYSTEM/root, or execute remotely across hosts. The focus
is the **execution act via the service control manager**, often with elevated
privilege and a parentage that breaks the normal admin workflow. Reach for it
when:

- A new service runs a LOLBin / a binary from a temp or user path.
- PsExec (`PSEXESVC`) appears, indicating remote service execution.
- A systemd unit or launch plist loads from `/tmp`, `/dev/shm`, or a user dir.

For durable auto-start **service persistence** inventory/baselining use
`hunting-for-unusual-service-installations`; for scheduled-task execution use
`detecting-malicious-scheduled-tasks-with-sysmon`.

## Prerequisites

- **Windows**: Security Event ID **4697** (service installed), System **7045**
  (new service), **7036/7040** (state/start-type change); Sysmon Event ID 1
  (`services.exe` children, `sc.exe`, `net start`, `PSEXESVC.exe`) and 13
  (`...\Services\*\ImagePath`); 4624 Logon Type 3 for remote install.
- **Linux**: `auditd` EXECVE for `systemctl`/`systemd-run` and SYSCALL/PATH for
  `*.service` writes under `/etc/systemd/system`, `/run/systemd/system`,
  `~/.config/systemd/user`.
- **macOS**: Unified Log / ESF `exec` for `launchctl` (`load`/`submit`/
  `bootstrap`) and file events on `LaunchDaemons`/`LaunchAgents`.
- A **baseline of legitimate service-install sources** (SCCM/Intune, apt/brew,
  packagers).

## Workflow

1. **Baseline legitimate service installs** by source, path, and signer.
2. **Windows service execution.** Alert on 4697/7045 where the service binary is
   in `\Temp\`, `\Users\Public\`, or is a LOLBin / `powershell -enc` / `cmd /c`;
   and on `PSEXESVC` installs (remote exec) correlated with 4624 Logon Type 3.
3. **Linux systemctl.** Alert on `systemctl`/`systemd-run` EXECVE referencing
   `/tmp`, `/dev/shm`, or `/var/tmp`, and on `*.service` unit writes to those
   paths followed by `daemon-reload`/`start`.
4. **macOS launchctl.** Alert on `launchctl load`/`submit` of plists in user
   LaunchAgents or with suspicious program arguments.
5. **Service-binary scrutiny.** Flag service binaries that are LOLBins, unsigned,
   or written seconds before the service was created.
6. **Classify** execution vs persistence (tie to T1543) and remote origin
   (PsExec/WinRM), then **respond** (see *Response*).

## Key Concepts

- **The service manager runs as SYSTEM/root:** creating a service is a clean way
  to execute with maximum privilege; the signal is a service whose binary/path/
  parent doesn't fit the admin-install baseline.
- **PsExec = remote service exec:** a `PSEXESVC` service install paired with a
  Type 3 logon is lateral movement via the SCM.
- **Odd unit paths on Linux:** systemd units legitimately live in system dirs; a
  unit pointing at `/tmp` or `/dev/shm` is almost always malicious.
- **Execution vs persistence:** a one-shot service run is T1569; a durable
  auto-start service is T1543 — reference, don't duplicate, the persistence skill.

## Tools & Systems

Windows Event Log + Sysmon, Splunk ESCU, Microsoft Sentinel / Defender for
Endpoint, Sigma; Linux `auditd`/auditbeat, Falco, osquery (`services`,
`systemd_units`); macOS ESF/EndpointSecurity, KnockKnock; Velociraptor.

## Detection Queries

### Sigma -- suspicious Windows service install

```yaml
title: Suspicious Service Installed (payload path / LOLBin)
status: experimental
logsource:
  product: windows
  service: system
detection:
  svc_install:
    EventID: [7045]
  susp:
    ServiceFileName|contains:
      - '\Temp\'
      - '\Users\Public\'
      - 'powershell'
      - '-enc'
      - 'cmd /c'
  condition: svc_install and susp
falsepositives:
  - Legitimate software installing a service from an installer temp path
level: high
```

### Splunk -- PsExec remote service execution

```spl
(`wineventlog` EventCode=7045) OR (`wineventlog_security` EventCode=4697)
| search (Service_Name="PSEXESVC*" OR Service_File_Name="*PSEXESVC*")
| stats count values(Service_File_Name) as binpath by host, Service_Name, user
| `comment("PSEXESVC install = remote service execution; correlate with 4624 LogonType 3")`
```

### KQL/auditd -- Linux systemctl from an odd path

```kql
union Syslog, auditd_CL
| where (CommandLine has "systemctl" or CommandLine has "systemd-run")
    and (CommandLine has "/tmp/" or CommandLine has "/dev/shm/" or CommandLine has "/var/tmp/")
| project TimeGenerated, Computer, Identity, CommandLine
```

## Common Scenarios

- **One-shot SYSTEM run:** `sc create x binPath= "cmd /c powershell -enc ..."` then
  `sc start x` — 7045 with a LOLBin path.
- **PsExec lateral:** `PSEXESVC` installed on a remote host via ADMIN$ + Type 3
  logon.
- **systemd from /tmp:** a `.service` unit pointing at `/tmp/payload` with
  `daemon-reload` + `start`.
- **False positive:** a signed installer creating its service from an installer
  temp dir — allowlisted by signer.

## Output Format

```
SYSTEM SERVICE EXECUTION DETECTION
  Host:            <computer>
  Verdict:         <confirmed | suspected | approved-install>
  OS/sub:          <Windows .002 | Linux .003 | macOS .001>
  Mechanism:       <sc/7045 | PSEXESVC remote | systemctl/systemd-run | launchctl>
  Service binary:  <path> (LOLBin/unsigned/temp-path: <y/n>)
  Remote origin:   <4624 Type 3 from <ip> | local>
  ATT&CK:          T1569(.001/.002/.003)[, T1543, T1021.002]
  Actions taken:   <host isolated | service/unit removed | binary captured | lateral origin hunted>
```

## Response

- **Isolate the host; stop and remove the malicious service/unit; capture the
  binary/plist/unit file** for analysis.
- Restrict who can create services (least privilege; reduce local admin), disable
  unused remote-exec paths (restrict SMB admin shares / remote SCM), and require
  signed service binaries via WDAC/AppLocker (NIST CSF PR.PS-01).
- Linux: lock down write access to systemd unit directories and monitor
  `daemon-reload`. macOS: restrict LaunchDaemon/Agent writes via configuration
  profiles.
- Determine **persistence vs one-shot** (tie to T1543) and the **lateral-movement
  origin** (PsExec/WinRM), and remediate both.
