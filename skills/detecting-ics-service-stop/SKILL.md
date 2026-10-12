---
name: detecting-ics-service-stop
description: 'Detects an adversary stopping or disabling OT-critical services and processes - SCADA and HMI runtimes, historian collectors, OPC servers, alarm engines, protocol gateways, and their Windows or Linux services - to inhibit response and deny availability (ATT&CK T0881; Industroyer, Industroyer2, KillDisk). Uses Service Control Manager events 7036/7040/7045, Sysmon process-create and registry Start value set to disabled, sc, net, Stop-Service, and taskkill command lines, direct ControlService and ChangeServiceConfigW API calls via EDR, Linux systemctl and kill, and process-rename anti-restart, scoped to maintenance windows and corroborated with historian stale-quality and SCADA comms-fail. Use when an OT service stops or is disabled outside a change window, or critical processes are killed. Keywords: service stop, disable service, sc config start disabled, taskkill, Industroyer2, T0881. Do not use for a whole-device restart or shutdown or broad SCADA attack triage - use detecting-attacks-on-scada-systems.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- service-stop
- inhibit-response
- windows-scm
- sysmon
- sigma
- edr
- historian
- t0881
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.CM-01
- DE.AE-02
- DE.AE-03
- RS.MI-01
mitre_attack:
- T0881
---

# Detecting ICS Service Stop

## When to Use

Use this skill to detect an adversary **stopping or disabling OT-relevant services
and processes** to inhibit response and deny availability (ATT&CK T0881) — SCADA/HMI
runtimes, historian collectors, OPC servers, alarm/polling engines, protocol
gateways, and the Windows or Linux services underpinning them. ATT&CK procedure
examples: Industroyer stops a service (sometimes logging in as a user first),
Industroyer2 terminates specific processes and renames the binaries to prevent
restart, and KillDisk/REvil terminate processes. Reach for it when:

- An OT-critical service enters stopped state outside an approved change window.
- A service start type is flipped to Disabled, or a known OT process is killed.
- A known OT service binary is renamed/moved to block Service Control Manager
  restart.

For a whole-device restart or shutdown, or broad SCADA attack triage, use
`detecting-attacks-on-scada-systems`.

## Prerequisites

- **System event log (Service Control Manager source) for 7036/7040/7045, plus
  Security for 4697** (4697 needs the Audit Security System Extension subcategory
  enabled) on OT-adjacent Windows hosts (HMI, SCADA server, historian, OPC server,
  EWS). There is no separate "SCM" channel — SCM is the event *source* writing into
  the System log.
- **Sysmon** for process-create and registry events, and **EDR** for direct-API
  service control that never touches `sc.exe`.
- **Linux auditd / service-manager logs** on gateways, historians, and soft-PLC
  hosts.
- **An OT-critical-service list per site** plus a reliable change-window feed —
  the load-bearing inputs. Ship the method, not a frozen name list.
- **Historian stale-quality and SCADA comms-fail telemetry** to confirm real OT
  impact versus a benign IT service bounce.
- Note: PLCs rarely run endpoint agents — this detection lives on the Windows/Linux
  hosts running OT software, corroborated by historian/SCADA health.

## Workflow

1. **Maintain the OT-critical-service list and change-window feed.** Enumerate the
   service and process names that matter (SCADA runtime, historian collector, OPC
   server, poll/alarm engine, protocol gateway) and keep an authoritative
   maintenance calendar.
2. **SCM + Sysmon rule.** Alert on SCM 7036 (stopped), 7040 (service start type
   changed — 7040 fires on *any* start-type change, so match the new value Disabled
   in the message), and Sysmon registry `Start=4` under the Services key for any
   OT-critical service **when no change ticket is active**. Add 7045 (new service)
   and Security 4697 for service installs.
3. **Command-line detection.** Flag `sc stop`/`sc config ... start= disabled`,
   `net stop`, `Stop-Service`/`Set-Service -StartupType Disabled`, `taskkill /F`,
   and `wmic service ... call StopService` against OT process/service names.
4. **Direct-API detection (EDR).** RATs call `ControlService` /
   `ChangeServiceConfigW` directly, bypassing `sc.exe`; this requires EDR
   telemetry, not SCM events alone — document the gap when only SCM is available.
5. **Process-rename anti-restart watch.** Correlate a change to a known OT service
   image path with a start-type change (Industroyer2 behaviour). Sysmon has no
   file-rename event, so use EID 11 (FileCreate) together with EID 23/26
   (FileDelete/FileDeleteDetected), or file-system auditing (Security 4663) on the
   image path.
6. **Downstream corroboration.** Join with historian stale-quality and SCADA
   comms-fail to confirm real OT impact.

## Key Concepts

- **The discriminator is context:** stop/disable of an OT-critical service outside
  an approved window by an unexpected user/process — not the stop verb itself.
- **Direct API bypasses `sc.exe`.** `ChangeServiceConfigW`/`ControlService` leave
  no command-line trace; without EDR this is a coverage gap, state it explicitly.
- **Rename-to-block-restart is a strong signal.** Industroyer2 renamed binaries so
  SCM could not restart them — a renamed service image + failed start is high
  confidence.
- **Corroborate with OT impact.** A stopped service plus historian stale-quality
  separates an attack from a routine IT bounce.
- **Linux/embedded matters too:** gateways and soft-PLCs stop via
  `systemctl`/`kill`, caught by auditd execve.

## Tools & Systems

Windows event logs (System log, Service Control Manager source; Security for 4697) + Sysmon, Sigma, EDR (CrowdStrike, Microsoft
Defender, SentinelOne) for direct-API service control, auditd/Linux for gateways,
Splunk (OT/Windows add-ons), Microsoft Sentinel, Claroty CTD, Nozomi Guardian,
Dragos Platform, historian/SCADA health monitoring (OSIsoft PI, AVEVA, Ignition).

## Detection Queries

### Splunk -- OT-critical service stopped/disabled outside a change window

Two things this query must get right. `Service` is **not** an extracted field for SCM
7036/7040 in Splunk's Windows TA — the service name arrives as an insertion string in
`param1` (state / new start type land in `param2`/`param3`), so it has to be coalesced
before any filter or table column, or both come back empty. And SPL `IN` takes a literal
value list, **not** a lookup name: `search Service IN (ot_critical_services)` compares
against that literal string and returns zero results. Use a `lookup` instead. Verify the
field names against your TA version.

```spl
index=ot_win ((EventCode=7036 "stopped") OR (EventCode=7040 "disabled")
  OR (EventCode=4697) OR (sysmon EventCode=13 TargetObject="*\\Services\\*\\Start" Details="DWORD (0x00000004)"))
| eval Service=coalesce(param1, Service)
| lookup ot_critical_services service AS Service OUTPUT is_critical
| where is_critical="true"
| lookup change_window host service AS Service OUTPUT in_window
| where in_window!="true"
| table _time, host, Service, EventCode, user, process
```

### Sigma -- service stop / taskkill of an OT process

```yaml
title: OT-Critical Service Stop or Disable
logsource: { product: windows, category: process_creation }
detection:
  tools:
    Image|endswith: ['\sc.exe', '\net.exe', '\taskkill.exe', '\powershell.exe']
    CommandLine|contains:
      - 'stop'
      - 'config'
      - 'start= disabled'
      - 'Stop-Service'
      - 'Set-Service'
      - '/F'
  ot_names:
    CommandLine|contains: '%ot_service_or_process_names%'
  condition: tools and ot_names
level: high
# Direct ControlService / ChangeServiceConfigW calls need EDR telemetry; sc.exe is absent there.
```

### Sysmon -- process-rename anti-restart (concept)

```
# Sysmon EID 11 is FileCreate (create/overwrite) — Sysmon has NO file-rename event, and a
# same-volume rename (the Industroyer2 behaviour) commonly emits no EID 11 at all. So pair
# EID 11 on a known OT service image path with EID 23/26 (FileDelete / FileDeleteDetected),
# or, for reliable coverage, use file-system auditing (Security 4663 with Write Data /
# Delete access) on the service image path.
# Any of those correlated with an SCM 7040 start-type change = Industroyer2-style restart block.
```

## Common Scenarios

- **Industroyer service stop:** an OT service enters stopped state off-window with
  a login first — SCM 7036 + change-window miss fire.
- **Industroyer2 anti-restart:** historian collector binary renamed, start type
  Disabled, start fails — rename watch + 7040 fire together.
- **Direct-API RAT:** a service is disabled with no `sc.exe` trace — only EDR
  `ChangeServiceConfigW` telemetry catches it.
- **False positive:** a ticketed patch reboot stopping services inside the window
  — suppressed by the change-window lookup.

## Output Format

```
ICS SERVICE STOP DETECTION
  Host:          <HMI | SCADA server | historian | OPC server | gateway>
  Verdict:       <confirmed | suspected | approved-maintenance>
  Service/proc:  <name>  action: <stopped | disabled | killed | renamed-image>
  Method:        <SCM 7036/7040 | sc/net/Stop-Service/taskkill | direct API (EDR) | systemctl/kill>
  Actor:         <user/process>  change window active: <y/n>
  OT impact:     <historian stale-quality | SCADA comms-fail | none observed>
  ATT&CK:        T0881
  Actions taken: <host integrity verified | service restored from known-good | host isolated | DFIR data preserved>
```

## Response

- **Verify host integrity before restart.** Industroyer2 renamed binaries to block
  restart — restore from known-good first rather than blindly restarting.
- **Isolate** the host if the stop came from an unexpected user/process; preserve
  volatile data for DFIR.
- **Harden:** restrict service-control rights to authorized admins, lock
  file/registry permissions on service configs, segment the OT network, run
  service watchdogs/auto-restart with alerting, and enable tamper-resistant
  logging. Keep safety functions in hardwired logic independent of stoppable
  software services.
