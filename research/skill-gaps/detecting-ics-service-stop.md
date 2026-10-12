# Detecting ICS Service Stop — research notes

- **Proposed slug:** detecting-ics-service-stop
- **ATT&CK (ICS):** T0881 Service Stop (tactic: Inhibit Response Function / Impact). Closely related: T0816 Device Restart/Shutdown, T0814 Denial of Service, T0809 Data Destruction, T0828 Loss of Productivity and Revenue, T0878 Alarm Suppression.
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary stopping or disabling OT-relevant services and processes to
inhibit response and deny availability — SCADA/HMI runtimes, historian
collectors, OPC servers, alarm/polling engines, protocol gateways, and the
Windows services underpinning them. ATT&CK procedure examples: Industroyer stops
a service (optionally logging in as a user first), Industroyer2 terminates
specific processes and renames the binaries to prevent restart, and KillDisk /
REvil terminate processes. The skill catches service-stop activity outside
approved maintenance windows and drives rapid restoration.

## Data sources / telemetry
- **Windows service control:** Service Control Manager events — EID 7036 (service
  entered stopped state), 7035 (control sent), 7040 (start type changed, e.g. to
  Disabled), 7045 (new service), and Security 4697. Sysmon 1 (process create) and
  13 (registry) for `Start` value set to 4 (disabled) under
  `HKLM\SYSTEM\CurrentControlSet\Services\*`.
- **Command-line / process:** `sc stop|config ... start= disabled`, `net stop`,
  `Stop-Service` / `Set-Service -StartupType Disabled`, `taskkill /F`,
  `wmic service ... call StopService`, and direct Win32 API
  `ControlService`/`ChangeServiceConfigW` (RATs call the API, bypassing sc.exe).
- **Linux/embedded (gateways, historians, soft-PLC):** `systemctl stop/disable`,
  `kill`/`killall`, auditd execve, service-manager logs.
- **OT-application telemetry:** HMI/SCADA runtime up/down, historian collector/
  interface stopped, OPC server down, poll-engine halt; a stop here produces
  downstream comms-fail and stale-quality tags.
- **Process-rename evidence (Industroyer2 pattern):** a known OT service binary
  renamed/moved so Service Control Manager cannot restart it.
- **Service-start-failure / repeated-failure events** outside maintenance windows.

## Detection logic / approach
MITRE strategy DET0765 (analytic AN1897): monitor executed commands/arguments and
file changes that stop or disable services, and watch for critical processes
terminated or failing to run — including direct API calls (ChangeServiceConfigW
example) that never touch `sc.exe`. Key discriminator: stop/disable of an
OT-critical service outside an approved change window, by an unexpected
user/process.

- **SIEM rule (Splunk/Sentinel) over SCM + Sysmon.** Maintain a list of
  OT-critical service names (SCADA runtime, historian collector, OPC server,
  protocol gateway). Alert on 7036=stopped / 7040 start-type=Disabled / 13
  `Start=4` for any in that list when no change ticket is active:
```
# pseudo-SPL
index=ot_win (EventCode=7036 "stopped") OR (EventCode=7040 "disabled")
| search Service IN (ot_critical_services)
| lookup change_window host service OUTPUT in_window
| where in_window!="true"
```
- **Sigma (cross-SIEM):** service-stop/disable and `taskkill /F` of OT process
  names; map to T0881. API-direct detection needs EDR telemetry
  (`ChangeServiceConfigW`/`ControlService`) since `sc.exe` is absent.
- **Process-rename watch:** file-rename/create of a known OT service image path
  (Industroyer2 anti-restart behaviour) via Sysmon 11 + 7040.
- **Downstream corroboration:** join with historian stale-quality and SCADA
  comms-fail to confirm real OT impact vs a benign IT service bounce.

## Response / mitigation
Attempt controlled restart of the stopped OT service only after confirming host
integrity (Industroyer2 renamed binaries to block restart — restore from
known-good first). Isolate the host if the stop came from an unexpected
user/process; preserve volatile data for DFIR. Harden: restrict service-control
rights to authorized admins (ATT&CK M0918 User Account Management), file/registry
permissions on service configs (M0922/M0924), network segmentation (M0930),
service watchdogs/auto-restart with alerting, and tamper-resistant logging. Keep
safety functions in hardwired logic independent of stoppable software services.

## Real tools
Windows Event Logs (SCM channel) + Sysmon, Sigma, EDR (CrowdStrike/Defender/
SentinelOne) for direct-API service control, auditd/Linux for gateways, Splunk
(OT/Windows add-ons), Microsoft Sentinel, Claroty CTD, Nozomi Guardian, Dragos
Platform, historian/SCADA health monitoring (PI, AVEVA, Ignition).

## Draft frontmatter mappings
- mitre_attack: [T0881, T0816, T0814]
- nist_csf: [DE.CM-09, DE.CM-01, DE.AE-02, DE.AE-03, RS.MI-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling: implementing-ot-incident-response-playbook

## Draft description (<=1024 chars)
Detects an adversary stopping or disabling OT-critical services and processes -
SCADA/HMI runtimes, historian collectors, OPC servers, polling and alarm engines,
protocol gateways, and their Windows or Linux services - to inhibit response and
deny availability (ATT&CK T0881; Industroyer, Industroyer2, KillDisk, REvil). Uses
Service Control Manager events 7036/7040/7045, Sysmon process and registry
Start=4, sc/net/Stop-Service/taskkill command lines, direct ControlService and
ChangeServiceConfigW API calls via EDR, Linux systemctl/kill, and process-rename
anti-restart detection, scoped to maintenance windows and corroborated with
historian stale-quality and SCADA comms-fail. Use when an OT service stops or is
disabled outside a change window, or critical processes are killed. Keywords:
service stop, disable service, sc config start disabled, taskkill, Industroyer,
T0881. Do not use for a full device restart or shutdown - use
detecting-malicious-system-shutdown.

## Key references
- MITRE ATT&CK T0881 Service Stop: https://attack.mitre.org/techniques/T0881/
- DET0765 Detection of Service Stop: https://attack.mitre.org/detectionstrategies/DET0765/
- ESET / Dragos, Industroyer and Industroyer2 analyses: https://www.welivesecurity.com/
- MITRE EMB3D TID-222 Critical System Service May Be Disabled: https://emb3d.mitre.org/threats/TID-222/
- Sigma rules (service stop/disable): https://github.com/SigmaHQ/sigma

## Open questions / scope boundaries
- Load-bearing input is the OT-critical-service list per site plus a reliable
  change-window feed; ship the method, not a fixed name list.
- Direct-API service control (ChangeServiceConfigW) requires EDR, not just event
  logs; document the coverage gap when only SCM events are available.
- Boundary with T0816 Device Restart/Shutdown (whole device) and T0814 DoS
  (resource exhaustion) — route accordingly; this is service/process termination.
- Verify current procedure-example attributions against the live T0881 page.
