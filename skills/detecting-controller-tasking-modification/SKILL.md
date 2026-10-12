---
name: detecting-controller-tasking-modification
description: 'Detects unauthorized changes to PLC and controller task execution configuration - task scheduling, priority, triggers, and scan or cycle parameters an adversary alters so their code runs more often or ahead of legitimate logic (the Stuxnet and PLC-Blaster task-abuse pattern). Combines engineering-software and controller application-log monitoring, task-configuration golden-master baselining, device alarms, and program-download corroboration on the OT network. Use when triaging unexplained controller timing or scan changes, task priority or trigger edits, OB or periodic-task reconfiguration, or building controller-configuration baselining. Keywords: modify controller tasking, task priority, scan cycle, OB task, periodic task, Stuxnet, PLC-Blaster, FortiSIEM ICS, T0821. Do not use for detecting changes to the controller program logic content itself - use detecting-plc-logic-modification.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- controller-tasking
- task-scheduling
- s7comm
- enip-cip
- engineering-workstation
- icsnpp
- t0821
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- PR.PS-01
mitre_attack:
- T0821
- T0889
---

# Detecting Controller Tasking Modification

## When to Use

Use this skill to detect an adversary changing **how and when** a controller
executes its programs (ATT&CK ICS T0821): altering task scheduling, priority,
triggers, or scan and cycle parameters so attacker code runs more frequently or
ahead of legitimate logic. This is a distinct, often overlooked tampering surface
- it changes the task structure, not the program content. Stuxnet and PLC-Blaster
both abused controller task structures to get their code executed. Reach for it
when:

- Triaging unexplained controller timing, scan-rate, or cycle changes.
- A task priority, trigger, or schedule edit is reported by engineering software.
- You are building a controller-configuration baseline alongside logic baselining.

Do not use for detecting changes to the controller program logic content itself -
use `detecting-plc-logic-modification`. For the transfer that often delivers a
tasking change use `detecting-plc-program-download`.

## Prerequisites

- Access to asset application and engineering-software logs that record task
  parameter changes (schedule, priority, trigger, cycle time, OB or task
  association in Siemens; periodic versus event task config in Rockwell).
- A golden-master task-configuration baseline per controller, diffable on a
  schedule, alongside the logic baseline.
- Device alarms where the controller emits them (coverage is device-dependent).
- Passive ICS network sensor for program-download and online-edit corroboration.
- Engineering-workstation telemetry (Sysmon/EDR) and a change-management feed.
- Note: PLCs rarely run endpoint agents - detection leans on application logs,
  the config diff, network corroboration, and EWS telemetry.

## Workflow

1. **Baseline** the task configuration for each controller - task list, priority,
   trigger type, and cycle/scan time - into a golden-master store.
2. **Diff on a schedule and on any observed download or edit.** Read the current
   task config through a read-only session and compare it to the master; a change
   with no approved ticket is the primary alert.
3. **Monitor application logs** from engineering tools and controllers for records
   that task parameters changed, and device alarms where emitted.
4. **Corroborate on the network.** A program-download or online-edit event from a
   non-EWS host within the window of the config change raises confidence, because
   downloads are a common delivery path for a tasking change. Verify any per-vendor
   task-config service codes against a live capture before trusting them.
5. **Correlate** with an EWS programming-software launch (Sysmon EID 1) and the
   change feed; historian timing/scan anomalies add corroboration.
6. **Respond** (see Response).

## Key Concepts

- **Tasking is a separate surface from logic.** The program content may be
  unchanged while the schedule or priority that runs it is altered - so a logic
  diff alone can miss it; baseline the task config explicitly.
- **Application logs are primary.** Detection leans on engineering-tool and
  controller log content indicating a schedule, priority, or trigger edit, backed
  by the config diff; device alarms help but coverage varies.
- **Download is corroboration.** A tasking change is frequently delivered via a
  program download, so a download-then-changed-timing pair is the chain.
- **Vendor task models differ.** Siemens OB/task priorities versus Rockwell
  periodic and event tasks - map the model per platform before writing rules.

## Tools & Systems

Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT;
Zeek with CISA ICSNPP; FortiSIEM (ships a Modify Controller Tasking ICS rule);
OpenText ArcSight ESM ICS ATT&CK content; vendor engineering software (TIA Portal
task/OB config, Studio 5000 task properties, Unity Pro / EcoStruxure Control
Expert); Wireshark ICS dissectors; Suricata or Snort with the Emerging Threats
SCADA ruleset.

## Detection Queries

### Task-configuration golden-master diff (primary analytic, pseudo-logic)

```
on schedule and on observed download or edit:
  current = read_task_config(controller)   # task list, priority, trigger, cycle
  if current != golden_master_tasks[controller] and no approved change ticket:
     ALERT "controller tasking changed" (controller, task, old vs new priority/trigger)
```

### Log analytic (Splunk/Sentinel) -- task-config edit from engineering sw

Sysmon process-create carries `Computer`/`Image`/`User`/`ProcessId` and emits **no
`src_host` field**, so the subsearch must rename `Computer` to the join key or the join
never matches and the EWS enrichment is silently always null. If `src_host` from the
engineering-tool logs is an IP rather than a hostname, resolve it through an asset
lookup before joining.

```spl
`eng_sw_logs` (event="task_priority_change" OR event="task_schedule_change"
               OR event="task_trigger_change")
| lookup change_tickets controller OUTPUT ticket_id
| where isnull(ticket_id)
| join type=left src_host [ search `sysmon` EventCode=1
    (Image="*TIA*" OR Image="*RSLogix*" OR Image="*ControlExpert*")
  | rename Computer AS src_host
  | eval ewsLaunch=_time | fields src_host ewsLaunch ]
| table _time, controller, event, src_host, ewsLaunch
```

### Zeek (ICSNPP) -- download/online-edit corroboration (concept)

```
# icsnpp-s7comm / cip.log: a program-download or online-edit from a non-EWS
# host inside the window of a tasking-config change raises confidence.
```

## Common Scenarios

- **Priority hijack:** an attacker raises the priority of an added task so it runs
  ahead of legitimate logic; the task-config diff shows the new priority with no
  change ticket.
- **Scan-time manipulation:** the cycle time is shortened to run injected code
  more often; historian update timing shifts and the config diff confirms it.
- **Download then tasking change:** a download from an unknown host is followed by
  changed task behavior - the corroborating chain.
- **False positive:** an approved commissioning change to a periodic task inside a
  maintenance window - excluded by the change feed and updated baseline.

## Output Format

```
CONTROLLER TASKING MODIFICATION DETECTION
  Controller:      <plc id / ip>
  Verdict:         <confirmed | suspected | approved-change>
  Change:          <priority | schedule | trigger | cycle/scan time | OB/task map>
  Detail:          <task>: <old> then <new>
  Source:          <host ip> (EWS allowlisted: <yes/no>)
  Corroboration:   <download/online-edit event | device alarm | historian timing>
  Change ticket:   <id | none>
  ATT&CK:          T0821 (related T0889)
  Actions taken:   <controller isolated | task config restored>
```

## Response

- **Contain:** on a confirmed unauthorized change, isolate the controller, capture
  the current task configuration and logic for forensics, and restore the approved
  configuration through change control.
- **Harden:** baseline task configuration alongside program logic and diff on a
  schedule; restrict who and what can issue tasking changes with software/device
  authentication and authorization enforcement; allowlist engineering sources and
  enforce the key-switch; and gate every tasking change behind change control.
