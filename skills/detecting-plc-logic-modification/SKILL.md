---
name: detecting-plc-logic-modification
description: 'Detects unauthorized modification of running PLC and controller control logic by golden-master integrity diffing - comparing the live program against a known-good baseline so stealthy online edits and program appends that leave the running logic no longer matching the master are caught even without a clean download event (the Stuxnet and TRITON tampering pattern). Combines scheduled logic diffing with network online-edit detection (S7comm, CIP, Modbus UMAS), engineering-workstation correlation, and historian process-value anomalies. Use when triaging suspected logic tampering, a controller behaving abnormally toward the process, logic-drift alerts, or building logic-integrity baselining. Keywords: modify program, PLC logic tampering, online edit, program append, golden master, logic drift, Stuxnet, TRITON, ICSNPP, T0889. Do not use for detecting the program-transfer event itself - use detecting-plc-program-download.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- plc-logic-modification
- golden-master
- s7comm
- enip-cip
- modbus-umas
- icsnpp
- t0889
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- PR.PS-01
---

# Detecting PLC Logic Modification

## When to Use

Use this skill to detect that the control logic **running** on a PLC or controller
has been added to or changed so the controller behaves differently toward the
physical process or the network (ATT&CK ICS T0889). Where program-download
detection catches the transfer event, this skill catches the **effect**: a running
program that no longer matches its golden master. Logic-integrity drift is the
strongest, hardest-to-evade signal because it survives even a stealthy online edit
that never stops the controller. This is the core Stuxnet and TRITON tampering
pattern. Reach for it when:

- Triaging suspected logic tampering or a controller acting abnormally.
- A logic-drift alert fires from an OT monitoring platform.
- You are standing up logic-integrity baselining for a fleet of controllers.

Do not use for detecting the program-transfer event itself - use
`detecting-plc-program-download`. For task/schedule changes use
`detecting-controller-tasking-modification`.

## Prerequisites

- A golden-master logic repository: a version-controlled store of the approved
  program per controller, with a hash or checksum to diff against.
- A safe read-only path to upload the running program on a schedule (vendor
  engineering tools or an asset-management platform; some controllers degrade
  under frequent polling - tune the cadence).
- Passive ICS network sensor for online-edit and append corroboration.
- Engineering-workstation telemetry (Sysmon/EDR) and a change-management feed.
- Historian access (PI, Ignition) for post-change process-value anomalies.
- Note: PLCs rarely run endpoint agents - the integrity diff plus network and EWS
  telemetry are the detection, not controller host logs.

## Workflow

1. **Baseline** the approved logic for each controller into the golden-master
   store with a hash, and record the diff cadence (hourly or per shift).
2. **Diff on a schedule and on any observed edit.** Read the running program
   through a read-only session and compare it to the golden master **per block,
   on normalised artifacts** — block checksums, or decompiled block text with
   volatile fields excluded (timestamps, retained/online data values, block
   metadata). A hash of the whole program image differs on every re-upload for
   non-semantic reasons, so it is a constant-false-positive comparison. Drift in a
   normalised block with no approved change ticket is the primary alert.
3. **Corroborate on the network.** Flag online-edit or append functions on
   `icsnpp-s7comm` or `cip.log` from a non-EWS host, or an edit without a preceding
   STOP (online edits avoid the STOP/RUN bracket). Verify any per-vendor service
   codes against a live capture - prefer the diff over a raw byte match.
4. **Correlate** the drift with an EWS programming-software launch (Sysmon EID 1)
   and the absence of an approved change ticket.
5. **Confirm impact** with historian set-point, interlock, or actuator anomalies
   after the change.
6. **Respond** (see Response).

## Key Concepts

- **Integrity diffing is the backstop.** Online edits and appends can occur
  without stopping the controller, so download-only monitoring misses them; the
  golden-master diff catches drift however it arrived.
- **Golden master must be trustworthy.** The approved program and its change
  record are the reference; protect that store and gate changes to it through
  change control.
- **S7comm-plus is encrypted.** On S7-1500 you cannot read raw edit function
  codes; lean on the diff and EWS endpoint telemetry.
- **Impact is corroboration, not proof.** Historian anomalies strengthen a drift
  finding but can lag or be masked - the diff is the anchor, provided it runs on
  normalised per-block artifacts rather than a raw program-image hash.
- **Blind spots:** shared engineering accounts and controllers whose activity is
  not forwarded to central monitoring.

## Tools & Systems

Dragos Platform (logic-change detection), Nozomi Guardian/Vantage, Claroty CTD
(baseline and change tracking), Microsoft Defender for IoT; Zeek with CISA ICSNPP;
Suricata or Snort with the Emerging Threats SCADA ruleset; CISA Malcolm; vendor
engineering software and its project version control (TIA Portal, Studio 5000 /
RSLogix, Unity Pro / EcoStruxure Control Expert); historian analytics (OSIsoft/
AVEVA PI, Ignition); Wireshark ICS dissectors.

## Detection Queries

### Scheduled golden-master logic diff (primary analytic, pseudo-logic)

```
on schedule (hourly / per shift) and on any observed download or edit event:
  current = read_program(controller)        # read-only engineering session
  # Compare NORMALISED per-block artifacts, not a raw whole-image hash: strip
  # timestamps, retained/online data values and block metadata first, then compare
  # block checksums (or decompiled block text) block by block. A whole-program hash
  # changes on every re-upload for non-semantic reasons and alerts constantly.
  for block in current:
      if normalise(block) != normalise(golden_master[controller][block])
         and no approved change:
         ALERT "PLC logic drift" (controller, block, last_edit_source)
```

### Zeek (ICSNPP) -- online edit/append from non-EWS (concept)

```
# icsnpp-s7comm / cip.log: raise severity when an online-edit or append
# function is seen from a host not in the EWS allowlist, or an edit with
# no preceding STOP transition. Feed the matching golden-master diff.
```

### Splunk -- drift joined to EWS launch and change feed

Sysmon process-create carries `Computer`/`Image`/`User`/`ProcessId` and has **no
`controller` field**, so joining the subsearch on `controller` never matches and the
EWS enrichment is silently always null. Join on the editing host instead: resolve the
drift alert's `last_edit_source` to a hostname and rename `Computer` to that key inside
the subsearch.

```spl
`logic_drift_alerts`
| lookup asset_inventory ip AS last_edit_source OUTPUT host AS ews_host
| eval ews_host=coalesce(ews_host, last_edit_source)
| join type=left ews_host [ search `sysmon` EventCode=1
    (Image="*TIA*" OR Image="*RSLogix*" OR Image="*ControlExpert*")
  | rename Computer AS ews_host
  | eval ewsLaunch=_time | fields ews_host ewsLaunch ]
| lookup change_tickets controller OUTPUT ticket_id
| where isnull(ticket_id)
| table _time, controller, changed_blocks, ews_host, ewsLaunch
```

## Common Scenarios

- **Stealthy online edit:** the controller never STOPs, no clean download event,
  but the hourly diff shows a changed block with no change ticket - the diff is
  the only thing that caught it.
- **Program append persistence:** attacker logic appended to a running program;
  historian shows an interlock set-point drifting from baseline.
- **S7-1500 (encrypted):** no visible edit code; drift is found purely by the
  read-only diff plus an unexplained EWS session.
- **False positive:** an approved logic change inside a maintenance window - the
  golden master is updated through change control and the drift closes.

## Output Format

```
PLC LOGIC MODIFICATION DETECTION
  Controller:      <plc id / ip>
  Verdict:         <confirmed-drift | suspected | approved-change>
  Change:          <online edit | program append | full replacement>
  Evidence:        <golden-master hash mismatch: blocks <...>>
  Network:         <online-edit function from <src> | none observed>
  Corroboration:   <EWS sw launch | historian set-point/interlock anomaly>
  Change ticket:   <id | none>
  ATT&CK:          T0889 (related T0843, T0821)
  Actions taken:   <controller isolated | golden master restored>
```

## Response

- **Contain:** on confirmed drift, isolate the controller, capture the current
  program for forensics, and restore the golden master through change control -
  never hot-patch in place.
- **Harden:** maintain and regularly diff the golden-master repository (especially
  after any download or reboot); enable code signing and program authentication
  where the platform supports it; enforce authorization and software/device
  authentication on programming functions; and use the key-switch in RUN to block
  online edits.
