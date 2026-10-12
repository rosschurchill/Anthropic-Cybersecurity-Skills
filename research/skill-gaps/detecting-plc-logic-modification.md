# Detecting PLC Logic Modification — research notes

- **Proposed slug:** detecting-plc-logic-modification
- **ATT&CK (ICS):** T0889 Modify Program (tactic: persistence) — closely related:
  T0843 Program Download (a delivery mechanism), T0821 Modify Controller Tasking,
  T0835 Manipulate I/O Image, T0820 Exploitation for Evasion. Historical: Stuxnet,
  TRITON/TRISIS, PLC-Blaster
- **Status:** research (not yet a skill)

## Defensive goal
Detect that the control logic running on a PLC/controller has been added to or changed so the
controller behaves differently toward the physical process or the network — whether delivered by a
full download, an online edit, or a program append. Where T0843 catches the *transfer event*, this
skill catches the *effect*: a running program that no longer matches its golden master. This is the
core Stuxnet/TRITON tampering pattern, and logic-integrity drift is the strongest, hardest-to-evade
signal because it survives even stealthy online edits.

## Data sources / telemetry
- **Logic-integrity baselining (primary):** periodic upload of the running program and a diff/hash
  against a known-good golden-master repository (e.g. a version-controlled store of the approved
  logic). Vendor engineering tools and asset-management platforms often retain the expected program
  and a change record — ATT&CK notes this explicitly.
- **Passive ICS network sensor:** S7comm/S7comm-plus, EtherNet/IP CIP, Modbus/UMAS (FC 90/0x5A)
  online-edit and append operations — these can occur without stopping the controller, so there may
  be no STOP/RUN bracket. Watch device-management protocol write/edit services. **Verify exact
  per-vendor service codes against captures.**
- **Engineering workstation (Sysmon/EDR):** programming-software (TIA Portal, Studio 5000 / RSLogix,
  Unity/Control Expert) process creation and project-file writes; session correlation to the edited
  controller.
- **Controller/device telemetry:** device alarms on program change where emitted; vendor engineering
  audit logs; controller program timestamp / CRC / cyclic-checksum registers where the platform
  exposes them.
- **Historian (PI / Ignition):** post-change process-value anomalies (set-points, interlocks,
  actuator behavior drifting from baseline) as corroborating impact evidence.

## Detection logic / approach
MITRE detection strategy **DET0783** (analytic AN1888-era; data components network traffic content
DC0085, device alarms DC0108, software DC0111). Online edits and appends can avoid a controller stop,
so program-download monitoring alone misses them — integrity diffing is required.

Primary analytic — scheduled golden-master diff:
```
on schedule (e.g. hourly / per-shift) and on any observed download/edit event:
  current_logic = upload_program(controller)          # read-only engineering session
  if hash(current_logic) != hash(golden_master[controller]) and no approved change ticket:
     ALERT "PLC logic drift" (controller, changed_blocks, last_edit_source)
```
Network corroboration (Zeek/ICSNPP): online-edit/append function on `icsnpp-s7comm` or `cip.log`
from a non-EWS host, or without a preceding STOP (online edit) — raise severity, feed the diff.

Splunk/Sentinel correlation: join (a) a logic-drift alert, (b) EWS programming-software launch
(Sysmon EID 1), and (c) absence of an approved change ticket; add historian set-point/interlock
anomaly as impact confirmation. Watch blind spots: shared engineering accounts and controllers whose
activity is not forwarded to central monitoring.

## Response / mitigation
Maintain and regularly diff against a golden-master logic repository (M0947 Audit / integrity checks,
especially after any download or reboot). Code signing / program authentication where the platform
supports it (M0945). Authorization enforcement and software/device authentication on programming
functions (M0800, M0813). Key-switch in RUN to block online edits (M0801). On confirmed drift:
isolate the controller, capture the current program for forensics, and restore the golden master
through change control — never hot-patch in place.

## Real tools
Dragos Platform (logic-change detection), Nozomi Guardian/Vantage, Claroty CTD (baseline/change
tracking), Microsoft Defender for IoT; Zeek + CISA ICSNPP; Suricata + Emerging Threats SCADA; CISA
Malcolm; vendor engineering software (TIA Portal, Studio 5000, Control Expert) and their project
version control; Wireshark ICS dissectors. (Logic static analysis of an extracted program is a
separate sibling — see below.)

## Draft frontmatter mappings
- mitre_attack: [T0889, T0843, T0821, T0835]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, PR.PS-01, ID.AM-02]
- suggested subdomain: ot-ics-security
- nearest existing sibling (for the negative trigger): performing-plc-firmware-security-analysis

## Draft description (<=1024 chars)
Detects unauthorized modification of PLC/controller control logic — full downloads, online edits,
and program appends that leave the running program no longer matching its golden master (the
Stuxnet/TRITON tampering pattern). Combines scheduled golden-master logic diffing with network
online-edit/append detection (S7comm, CIP, Modbus UMAS), engineering-workstation correlation, and
historian process-value anomalies (ATT&CK ICS T0889). Use when triaging suspected logic tampering,
controller behaving abnormally toward the process, logic-drift alerts, or building logic-integrity
baselining. Keywords: modify program, PLC logic tampering, online edit, program append, golden
master, logic drift, Stuxnet, TRITON, ICSNPP, T0889. Do not use for static security analysis of an
already-extracted PLC firmware image - use performing-plc-firmware-security-analysis.

## Key references
- MITRE ATT&CK T0889 + DET0783: https://attack.mitre.org/techniques/T0889/ , https://attack.mitre.org/detectionstrategies/DET0783
- CISA ICSNPP: https://github.com/cisagov/ICSNPP
- MITRE ATT&CK Stuxnet / TRITON software entries: https://attack.mitre.org/software/
- CISA ICS advisories: https://www.cisa.gov/news-events/cybersecurity-advisories

## Open questions / scope boundaries
- Author must decide the golden-master store and diff cadence, and how to perform read-only logic
  uploads safely (vendor-specific; some platforms degrade under frequent polling).
- Boundary vs T0843 (the transfer), T0821 (task scheduling) and T0835 (I/O image) — this skill is
  the *logic content* change. Must NOT include offensive logic-modification code.
- Verify per-vendor online-edit/append service codes against captures before shipping signatures.
