---
name: detecting-alarm-setting-tampering
description: 'Detects tampering with OT alarm configuration - a persistent change to alarm thresholds, enable flags, priorities, deadbands or notification routing so operators are not alerted to dangerous conditions (ATT&CK ICS T0838, Maroochy-style) - using HMI, SCADA and historian alarm-config change logs, controller and IED setting changes, protocol writes to alarm points (Modbus, DNP3, IEC 61850 setting-group control block services, BACnet Notification Class), and a diff against a golden alarm baseline, tied to an authenticated user and change window. Use when an alarm limit or enable flag changed unexpectedly, when a process exceeded bounds with no alarm, or when building alarm-config change monitoring. Keywords: Modify Alarm Settings, T0838, alarm limit, alarm disabled, setpoint, Notification Class, FactoryTalk Alarms and Events, WinCC, PI Notifications, golden baseline, change window. Do not use for transient run-time alarm muting or missing-expected alarms with no config change - use detecting-alarm-suppression.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- alarm-setting-tampering
- modify-alarm-settings
- hmi
- historian
- scada
- t0838
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.AA-05
- PR.PS-01
mitre_attack:
- T0838
- T0878
---

# Detecting Alarm Setting Tampering

## When to Use

Use this skill to detect an adversary changing **alarm configuration** —
thresholds/setpoints, enable/disable flags, priorities, deadbands, or
notification routing — so operators are not alerted to dangerous process
conditions (ATT&CK ICS T0838, Modify Alarm Settings). Unlike transient
suppression, this is a **persistent configuration change** that survives in the
HMI/historian/controller until someone reverts it. Reach for it when:

- An alarm limit, priority, or enable flag changed unexpectedly.
- A process exceeded historical trip bounds but no alarm fired.
- Building alarm-config change monitoring tied to users and change windows.

This skill is about a **persistent config change** (golden-baseline diff). For
detection of **transient** run-time muting or alarms that should have fired but
did not, with no config change, use `detecting-alarm-suppression`. The two
frequently co-occur — cross-reference, but keep the trigger distinct.

## Prerequisites

- **Golden alarm-config baseline** per point: expected limits, enable flags,
  priorities, deadbands, and notification recipients, from engineering records
  or an OT monitoring platform. This is the reconciliation reference.
- **HMI/SCADA and historian alarm-config change logs** with old-to-new value,
  who, and from where: FactoryTalk Alarms & Events, Siemens WinCC alarm
  logging, AVEVA/Wonderware alarm database, Inductive Automation Ignition, GE
  iFIX/CIMPLICITY, OSIsoft/AVEVA PI (AF analyses, Notifications, Event Frames).
- **Controller/IED setting logs** where alarm limits live in PLC logic or IED
  setting groups.
- **Passive protocol monitoring** (Zeek + ICSNPP, or an OT IDS) plus a **point
  map** so you know which registers/points hold alarm limits.
- **Authentication logs** for accounts that can change alarm config.
- Alarm config lives in HMI/historian/controller, not on a controller endpoint
  agent — detection is application logs + network + baseline reconciliation.

## Workflow

1. **Build the golden baseline** of alarm config per point and the list of
   authorized engineers and change windows.
2. **Alert on any alarm-config change** in HMI/historian logs not matched to an
   approved change ticket **and** an authorized engineer.
3. **Reconcile against baseline periodically.** Pull live alarm config and diff
   against golden; flag any delta — especially disabled alarms, widened limits,
   or removed notification recipients.
4. **Watch protocol writes to alarm points.** With the point map, alert on
   writes to alarm-limit registers/points from non-EWS hosts.
5. **Cross-check process condition.** Flag when a process value approaches or
   exceeds historical trip bounds but no alarm fires — corroborating evidence of
   a widened or disabled limit.
6. **Respond** (see *Response*).

## Key Concepts

- **Persistent, not transient.** The discriminator from suppression is that the
  config itself changed and stays changed — a golden-baseline diff shows it even
  after the attacker has gone.
- **Old-to-new value matters.** An alarm-config audit record without the prior
  value cannot prove tampering direction; capture both or reconstruct from the
  golden baseline.
- **Process cross-check is corroborating, not direct.** An out-of-bounds value
  with no alarm points to a limit that was widened or an alarm that was
  disabled, but confirm it against the config-change record before concluding.
- **Protocol service names are illustrative.** Writes may ride Modbus write
  function codes to alarm-limit registers, DNP3 writes/select-operate to config
  points, IEC 61850 MMS SetDataValues or the setting-group control block
  services (SelectActiveSG / SelectEditSG / SetEditSGValue / SetEditSGValues /
  ConfirmEditSGValues), OPC UA Alarms & Conditions writes, or BACnet
  WriteProperty to Notification Class recipients / Limit_Enable. Report control
  block manipulation (`SetRCBValues`, `RptEna`) suppresses reporting without
  changing the alarm configuration, so it belongs to
  `detecting-alarm-suppression`. Verify the exact service names against your
  stack and dissector, and which registers are alarm limits against the
  site point map, before signaturing — prefer the config-log and baseline-diff
  framing, which does not depend on the exact code.

## Tools & Systems

HMI/SCADA + historian: Rockwell FactoryTalk Alarms & Events, Siemens WinCC,
AVEVA System Platform / InTouch / Historian, Inductive Automation Ignition, GE
iFIX/CIMPLICITY, OSIsoft/AVEVA PI (AF, Notifications, Event Frames). Network:
Zeek + ICSNPP (`icsnpp-modbus`, `icsnpp-dnp3`, `icsnpp-bacnet`,
`icsnpp-opcua-binary`), Suricata, Dragos Platform, Nozomi Guardian, Claroty
CTD/xDome, Microsoft Defender for IoT, Wireshark ICS dissectors. SIEM: Splunk,
Microsoft Sentinel.

## Detection Queries

Point-level protocol detection depends on a per-site point map; the config-log
and golden-baseline checks are the vendor-agnostic anchors.

### Splunk — alarm-config change with no ticket or unauthorized user (core)

```spl
index=ot (sourcetype=ftae_audit OR sourcetype=wincc_alarm_cfg OR sourcetype=pi_notifications)
  action IN ("alarm_limit_changed","alarm_disabled","priority_changed","notification_recipient_changed")
| lookup change_windows asset OUTPUT window_active
| lookup authorized_engineers user OUTPUT authorized
| where window_active!="true" OR authorized!="true"
| table _time, asset, point, action, old_value, new_value, user, src_host
```

### Splunk — golden alarm-config baseline reconciliation

```spl
index=ot sourcetype=alarm_config_snapshot
| stats latest(limit_high) as hi latest(limit_low) as lo latest(enabled) as en latest(recipients) as rcpt by asset, point
| lookup golden_alarm_config asset point OUTPUT g_hi g_lo g_en g_rcpt
| where hi!=g_hi OR lo!=g_lo OR en!=g_en OR rcpt!=g_rcpt
| table asset, point, hi, g_hi, lo, g_lo, en, g_en, rcpt, g_rcpt
```

### Splunk — process breach with widened/disabled limit (corroboration)

```spl
index=ot sourcetype=historian
| lookup golden_alarm_config asset point OUTPUT g_hi
| where value>=g_hi   /* exceeds the ORIGINAL golden limit */
/* left join: an INNER join would discard exactly the no-alarm rows below */
| join type=left asset point [ search index=ot sourcetype=alarm_journal | stats count as alarms by asset point ]
| where isnull(alarms) OR alarms=0
| table _time, asset, point, value, g_hi
```

## Common Scenarios

- **Widened limit:** an engineer account from an unexpected host raises a
  high-high limit well above the process's safe band; baseline diff flags it.
- **Disabled alarm (Maroochy-style):** critical alarms disabled at multiple
  stations so operators never see the excursion.
- **Rerouted notification:** notification-class recipients removed or redirected
  so the alert fires but reaches no one.
- **False positive:** an authorized tuning change inside an approved window by a
  named engineer, with old-to-new recorded — closed by the ticket/user lookups.

## Output Format

```
ALARM SETTING TAMPERING DETECTION
  Asset/point:     <HMI/controller + point/tag>
  Verdict:         <confirmed-tamper | suspected | authorized-change>
  Change:          <limit widened | alarm disabled | priority lowered | recipients removed>
  Old -> new:      <prior value> then <new value>
  Baseline diff:   <delta vs golden alarm config>
  Actor:           <user + src host>  authorized: <yes/no>  change ticket: <matched/none>
  Process check:   <value breached original limit with no alarm | n/a>
  ATT&CK:          T0838
  Actions taken:   <config restored from golden | credentials rotated | unalarmed window reviewed>
```

## Response

- **Restore** the alarm configuration from the golden baseline and verify which
  conditions went unalarmed during the gap; inspect the physical process state.
- **Revoke/rotate** the credentials used and confirm the change source.
- **Harden:** least privilege on alarm configuration (separate from operation),
  mandatory change management logging old-to-new values, role separation
  between engineering and operating accounts, segmentation so only sanctioned
  EWS can write alarm points (IEC 62443), and independent/out-of-band alarm
  paths so a tampered HMI config does not blind every channel.
