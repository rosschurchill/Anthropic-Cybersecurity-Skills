---
name: detecting-alarm-suppression
description: 'Detects alarm suppression in OT - alarms that should have fired but did not, often transient - via missing-expected-alarm logic (a process value breaches a limit with no alarm event), loss of cyclic traffic or heartbeats, and protocol signals like DNP3 disable-unsolicited, IEC 61850 Report Control Block disable, GOOSE stNum or time-to-live gaps, and BACnet COV or Notification removal (ATT&CK ICS T0878, Maroochy-style). Use when operators report missing alarms, when a process excursion raised no alarm, or when building liveness and missing-alarm monitoring across protocol, process and HMI telemetry. Keywords: Alarm Suppression, T0878, missing alarm, disable-unsolicited, DNP3, GOOSE heartbeat, Report Control Block, COV, out-of-band alarm, heartbeat loss. Do not use for a persistent change to alarm thresholds or enable flags - use detecting-alarm-setting-tampering.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- alarm-suppression
- inhibit-response
- dnp3
- iec-61850
- historian
- t0878
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- RS.MI-01
mitre_attack:
- T0878
- T0838
---

# Detecting Alarm Suppression

## When to Use

Use this skill to detect an adversary **suppressing alarms** so operators are
not notified of critical process conditions (ATT&CK ICS T0878, Alarm
Suppression) — by blocking or dropping the alarm message, muting it at the HMI,
manipulating the I/O or flag bit that signals it, or disabling event reporting
on the wire. Suppression is often **transient** and leaves a **negative
signal**: the alarm that should have fired did not. Reach for it when:

- Operators report missing alarms, or a mass-acknowledge/shelve looks wrong.
- A process excursion crossed a known limit but raised no alarm.
- Building liveness and missing-alarm monitoring across protocol, process, and
  HMI telemetry.

This skill is about **transient** blocking/muting/non-reporting with no config
change. For detection of a **persistent configuration change** — a new limit, a
disabled enable flag, rerouted notifications — use
`detecting-alarm-setting-tampering`. The two frequently co-occur; cross-
reference, but keep the trigger distinct.

## Prerequisites

- **Per-point alarm-limit baseline** so missing-expected-alarm logic can know
  when a value should have alarmed.
- **Expected-traffic / liveness model** per asset: polling cadence, DNP3
  integrity/event polls, GOOSE heartbeat `timeAllowedtoLive`, OPC UA
  subscription rates — a drop below baseline is a core tell.
- **HMI/historian alarm journals** (FactoryTalk A&E, WinCC, AVEVA, Ignition,
  PI) for gaps, mass acknowledgements, and shelve/mute actions.
- **Passive protocol monitoring** (Zeek + ICSNPP, or an OT IDS) to see
  reporting-control commands and traffic gaps.
- **Historian process trends** to compare values against alarm limits.
- Detection is network + process + HMI telemetry, not controller host logs —
  PLCs/RTUs rarely run endpoint agents.

## Workflow

1. **Baseline** per-point alarm limits and each asset's expected cyclic traffic
   and heartbeat cadence.
2. **Missing-expected-alarm (core).** Join process values against the alarm
   journal; alert when a value breaches a limit but no alarm event exists in the
   window.
3. **Traffic/heartbeat loss.** Alert when cyclic traffic, DNP3 unsolicited
   responses, or GOOSE heartbeats from a device stop below the liveness model.
4. **Reporting-control commands.** Flag DNP3 disable-unsolicited, IEC 61850 RCB
   disable, OPC UA subscription/monitored-item removal, or BACnet COV/
   Notification removal, especially from a non-master/non-authorized host.
5. **HMI action audit.** Alert on bulk alarm shelving/suppression/mute outside
   normal operator patterns.
6. **Corroborate and pivot.** None of the three checks alone proves suppression;
   together, against baseline, they do — and check whether a limit was also
   changed (pivot to `detecting-alarm-setting-tampering`).
7. **Respond** (see *Response*).

## Key Concepts

- **The signal is an absence.** A single-event rule cannot see a suppressed
  alarm; you detect the gap against a baseline — the alarm, traffic, or
  heartbeat that should be there and is not.
- **Three corroborating checks.** (1) a drop in expected network traffic, (2)
  loss of operational process data (or a frozen last-good value), (3) expected
  device alarms missing from the journal. Combine them; each alone is weak.
- **Transient vs persistent.** Suppression here is run-time muting/blocking/
  non-reporting that may leave no config change — contrast with
  `detecting-alarm-setting-tampering`.
- **Protocol function values.** DNP3 disable-unsolicited (function code 21,
  0x15 - a fixed IEEE 1815 constant), IEC 61850 RCB `RptEna`=false, GOOSE
  `stNum`/`sqNum`/TTL anomalies, OPC UA subscription removal, and BACnet COV /
  Notification-class removal all suppress reporting. Vendor-specific objects and
  your Suricata/Zeek build's keyword support still need verifying against a live
  capture; prefer the liveness and missing-alarm framing, which does not depend
  on any one code. Wholesale denial of all traffic to a device (for example
  BACnet DeviceCommunicationControl) is the scope of
  `detecting-ics-communication-blocking`, not alarm suppression.

## Tools & Systems

Zeek + ICSNPP (`icsnpp-dnp3`, `icsnpp-modbus`, `icsnpp-bacnet`,
`icsnpp-opcua-binary`), Suricata, Snort, Dragos Platform, Nozomi Guardian,
Claroty CTD/xDome, Microsoft Defender for IoT, CISA
Malcolm, Security Onion, Wireshark ICS dissectors. HMI/historian: FactoryTalk
A&E, Siemens WinCC, AVEVA, Inductive Automation Ignition, OSIsoft/AVEVA PI.
SIEM: Splunk, Microsoft Sentinel. There is no official ICSNPP GOOSE parser
(`icsnpp-genisys` parses the rail-industry Genisys protocol, not IEC 61850), so
GOOSE heartbeat and `stNum`/TTL monitoring needs an OT IDS or a dedicated
third-party Zeek GOOSE parser.

## Detection Queries

### Splunk — missing-expected-alarm (process breach, no alarm) (core)

```spl
index=ot sourcetype=historian
/* field-to-field comparison is not supported in a base search (Splunk would
   compare `value` to the literal string "limit_high"), so it must be a `where`.
   If the limit is not on the event, `| lookup point_limits point OUTPUT
   limit_high` first. */
| where value>=limit_high
| join type=left device_id point [ search index=ot sourcetype=alarm_journal | stats count as alarms by device_id point ]
| where isnull(alarms) OR alarms=0   /* breach with no alarm -> suppression candidate */
| table _time, device_id, point, value, limit_high
```

### Zeek (ICSNPP) — DNP3 disable-unsolicited from a non-master host

```
# Pseudo-Zeek over icsnpp-dnp3 (is_known_master is your own helper). DNP3
# function code 21 (0x15) is DISABLE_UNSOLICITED - a fixed IEEE 1815 constant -
# and stops spontaneous event/alarm reporting.
event dnp3_application_request_header(c: connection, is_orig: bool,
                                      application: count, fc: count) {
    if ( is_orig && fc == 21 && ! is_known_master(c$id$orig_h) )
        NOTICE([$note=DNP3_DisableUnsolicited_Suspicious, $conn=c]);
}
```

### Splunk — traffic/heartbeat liveness loss

```spl
index=ot sourcetype=ics_proto
/* timechart (not stats) because stats emits no row at all for a silent bucket,
   so a zero-count minute would never reach the `where` clause below. */
| timechart span=60s count by device_id
| untable _time, device_id, msgs
| eventstats avg(msgs) as baseline by device_id
| where msgs=0 AND baseline>0   /* a device that normally reports has gone silent */
| table _time, device_id, baseline
```

### Suricata — reporting-control command from an unexpected source (local SID)

```
# DNP3 disable-unsolicited from outside the master set. Without the
# dnp3_func keyword this rule fires on every DNP3 request from a non-master.
# Confirm the rule loads with `suricata -T`; sid is a local placeholder.
alert dnp3 !$MASTERS any -> $OUTSTATIONS 20000 ( \
  msg:"DNP3 disable-unsolicited from non-master"; \
  flow:to_server; \
  dnp3_func:21; \
  sid:1000001; rev:1; )
```

## Common Scenarios

- **Suppressed reporting (Maroochy-style):** alarm reporting to the central
  computer stops; outstations go quiet and operators see no events.
- **Disable-unsolicited:** a non-master issues DNP3 disable-unsolicited and the
  outstation stops spontaneously reporting events.
- **GOOSE heartbeat gap:** a stalled `stNum`/`sqNum` or a missed heartbeat
  within the configured TTL indicates suppressed/blocked state messages.
- **Breach with no alarm:** a historian trend crosses a known limit with no
  corresponding alarm event — the negative signal.
- **False positive:** a planned outstation maintenance window where reporting is
  intentionally paused — closed by the change/liveness exception.

## Output Format

```
ALARM SUPPRESSION DETECTION
  Asset/point:     <device + point/tag>
  Verdict:         <confirmed-suppression | suspected | planned-maintenance>
  Negative signal: <breach with no alarm | missing device alarm | frozen value>
  Traffic loss:    <cyclic/unsolicited/GOOSE silence since <time> | none>
  Protocol action: <DNP3 disable-unsolicited | RCB disable | COV removal | HMI bulk shelve>
  Source:          <src host/IP>  (master/non-master)
  Config changed:  <no (transient) | yes -> pivot to detecting-alarm-setting-tampering>
  ATT&CK:          T0878
  Actions taken:   <process verified | reporting re-enabled | out-of-band alarms checked>
```

## Response

- **Treat missing alarms as a potential safety event:** manually verify the
  physical process state before anything else.
- **Restore event reporting:** re-enable unsolicited responses / RCB / COV /
  subscriptions, and check whether a limit was also changed (pivot to
  `detecting-alarm-setting-tampering`).
- **Harden:** network allowlists and segmentation so only authorized
  masters/servers can issue reporting-control commands (IEC 62443), independent
  out-of-band alarm channels (annunciators, separate SIS/safety alarms) so one
  path cannot blind operators, heartbeat/liveness monitoring for every critical
  reporting flow, and baseline models of expected alarm and traffic rates.
