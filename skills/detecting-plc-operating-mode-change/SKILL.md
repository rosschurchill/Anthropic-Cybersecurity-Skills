---
name: detecting-plc-operating-mode-change
description: 'Detects unauthorized PLC and controller operating-mode changes - RUN, PROGRAM or STOP, REMOTE, or a vendor service mode - issued over ICS management protocols (S7comm start and stop, CIP Stop/Run/Reset, Modbus UMAS) or via key-switch where the device logs it, often as a precursor to a malicious program download. Flags mode changes from non-allowlisted sources, off-hours, or with no change ticket, and chains a STOP transition then a download. References the Microsoft Defender for IoT PLC Operating Mode Changed alert (ATT&CK ICS T0858). Use when triaging unexpected controller STOP or RUN transitions, remote mode changes, or building key-switch and management-function enforcement. Keywords: change operating mode, PLC STOP, RUN mode, key switch, S7comm start stop, UMAS, CIP Stop, T0858. Do not use for broad SCADA intrusion detection - use detecting-attacks-on-scada-systems.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- operating-mode-change
- plc-stop
- key-switch
- s7comm
- enip-cip
- modbus-umas
- t0858
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- PR.AA-05
- PR.IR-01
mitre_attack:
- T0858
- T0868
---

# Detecting PLC Operating Mode Change

## When to Use

Use this skill to detect an adversary changing a controller operating mode (ATT&CK
ICS T0858) - RUN, PROGRAM or STOP, REMOTE, or a vendor service/firmware-update
mode - to enable program downloads, suspend process control, or access privileged
functions. A change to PROGRAM or STOP is frequently the precursor to a malicious
download, and is itself an availability and evasion action. The skill catches both
API-driven mode changes on the network and, where the device reports it, physical
key-switch changes. Reach for it when:

- Triaging an unexpected controller STOP or RUN transition.
- A remote mode change is seen against a controller.
- You are building key-switch and management-function enforcement.

Do not use for broad SCADA intrusion detection - use
`detecting-attacks-on-scada-systems`. For the download a mode change often precedes
use `detecting-plc-program-download`.

## Prerequisites

- Passive ICS network sensor on a SPAN/TAP that can see ICS management-protocol
  functions, with an industrial dissector (Zeek + CISA ICSNPP, or a vendor OT IDS).
- Device application logs and alarms where the controller emits mode transitions
  (coverage is device-dependent; device logs may also record mode *reads*.
  Adversary mode reading is ATT&CK ICS T0868 and is covered by
  `detecting-operating-mode-enumeration`, not by this skill).
- An allowlist of hosts permitted to issue mode changes and a change-management
  feed for approved windows.
- Engineering-workstation telemetry (Sysmon/EDR) and historian access for process
  halt/resume corroboration.
- Note: a physical key-switch turn may produce no network event - detection then
  depends on a device mode-change alarm/log where available.

## Workflow

1. **Baseline** which hosts may issue mode changes and the normal pattern of
   planned RUN/STOP transitions (maintenance windows).
2. **Watch management-protocol mode functions.** S7comm carries RUN/STOP via its
   PI-service start and stop functions. On CIP the generic common services are
   Reset `0x05`, Start `0x06` and Stop `0x07` - standard ODVA definitions and the
   illustrative starting point - but note that Logix run/program mode is not set
   through these generic services: it goes through vendor-specific objects, so map
   that per platform. UMAS over Modbus performs STOP/RUN on Modicon/Unity; verify
   its per-vendor sub-function against a live capture and your dissector. CIP tag
   read/write services are not the mode-change service.
3. **Score by context.** Alert on any mode-change function from a source that is
   not an allowlisted host, off-hours, or with no change ticket.
4. **Chain STOP then download.** A STOP transition immediately followed by a
   program download is the reprogramming kill-chain - high confidence.
5. **Correlate** with device mode-change alarms, EWS programming-software launch,
   and a historian halt/resume of process-value updates.
6. **Respond** (see Response).

## Key Concepts

- **Mode change is a precursor.** A STOP or PROGRAM transition frequently precedes
  a malicious download, so a STOP-then-download chain is the strongest signal.
- **S7comm-plus is encrypted.** On S7-1500 the classic start/stop function codes do
  not apply; detect by session behavior and device alarms.
- **Key-switch blindness.** A physical key-switch turn often emits no network
  event; rely on the device mode-change alarm where it exists, and state this
  coverage limit.
- **Productized reference.** Microsoft Defender for IoT emits a PLC Operating Mode
  Changed alert mapped to T0858 and queryable in Microsoft Sentinel - a concrete
  event to build on where that platform is deployed.

## Tools & Systems

Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT
(PLC Operating Mode Changed alert) with Microsoft Sentinel; Zeek with CISA ICSNPP
(`icsnpp-s7comm`, `icsnpp-enip`); Suricata or Snort with the Emerging Threats SCADA
ruleset; CISA Malcolm; Wireshark S7comm/CIP dissectors; vendor engineering software
logs (TIA Portal, Studio 5000 / RSLogix, Unity Pro / EcoStruxure Control Expert).

## Detection Queries

### Zeek (ICSNPP) -- mode transition from a non-allowlisted source (concept)

```
# icsnpp-s7comm: PI-service start/stop events -> alert when id.orig_h is not
# in the allowlist. icsnpp-enip cip.log: CIP control-class Stop/Run/Reset from
# a non-allowlisted host. Verify the mapped service/function names in your build.
```

### Suricata -- illustrative S7comm STOP from non-EWS (verify code/offset)

```
# Suricata does not support comments behind or inside a rule body, so the caveats live here
# and the rule is continued with a trailing backslash.
# The matches below are ILLUSTRATIVE: protocol-id 0x32 / ROSCTR 0x01 (job) sits just past the
# TPKT+COTP headers, and 0x29 is the classic S7comm PLC-stop function. Offsets shift with the
# S7 header variant and the stop request is carried as a PI service string on some platforms,
# so tune offset/depth/within against a live capture before deploying.
alert tcp !$EWS any -> $PLC 102 ( \
  msg:"ICS-LOCAL S7comm CPU STOP from non-EWS host (verify FC/offset)"; \
  flow:to_server,established; \
  content:"|32 01|"; offset:7; depth:2; \
  content:"|29|"; distance:0; within:16; \
  sid:1000004; rev:1; \
)
```

### Sentinel/Splunk -- mode-change event, enriched and chained

```spl
`plc_operating_mode_changed`
| where NOT src_ip IN ($MODE_CHANGE_ALLOWLIST)
| lookup change_tickets controller OUTPUT ticket_id
| join type=left controller [ search `ics_download_events`
    | eval dlTime=_time | fields controller dlTime ]
| where isnull(ticket_id)
| eval stop_then_download=if(isnotnull(dlTime) AND dlTime>=_time,"yes","no")
| table _time, controller, src_ip, new_mode, stop_then_download
```

## Common Scenarios

- **STOP then download:** a remote STOP from an unknown host, then a program
  download - the reprogramming kill-chain, escalate immediately.
- **Off-hours remote STOP:** a controller stopped at night with no change ticket;
  historian shows process-value updates halting.
- **Key-switch turn:** no network event, but a device mode-change alarm records a
  transition to PROGRAM - caught only where the device emits the alarm.
- **False positive:** a planned STOP from the sanctioned EWS inside a maintenance
  window - excluded by the allowlist and change feed.

## Output Format

```
PLC OPERATING MODE CHANGE DETECTION
  Controller:      <plc id / ip>
  Verdict:         <confirmed | suspected | approved-maintenance>
  Transition:      <RUN then STOP | STOP then RUN | to PROGRAM | to REMOTE/service>
  Vector:          <network management protocol | key-switch (device alarm)>
  Protocol:        <S7comm | CIP/EtherNet-IP | Modbus UMAS | other>
  Source:          <host ip> (allowlisted: <yes/no>)
  Chain:           <standalone | STOP then download observed>
  ATT&CK:          T0858 (related T0868)
  Actions taken:   <controller isolated | logic verified | service restored>
```

## Response

- **Contain:** treat an unauthorized STOP or mode change as an active intrusion and
  likely precursor to a download - isolate the controller, verify logic integrity
  against the golden master, and restore service through change control.
- **Harden:** enforce the physical key-switch in RUN so remote mode changes are
  blocked by hardware (the strongest control); deny mode-change functions from
  non-allowlisted sources at a protocol-aware OT firewall; require software/device
  and human-user authentication on management functions; and gate any planned mode
  change behind change control and maintenance windows.
