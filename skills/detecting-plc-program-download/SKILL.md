---
name: detecting-plc-program-download
description: 'Detects unauthorized PLC and controller program downloads - full downloads, online edits, and program appends that write or install new control logic onto a controller over engineering protocols (S7comm, EtherNet/IP CIP, Modbus UMAS) or from an engineering workstation. Flags transfers from non-allowlisted source hosts, off-hours, or with no change ticket, correlating network programming functions with EWS programming-software launches and golden-master logic diffs. Use when triaging suspected PLC reprogramming, unexpected controller STOP then RUN transitions, downloads from an unknown host, or building engineering-source allowlisting. Keywords: PLC program download, S7comm, UMAS, CIP, TIA Portal, Studio 5000, online edit, ICSNPP, Stuxnet, T0843. Do not use for passive S7comm protocol assessment or logic static analysis - use performing-s7comm-protocol-security-analysis.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- plc-program-download
- s7comm
- enip-cip
- modbus-umas
- engineering-workstation
- icsnpp
- t0843
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- PR.AA-05
- ID.AM-02
mitre_attack:
- T0843
- T0845
- T0889
---

# Detecting PLC Program Download

## When to Use

Use this skill to detect an adversary transferring new or altered control logic
**into** a PLC or controller (ATT&CK ICS T0843): a full download, an online edit,
or a program append delivered over an engineering protocol or from an engineering
workstation (EWS). This is the write side of logic tampering - the Stuxnet-style
reprogramming and PLC-Blaster propagation pattern - so catching it early lets
defenders intervene before malicious logic runs the process. Reach for it when:

- Triaging a suspected PLC reprogramming or an unexpected STOP then RUN sequence.
- A program-transfer function appears from a host that is not a known EWS.
- Downloads land off-hours or without a matching change ticket.

Do not use for passive S7comm protocol assessment or static logic analysis - use
`performing-s7comm-protocol-security-analysis`. For the read counterpart (pulling
logic off a controller) use `detecting-plc-program-upload`; for the resulting
integrity drift use `detecting-plc-logic-modification`.

## Prerequisites

- Passive ICS network sensor on a SPAN/TAP at the cell or control layer, with an
  industrial-protocol dissector (Zeek + CISA ICSNPP, or a vendor OT IDS).
- An allowlist of legitimate engineering stations and the controller programming
  endpoints they are permitted to reach.
- Engineering-workstation telemetry (Sysmon/EDR): process creation of vendor
  programming software and project-file opens or writes.
- A golden-master logic repository to diff against, plus a change-management feed
  for approved maintenance windows.
- Note: PLCs rarely run endpoint agents. Detection is network monitoring plus EWS
  telemetry plus historian/HMI context, not host logs on the controller.

## Workflow

1. **Baseline** which hosts are engineering stations, the normal download cadence,
   and the approved maintenance windows.
2. **Watch for program-transfer functions** on the wire. On S7comm the classic
   job set covers request-download, download-block, and download-ended functions
   (verify the exact function codes against your protocol dissector and a live
   capture before trusting any single byte). Downloads are usually bracketed by a
   STOP then RUN transition.
3. **Score by context, not by the code alone.** Raise an alert when a download is
   seen from a source that is not an allowlisted EWS, outside a change window, or
   with no corresponding change ticket.
4. **Correlate** the network transfer with an EWS programming-software launch
   (Sysmon EID 1) within a short window, and with the change feed.
5. **Confirm effect** with a golden-master logic diff after any observed download
   (feeds `detecting-plc-logic-modification`).
6. **Respond** (see Response).

## Key Concepts

- **Behavior beats the byte.** The strongest signal is an unexpected source host,
  off-hours timing, or a missing change ticket - framing that does not depend on
  an exact, vendor-specific function code.
- **S7comm-plus is encrypted.** On S7-1500 controllers the classic S7comm function
  codes do not apply; fall back to session/behavioral detection and EWS endpoint
  telemetry.
- **Unauthenticated protocols.** CIP on EtherNet/IP and UMAS over Modbus are
  largely unauthenticated at the application layer, so source allowlisting at a
  protocol-aware firewall is the practical control.
- **STOP/RUN bracket.** A full download typically forces the CPU to STOP first; a
  stealthy online edit may not, which is why the integrity diff is the backstop.

## Tools & Systems

Zeek with CISA ICSNPP (`icsnpp-s7comm` emits an upload/download log; `icsnpp-enip`
emits `cip.log`); Suricata or Snort with the Emerging Threats SCADA ruleset; CISA
Malcolm (bundles Zeek + Suricata + Arkime); Dragos Platform, Nozomi Guardian/
Vantage, Claroty CTD, Microsoft Defender for IoT; Wireshark S7comm/ENIP/CIP
dissectors; vendor engineering software and its logs (TIA Portal, Studio 5000 /
RSLogix, Unity Pro / EcoStruxure Control Expert, GX Works).

## Detection Queries

### Zeek (ICSNPP) -- download from a non-EWS host (concept)

```
# icsnpp-s7comm upload/download log: alert when a download event's
# id.orig_h is NOT in the engineering-station allowlist.
# icsnpp-enip cip.log: alert on control-class CIP services to a
# controller from a host that is not a known EWS.
```

### Suricata -- illustrative Modbus/UMAS program transfer from non-EWS

```
alert modbus !$EWS any -> $PLC 502 (
  msg:"ICS-LOCAL UMAS program/config transfer to PLC from non-EWS (verify FC)";
  flow:to_server; app-layer-protocol:modbus;
  # UMAS rides Modbus as a reserved vendor function code; verify the exact
  # code and byte offset against a live capture and your dissector before use.
  threshold:type limit, track by_src, count 1, seconds 60;
  sid:1000001; rev:1;
)
```

### Splunk -- network download joined to EWS launch and change feed

```spl
`ics_download_events` dest_ip=$PLC
| where NOT src_ip IN ($EWS_ALLOWLIST)
| join type=left src_ip [ search `sysmon` EventCode=1
    (Image="*TIA*" OR Image="*RSLogix*" OR Image="*ControlExpert*")
  | eval ewsLaunch=_time | fields src_ip ewsLaunch ]
| lookup change_tickets dest_ip OUTPUT ticket_id
| where isnull(ticket_id)
| table _time, src_ip, dest_ip, ewsLaunch
```

## Common Scenarios

- **Reprogramming from an unknown host:** a download to a controller from an IP
  that is not an engineering station, with no change ticket - high confidence.
- **Off-hours online edit:** a program append at 02:00 with no STOP transition;
  the golden-master diff confirms the running logic changed.
- **S7-1500 (encrypted):** no classic function code visible; detection falls back
  to an unexpected engineering session plus an EWS programming-software launch.
- **False positive:** a scheduled vendor backup or an approved maintenance window
  download from the sanctioned EWS - excluded by the allowlist and change feed.

## Output Format

```
PLC PROGRAM DOWNLOAD DETECTION
  Controller:      <plc id / ip>
  Verdict:         <confirmed | suspected | approved-change>
  Transfer:        <full download | online edit | program append>
  Protocol:        <S7comm | CIP/EtherNet-IP | Modbus UMAS | other>
  Source:          <host ip> (EWS allowlisted: <yes/no>)
  Window:          <in-change-window: yes/no> ticket: <id | none>
  Corroboration:   <STOP/RUN bracket | EWS sw launch | golden-master diff>
  ATT&CK:          T0843 (related T0845, T0889)
  Actions taken:   <controller isolated | logic restored | source blocked>
```

## Response

- **Contain:** isolate the controller, capture the transferred program for
  forensics, and restore known-good logic from the golden master through change
  control - never hot-patch in place.
- **Harden:** allowlist engineering sources so only named EWS may reach controller
  programming ports; deploy a protocol-aware OT firewall or data diode at the
  conduit; enforce the physical key-switch in RUN to block remote downloads;
  require software/device and human-user authentication on programming functions;
  use code signing where the platform supports it; and gate every download behind
  change control and maintenance windows.
