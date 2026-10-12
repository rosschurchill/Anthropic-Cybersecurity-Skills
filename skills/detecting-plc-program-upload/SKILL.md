---
name: detecting-plc-program-upload
description: 'Detects unauthorized PLC and controller program uploads - an adversary reading running control logic OFF a controller as reconnaissance before tampering, over engineering protocols (S7comm upload sequence, EtherNet/IP CIP read-class services, Modbus UMAS) or from an engineering workstation. Flags uploads from non-allowlisted source hosts, off-hours, or with no change ticket, and chains an upload later followed by a download as a recon then tamper sequence. Use when triaging suspicious engineering sessions, unexpected logic or tag reads from an unknown host, point and tag enumeration, or building engineering-source allowlisting. Keywords: PLC program upload, S7comm upload, CIP read, UMAS, point and tag identification, TIA Portal, Studio 5000, reconnaissance, ICSNPP, T0845. Do not use for detecting logic being written INTO a controller - use detecting-plc-program-download.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- plc-program-upload
- s7comm
- enip-cip
- modbus-umas
- reconnaissance
- icsnpp
- t0845
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
- T0845
- T0843
- T0861
---

# Detecting PLC Program Upload

## When to Use

Use this skill to detect an adversary **reading** control logic off a PLC or
controller (ATT&CK ICS T0845). In vendor terminology an upload has the controller
as the source: the attacker pulls the running program to understand the process
before crafting a Program Download (T0843) or modifying the logic. An upload is a
collection and reconnaissance step, so catching an unexpected one gives early
warning of activity that precedes logic tampering. Reach for it when:

- Triaging a suspicious engineering session or a logic read from an unknown host.
- Point-and-tag or program enumeration appears against a controller.
- You are building an engineering-source allowlist and want to see who reads logic.

Do not use for detecting logic being written **into** a controller - use
`detecting-plc-program-download`. For the integrity effect of a change use
`detecting-plc-logic-modification`.

## Prerequisites

- Passive ICS network sensor on a SPAN/TAP with an industrial-protocol dissector
  (Zeek + CISA ICSNPP, or a vendor OT IDS).
- An allowlist of legitimate engineering stations; an upload from anything else is
  suspect.
- Engineering-workstation telemetry (Sysmon/EDR): launch of vendor programming
  software and creation of exported project or listing files on the host.
- A change-management feed to distinguish approved logic backups from recon.
- Note: PLCs rarely run endpoint agents - rely on network monitoring plus EWS and
  historian context, not controller host logs.

## Workflow

1. **Baseline** which hosts are engineering stations and the normal cadence of
   legitimate uploads (scheduled backups are common and benign).
2. **Watch for upload functions** on the wire. On S7comm the classic upload
   sequence covers start-upload, upload, and end-upload functions (verify the
   exact function codes against your dissector and a live capture; do not assert a
   single byte as fact).
3. **Score by context, not the action.** An upload is a legitimate engineering
   operation, so the signal is a source that is not an allowlisted EWS, off-hours
   timing, or no change ticket.
4. **Correlate** with an EWS programming-software launch (Sysmon EID 1) on the
   source and with the change feed.
5. **Chain the sequence.** An upload (T0845) later followed by a download (T0843)
   to the same controller is a high-confidence recon-then-tamper chain - escalate.
6. **Respond** (see Response).

## Key Concepts

- **Upload-only is often benign.** Isolated uploads are frequently legitimate
  backups; treat an upload primarily as enrichment that raises severity on a later
  download, not as a standalone incident, unless the source or timing is wrong.
- **Point and tag identification.** Enumerating tags, points, and program blocks
  (ATT&CK ICS T0861) is reconnaissance that often precedes or accompanies an
  upload - correlate the two.
- **S7comm-plus is encrypted.** On S7-1500 the classic upload function codes do
  not apply; detect on session behavior and EWS endpoint telemetry.
- **Unauthenticated reads.** CIP read-class services and UMAS read sub-functions
  are largely unauthenticated, so source allowlisting is the practical control.

## Tools & Systems

Zeek with CISA ICSNPP (`icsnpp-s7comm` upload/download log; `icsnpp-enip`
`cip.log`); Suricata or Snort with the Emerging Threats SCADA ruleset; CISA
Malcolm; Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender
for IoT; Wireshark S7comm/CIP dissectors; vendor engineering software and logs
(TIA Portal, Studio 5000 / RSLogix, Unity Pro / EcoStruxure Control Expert).

## Detection Queries

### Zeek (ICSNPP) -- upload from a non-EWS host (concept)

```
# icsnpp-s7comm upload/download log: alert on UPLOAD events whose
# id.orig_h is NOT in the engineering-station allowlist.
# icsnpp-enip cip.log: alert on read-class CIP services to a controller
# from a host that is not a known EWS.
```

### Suricata -- illustrative S7comm upload from non-EWS (verify codes)

```
# Suricata does not support comments behind or inside a rule body, so the caveats live here
# and the rule is continued with a trailing backslash.
# Classic S7comm start-upload is function 0x1D, with upload 0x1E and upload-end 0x1F
# completing the sequence (Wireshark's s7comm dissector parses them; icsnpp-s7comm surfaces
# them in s7comm_upload_download.log). The matches below are ILLUSTRATIVE: the protocol-id
# 0x32 / ROSCTR 0x01 (job) pair sits just past the TPKT+COTP headers, and the function-code
# offset shifts with the S7 header variant - tune offset/depth/within against a live capture
# before deploying.
alert tcp !$EWS any -> $PLC 102 ( \
  msg:"ICS-LOCAL S7comm program UPLOAD from non-EWS host (verify FC/offset)"; \
  flow:to_server,established; \
  content:"|32 01|"; offset:7; depth:2; \
  content:"|1d|"; distance:0; within:16; \
  threshold:type limit, track by_src, count 1, seconds 60; \
  sid:1000002; rev:1; \
)
```

### Splunk -- upload then later download chain to the same controller

```spl
`ics_upload_events` dest_ip=$PLC
| where NOT src_ip IN ($EWS_ALLOWLIST)
| eval uploadTime=_time
| join dest_ip [ search `ics_download_events` | eval dlTime=_time ]
| where dlTime > uploadTime AND (dlTime - uploadTime) < 86400
| table uploadTime, dlTime, src_ip, dest_ip
```

## Common Scenarios

- **Recon then tamper:** an upload from an unknown host, then a program download
  to the same controller hours later - the strongest chain, escalate immediately.
- **Tag enumeration:** a host sweeps points and tags (T0861) and then uploads the
  program - reconnaissance before a crafted write.
- **S7-1500 (encrypted):** no classic upload code; detection relies on an
  unexpected engineering session plus an EWS programming-software launch.
- **False positive:** a nightly backup from the sanctioned EWS inside a change
  window - excluded by the allowlist and change feed.

## Output Format

```
PLC PROGRAM UPLOAD DETECTION
  Controller:      <plc id / ip>
  Verdict:         <confirmed-recon | suspected | approved-backup>
  Read:            <program upload | tag/point enumeration | config read>
  Protocol:        <S7comm | CIP/EtherNet-IP | Modbus UMAS | other>
  Source:          <host ip> (EWS allowlisted: <yes/no>)
  Window:          <in-change-window: yes/no> ticket: <id | none>
  Chain:           <upload only | upload then download observed>
  ATT&CK:          T0845 (related T0843, T0861)
  Actions taken:   <monitoring raised | source blocked | logic verified>
```

## Response

- **Contain:** treat an unexpected upload as reconnaissance - raise monitoring on
  that controller, verify its logic integrity against the golden master, and watch
  for a follow-on download.
- **Harden:** allowlist engineering sources and restrict controller programming
  ports to named EWS via a protocol-aware OT firewall or data diode; require
  software/device and human-user authentication on engineering sessions; and audit
  upload events against change control so routine backups are recognized and recon
  stands out.
