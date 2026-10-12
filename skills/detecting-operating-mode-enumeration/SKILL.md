---
name: detecting-operating-mode-enumeration
description: 'Detects operating-mode enumeration against PLCs, RTUs and IEDs - reading a controller run, program, remote or key-switch state during reconnaissance via CIP Identity-Object state reads, S7comm CPU and SZL diagnostics, Modbus vendor status reads and DNP3 or IEC 61850 MMS status queries, on the wire and in engineering-workstation logs, flagging mode reads from unexpected sources or via a read path not normally used (ATT&CK ICS T0868). Use when hunting ICS reconnaissance, when a controller run or program state is queried by a non-engineering host, or when building Zeek and Suricata coverage for mode-read functions ahead of a program or firmware change. Keywords: Detect Operating Mode, T0868, key switch, run program remote, CIP Identity Object attribute 8, S7comm SZL, UMAS, DNP3, Zeek ICSNPP, Suricata enip. Do not use for actually flipping a controller run or program mode - use detecting-plc-operating-mode-change.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- operating-mode-enumeration
- detect-operating-mode
- plc
- cip
- s7comm
- zeek
- t0868
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- ID.AM-02
mitre_attack:
- T0868
- T0858
- T0861
---

# Detecting Operating Mode Enumeration

## When to Use

Use this skill to detect an adversary **reading** a controller's operating
mode — run / program / remote, or the physical key-switch position — during
reconnaissance (ATT&CK ICS T0868, Detect Operating Mode). Mode state tells an
attacker whether reprogramming, a program download, or a firmware operation
will succeed, so a mode read is a precursor to an impactful change. Reach for
it when:

- Hunting ICS reconnaissance ahead of a suspected program or firmware change.
- A controller's run/program state is being queried by a host that is not a
  sanctioned engineering workstation (EWS) or master.
- Building Zeek/Suricata coverage for protocol mode-read functions.

This skill is about **reading** mode (collection/recon). For detection of an
adversary **changing** the mode — actually flipping run/program/stop — use
`detecting-plc-operating-mode-change`.

## Prerequisites

- **Passive network monitoring** on SPAN/TAP ports at OT boundaries with ICS
  protocol dissectors (Zeek + CISA/INL ICSNPP parsers, or an OT IDS).
- **Per-family mode map.** Mode names and the read paths that expose them are
  vendor-specific; you need to know, per controller family, which function or
  object carries operating-mode/state and which hosts legitimately read it.
- **Asset/master allowlist** of the EWS and masters that normally poll
  controller state (from Claroty / Nozomi / Dragos inventory).
- **EWS telemetry**: process-creation and "go online" / read-status events from
  TIA Portal, Studio 5000 / FactoryTalk, EcoStruxure Control Expert on the
  engineering host (Sysmon EID 1 where the EWS is Windows).
- Remember PLCs rarely run endpoint agents: detection is network + EWS +
  historian/HMI telemetry, not host logs on the controller itself.

## Workflow

1. **Baseline** which hosts legitimately read controller state, on which
   protocols, and at what cadence. Record the normal read paths per device.
2. **Flag mode reads from an unexpected source.** On the wire, alert when a
   mode/state read reaches a controller from a source not on the EWS/master
   allowlist — the single strongest behavioral signal.
3. **Flag an unusual read path.** A mode read via a function or object not used
   for mode in this environment (even from a known host) is suspicious; tie it
   to the per-family map rather than to a fixed hex code.
4. **Correlate read then write.** In the SIEM, join a mode read to the same
   host's subsequent program download, parameter write, or firmware activity —
   a mode read tightly followed by a write is the high-value sequence.
5. **Confirm context.** Check for a change window, maintenance task, or
   authorized engineer that explains the read before escalating.
6. **Respond** (see *Response*).

## Key Concepts

- **Read is recon, not impact.** The read itself changes nothing; its value is
  as a precursor. The alert earns priority from *who* read and *what follows*.
- **Behavioral framing beats byte matching.** Unexpected source, off-hours, no
  change ticket, and read-then-write sequencing are robust; exact function
  codes vary by vendor and version and must be verified against your dissector.
- **State is not the same as run/program.** The CIP Identity Object is class
  `0x01` and its State is attribute `8`, with a fixed ODVA enum: 0 nonexistent,
  1 device self-testing, 2 standby, 3 operational, 4 major recoverable fault,
  5 major unrecoverable fault. What that attribute does **not** encode is Logix
  run-vs-program mode or key-switch position — that detail is read through
  vendor-specific objects, and that mapping is what must be verified per
  platform.
- **S7comm-plus (S7-1200/1500) is encrypted.** Classic S7comm SZL/CPU-function
  reads do not apply there; fall back to EWS and endpoint telemetry.

## Tools & Systems

Zeek + ICSNPP (`icsnpp-enip`, `icsnpp-s7comm`, `icsnpp-modbus`,
`icsnpp-dnp3`), Suricata, Snort, Dragos Platform, Nozomi Networks Guardian,
Claroty CTD/xDome, Microsoft Defender for IoT, CISA Malcolm, Security Onion,
Wireshark ICS dissectors. EWS/engineering software (as the legitimate read
baseline): Siemens TIA Portal, Rockwell Studio 5000 / FactoryTalk, Schneider
EcoStruxure Control Expert (Unity Pro). SIEM: Splunk, Microsoft Sentinel.

## Detection Queries

Protocol mode-read functions are **illustrative** below. Verify the exact
function/class/attribute values against your protocol dissector and a live
capture before deploying — prefer the behavioral source/path framing, which
does not depend on the exact code.

### Zeek (ICSNPP) — CIP Identity state read from a non-engineering host

```
# Pseudo-Zeek over icsnpp-enip CIP fields.
# Identity Object is class 0x01 and device State is attribute 8 - a fixed ODVA
# definition. State does NOT carry Logix run/program or key-switch position; for
# that, map the vendor-specific object per platform and match on it instead.
event cip_get_attribute(c: connection, class_id: count, instance: count, attribute: count) {
    if ( class_id == 0x01 && attribute == 8 && ! is_known_ews(c$id$orig_h) )
        NOTICE([$note=CIP_OperatingMode_Read_From_Unexpected_Host, $conn=c]);
}
```

### Zeek (ICSNPP) — DNP3 and IEC 61850 MMS status reads (concept)

```
# DNP3 (TCP/20000), via icsnpp-dnp3 (dnp3.log records the function code and the
# object group/variation): the closest DNP3 equivalent of a mode read is a
# function code 1 (READ) request for object group 80 variation 1, Internal
# Indications - the outstation status bits, which include local-control and
# device-trouble state. Alert when such a read reaches an outstation from a host
# outside the DNP3 master allowlist, and on repeated sweeps across outstations.

# IEC 61850 MMS (TCP/102): an MMS Read naming the logical device's LLN0 Mod or Beh
# data attributes (e.g. <LD>/LLN0$ST$Beh$stVal) returns the IED's mode/behaviour -
# on / blocked / test / test-blocked / off. Alert on MMS Read requests for LLN0
# Mod/Beh from a client that is not an allowlisted station-bus client. This needs a
# sensor that parses MMS object names; verify your build exposes them before relying
# on the object-name match, and otherwise fall back to source-allowlist framing.
```

### Suricata — operating-mode read from outside the master net (local SID)

```
# PREREQUISITE: the enip app-layer parser is DISABLED BY DEFAULT in suricata.yaml, so an
# `alert enip` rule never matches until app-layer.protocols.enip.enabled: yes is set.
# The source must exclude the sanctioned engineering/master net, or the rule fires on all
# ENIP traffic including the EWS's own polling.
# The cip_service / cip_class / cip_attribute matches below are ILLUSTRATIVE - they target
# Get_Attribute_Single (0x0e) on Identity Object class 0x01 attribute 8. Keyword names and
# CIP class/attribute matching vary by Suricata build; verify support and tune against a
# live capture, and fall back to the Zeek analytic above where the keywords are absent.
# sid is a local placeholder.
alert enip !$EWS_NET any -> $PLC_NET 44818 ( \
  msg:"ICS operating-mode read from non-EWS host (verify CIP fields)"; \
  flow:to_server; \
  cip_service:0x0e; \
  cip_class:0x01; \
  cip_attribute:8; \
  threshold:type limit, track by_src, count 1, seconds 60; \
  sid:1000001; rev:1; )
```

### Splunk — mode read tightly followed by a write (the escalation)

A host missing from `authorized_ews` gets a **null** `authorized`, and SPL comparisons
against null are false — so `where authorized!="true"` on its own filters out exactly
the unknown hosts this analytic is looking for and leaves only known-but-unauthorised
rows. Test for the null explicitly.

```spl
index=ot (sourcetype=ics_proto action=mode_read OR sourcetype=ews_audit action="go_online")
| eval readTime=_time
| join src_host [ search index=ot sourcetype=ics_proto action IN ("program_download","param_write","firmware_update") | eval writeTime=_time ]
| where writeTime>=readTime AND (writeTime-readTime) < 1800
| lookup authorized_ews host AS src_host OUTPUT authorized
| where isnull(authorized) OR authorized!="true"
| table readTime, src_host, dest_device, writeTime
```

## Common Scenarios

- **Recon before a download:** a non-EWS host reads CIP Identity state across a
  cell, then one device receives a program download minutes later — read-then-
  write correlation fires.
- **S7comm SZL sweep:** CPU-function/SZL diagnostics reads from an unknown host
  on classic S7comm (verify SZL IDs against your dissector).
- **Modbus vendor status read:** a Schneider UMAS "read PLC status" over its
  vendor function (verify the sub-function), or FC 0x2B/43 MEI Read Device
  Identification, from outside the master net.
- **False positive:** a sanctioned EWS reading status during an approved change
  window — closed by the allowlist and change-window lookup.

## Output Format

```
OPERATING MODE ENUMERATION DETECTION
  Target device:   <PLC/RTU/IED id + IP>
  Verdict:         <confirmed-recon | suspected | authorized-maintenance>
  Read source:     <src host/IP/MAC>  (on/off EWS-master allowlist)
  Protocol/path:   <CIP Identity state | S7comm SZL | Modbus vendor status | DNP3/MMS status>
  Read cadence:    <single | repeated/sweep>  off-hours: <yes/no>
  Follow-on:       <program download | param write | firmware mode | none> within <window>
  Change ticket:   <matched | none>
  ATT&CK:          T0868
  Actions taken:   <source investigated | host isolated | allowlist enforced | escalated>
```

## Response

- **Investigate** the source host and the account behind the read; confirm
  whether a change window or maintenance task explains it.
- **Watch for the follow-on.** Treat a subsequent program download, parameter
  write, or firmware-mode entry from the same host as escalation and respond to
  that technique.
- **Harden:** enforce host/master allowlists and segmentation so only
  sanctioned EWS can query controller state (IEC 62443 zones/conduits); keep
  controllers in RUN with the key-switch physically keyed so program operations
  require a local action; monitor every mode-read path, not just one protocol.
