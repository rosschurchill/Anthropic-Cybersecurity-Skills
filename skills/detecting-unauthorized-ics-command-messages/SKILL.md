---
name: detecting-unauthorized-ics-command-messages
description: 'Detects unauthorized ICS command and spoofed reporting messages injected by a rogue master, compromised engineering workstation, or adversary-in-the-middle (ATT&CK T1692). Uses passive protocol monitoring of Modbus write function codes, DNP3 operate and CROB objects, EtherNet/IP CIP writes, S7comm, OPC UA Write, and IEC 61850 MMS and GOOSE stNum and sqNum integrity, with a source-allowlist baseline (Claroty, Nozomi, Dragos) and Zeek ICSNPP, corroborating reported values against out-of-band historian data. Use when a control write or telemetry report comes from an off-baseline source, operators see values that do not match the physical process, or you are building authorized-source detection. Keywords: unauthorized command message, spoofed reporting message, rogue master, Modbus write, DNP3 operate, GOOSE stNum, T1692. Do not use for detecting an unauthorized master station itself - use detecting-rogue-master-on-ics-network.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- unauthorized-command-message
- spoofed-reporting
- modbus
- dnp3
- iec-61850
- goose
- zeek-icsnpp
- t1692
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- PR.AA-05
- RS.MI-01
mitre_attack:
- T1692
- T1692.001
- T1692.002
- T0848
---

# Detecting Unauthorized ICS Command Messages

## When to Use

Use this skill to detect **illegitimate control/command messages** or **spoofed
reporting messages** injected into an ICS network from a source not authorized to
originate them (ATT&CK T1692). A command message drives an actuator outside its
intended function or without the expected preconditions; a reporting message
spoofs I/O or telemetry so the process looks normal or operators chase a false
fault. The originating source is typically a rogue master, a compromised
engineering workstation (EWS)/HMI, or an adversary-in-the-middle. Reach for it
when:

- A control write or Operate reaches an outstation from an off-baseline source.
- Operators see values that do not match an independent physical measurement.
- You are building authorized-source (comms-matrix) detection for OT writes.

This skill is the **message-level** detection. To detect the unauthorized master
station itself, use `detecting-rogue-master-on-ics-network`.

## Prerequisites

- **Passive network monitoring** on the process/control LAN via SPAN/TAP, with
  protocol dissection (Modbus/TCP, DNP3, EtherNet/IP + CIP, S7comm, OPC UA,
  IEC 61850 MMS/GOOSE).
- **A source-identity baseline / comms matrix:** which IP/MAC/EWS legitimately
  issues writes to which outstation. This is the load-bearing input — learn it
  from a clean capture and review it, rather than hard-coding IP lists.
- **An out-of-band value source** (independent sensor or historian tag) for
  corroborating reported values against the physical process.
- **EWS/HMI auth and session logs** to attribute an originating operator/session.
- Remember PLCs rarely run endpoint agents: detection here is **network passive
  monitoring + EWS/historian telemetry**, not controller host logs.

## Workflow

1. **Baseline authorized sources.** Build the per-outstation set of legitimate
   masters/writers from a clean capture plus asset-tool inventory (Claroty,
   Nozomi, Dragos). Record which function classes each source normally issues.
2. **Flag off-baseline writes (strongest signal).** Alert on any write-class
   operation whose source is not in the authorized-master set for that
   destination — Modbus write function codes, DNP3 Operate/Direct-Operate and
   control relay output block (CROB), CIP SetAttribute/service writes, OPC UA
   Write, IEC 61850 MMS control (Operate/SelectWithValue).
3. **GOOSE semantic integrity check.** Watch IEC 61850 GOOSE for stNum
   incrementing without a real state change, duplicate or regressing sqNum
   (replay/takeover), or two publishers for one control block (gocbRef). These
   rule-based checks meet the GOOSE real-time delivery bound where ML detectors
   cannot.
4. **Out-of-band value corroboration (spoofed reporting).** Join the reporting
   stream against an independent measurement; flag a reported-vs-measured
   divergence beyond physical tolerance even when the quality flag reads GOOD.
5. **Attribute and respond.** Correlate the source with EWS/HMI session logs;
   proceed per *Response* without auto-commanding safety-critical loops.

## Key Concepts

- **Source, not payload, is the discriminator.** A valid-looking write from an
  unauthorized source is the primary signal; behavioral framing (unexpected
  source host, off-hours, no change ticket) survives protocol encryption and
  unknown function codes.
- **S7comm-plus (S7-1500) is encrypted.** Classic S7comm job-code inspection does
  not apply there; fall back to source-allowlist and EWS endpoint telemetry.
- **Function codes are illustrative, not canonical.** Verify exact write/program
  function codes against your own dissector and baseline before relying on them.
- **Spoofed reports hide in GOOD quality.** Only an independent measurement
  exposes a telemetry value that the protocol itself vouches for.
- **Rogue master vs AiTM are delivery mechanisms;** this skill detects the message
  they carry.

## Tools & Systems

Zeek + CISA/INL ICSNPP parsers (`icsnpp-modbus`, `icsnpp-dnp3`, `icsnpp-enip`,
`icsnpp-s7comm`, `icsnpp-opcua-binary`, `icsnpp-bacnet`), Suricata with Emerging
Threats SCADA / Digital Bond Quickdraw rules, Claroty CTD, Nozomi Guardian,
Dragos Platform, Wireshark (modbus/dnp3/s7comm/goose/mms dissectors), Splunk OT
add-ons, Microsoft Sentinel, OSIsoft PI / AVEVA historian for out-of-band values.

## Detection Queries

### Zeek (icsnpp-modbus) -- write from a non-authorized master

```
# Maintain AUTHORIZED_MASTERS[resp_h] = set of permitted source hosts.
# WRITE_FCS = the write-class function codes confirmed against your baseline.
event modbus_message(c: connection, h: ModbusHeader, is_orig: bool) {
    if ( is_orig && h$function_code in WRITE_FCS &&
         c$id$orig_h !in AUTHORIZED_MASTERS[c$id$resp_h] )
        NOTICE([$note=Modbus::Unauthorized_Write, $conn=c]);
}
```

### Suricata -- DNP3 operate from outside the master net (local placeholder SID)

```
alert ip !$SCADA_MASTERS any -> $SCADA_SLAVES 20000 (
  msg:"OT-LOCAL DNP3 control/operate from unauthorized source";
  flow:to_server,established;
  dnp3_func:operate;        # tune against a live capture; alert, do not inline-drop
  sid:1000001; rev:1;
)
```

### Splunk -- reported value vs out-of-band measurement divergence

```spl
`ot_protocol_reports` tag=* reported_value=*
| join type=inner tag [ search `historian_oob` | rename value as measured ]
| eval delta=abs(reported_value-measured)
| where delta > tolerance_for_tag
| table _time, src_ip, tag, reported_value, measured, delta, quality_flag
```

## Common Scenarios

- **Rogue-master command:** an actuator Operate arrives from a host absent from
  the comms matrix — off-baseline source fires.
- **Spoofed telemetry:** a frozen or falsified tag reads GOOD quality while the
  out-of-band sensor diverges — value corroboration fires.
- **GOOSE takeover:** stNum jumps with no process change and sqNum regresses —
  GOOSE semantic rule fires.
- **False positive:** a newly commissioned, ticketed EWS issues writes — suppress
  via baseline review and change window, do not auto-trust.

## Output Format

```
UNAUTHORIZED ICS MESSAGE DETECTION
  Target:        <outstation / PLC / IED>
  Verdict:       <confirmed | suspected | authorized-change>
  Message type:  <command (T1692.001) | reporting (T1692.002)>
  Source:        <src host/MAC — in-baseline? y/n> via <protocol/function>
  Evidence:      <off-baseline write | GOOSE stNum/sqNum anomaly | value divergence>
  Corroboration: <out-of-band measured value vs reported | EWS session>
  ATT&CK:        T1692(.001/.002), T0848
  Actions taken: <source isolated | actuator to safe state | EWS creds rotated | pcap preserved>
```

## Response

- **Contain:** isolate the unauthorized source; fail the actuator to a safe state
  per the process safety plan — do **not** auto-command in safety-critical loops.
- **Attribute:** pull EWS/HMI session logs; rotate engineering-station credentials
  if an EWS was the origin.
- **Preserve:** keep the full pcap and protocol logs for the DFIR timeline.
- **Harden:** enforce source authorization and field-controller access management,
  network allowlists, and IEC 62443 zone/conduit segmentation; deploy IEC 62351
  authentication for GOOSE/MMS so spoofed publications are rejected at the wire.
