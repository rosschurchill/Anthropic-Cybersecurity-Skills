---
name: detecting-rogue-master-on-ics-network
description: 'Detects a rogue master on an ICS network - an unauthorized control server, SCADA master, HMI or engineering station placed on the OT network to drive outstations with legitimate control functions, or to intercept traffic meant for the real master (ATT&CK ICS T0848). Uses asset-baseline and ARP or DHCP deviation, control and write traffic from IPs or MACs not on the authorized-master allowlist, new master-to-outstation sessions, and unexpected protocol functions (Modbus writes, DNP3 SELECT and OPERATE, CIP write-tag, S7comm PLC control) from new or known devices. Use when an unknown device issues writes or control on OT, when a new master-to-outstation flow appears, or when building rogue-master detection on Zeek, Suricata, Dragos or Nozomi. Keywords: Rogue Master, T0848, unauthorized master, authorized-master allowlist, new asset, ARP anomaly, DNP3 OPERATE, Modbus write, port security. Do not use for analysing the illegitimate control messages themselves - use detecting-unauthorized-ics-command-messages.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- rogue-master
- lateral-movement
- asset-baseline
- arp
- zeek
- t0848
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- ID.AM-02
- PR.AA-05
- PR.IR-01
mitre_attack:
- T0848
- T1692
---

# Detecting Rogue Master on ICS Network

## When to Use

Use this skill to detect an unauthorized/**rogue master** — a control server,
SCADA master, HMI, or engineering station placed on the OT network to drive
outstations via legitimate control-server functions (reads, writes, control
commands), or to intercept traffic meant for the real master (ATT&CK ICS
T0848, Rogue Master). The focus is **who is acting as master**: a new or
unexpected station exercising master-role behavior. Reach for it when:

- An unknown device issues writes or control commands on an OT segment.
- A new master-to-outstation flow appears that is not in the communication
  matrix.
- Building rogue-master detection on Zeek/Suricata or an OT monitoring platform.

This skill is about identifying the unauthorized master (asset/ARP baseline +
master-role behavior). For analysis of the **illegitimate control messages
themselves** — the command content — use
`detecting-unauthorized-ics-command-messages`.

## Prerequisites

- **Authorized-master inventory** and the master-to-outstation **communication
  matrix** (from Claroty / Nozomi / Dragos): which masters, HMIs, and EWS exist
  and which outstations each legitimately talks to. New devices or new flows are
  the primary signal.
- **Function-level allowlist for known devices.** The hard case is an
  authorized historian vs a rogue one; distinguishing them needs
  which-device-may-issue-which-function-to-which-outstation, not just IP.
- **Passive protocol monitoring** (Zeek + ICSNPP, or an OT IDS) on SPAN/TAP
  ports covering operational protocol ports.
- **DHCP/ARP visibility** and **switch telemetry** (port security /
  MAC-notification) to catch a new host and ARP anomalies.
- Detection is network + asset baseline + switch infra, not controller host
  logs — PLCs/RTUs rarely run endpoint agents.

## Workflow

1. **Baseline** the authorized-master set, the communication matrix, and the
   per-device function allowlist.
2. **New-device detection.** Alert on an unknown IP/MAC opening sessions on
   operational protocol ports, on a new DHCP lease or ARP announcement for an
   unknown host on an OT VLAN, and on a new MAC on a switch port.
3. **ARP anomalies.** Flag duplicate-IP or changed IP-to-MAC bindings — a rogue
   master may also be doing adversary-in-the-middle to capture the real
   master's traffic.
4. **Master-role behavior.** Alert when a device establishes master-side
   sessions with outstations (polling/writing, enabling or disabling unsolicited
   reporting) from outside the authorized-master set.
5. **Unexpected functions from known devices (hard case).** Using the
   function-level allowlist, flag control/write functions from a device not
   permitted to issue them to that outstation.
6. **Enrich and triage.** Auto-close known maintenance laptops via the asset
   inventory; route the rest to an analyst to confirm legitimacy.
7. **Respond** (see *Response*).

## Key Concepts

- **Identity first, then behavior.** The strongest signal is a device that is
  not on the authorized-master list exercising master-role behavior — but the
  known-device-rogue-behavior case needs function-level allowlisting, not IP
  alone.
- **A rogue master can also be AiTM.** ARP duplication / changed bindings mean
  it may be intercepting the real master's traffic as well as issuing commands —
  check both.
- **Protocol function values are illustrative.** Control/write functions include
  Modbus write function codes, DNP3 SELECT / OPERATE / DIRECT-OPERATE and
  restart, CIP Set_Attribute_Single / write-tag, and S7comm write-var / PLC
  control / PLC stop. CIP ForwardOpen is **not** a control function - it
  establishes a Class 1/3 connection and carries no write semantics - but a
  ForwardOpen from an unknown source is still a useful new-flow signal. Verify the exact function codes and your Suricata/Zeek keyword
  support against the deployed dissector and a live capture; prefer the
  authorized-master allowlist framing, which does not depend on the exact code.
  Classic S7comm codes do not apply to encrypted S7comm-plus (S7-1500) — fall
  back to asset-baseline and session-source detection there.

## Tools & Systems

Dragos Platform, Nozomi Networks Guardian, Claroty CTD/xDome (asset baseline +
new-device / new-communication alerts), Zeek + ICSNPP (`icsnpp-modbus`,
`icsnpp-dnp3`, `icsnpp-enip`, `icsnpp-s7comm`, `icsnpp-bacnet`), Suricata,
Snort, Microsoft Defender for IoT, CISA Malcolm, Security Onion, Wireshark ICS
dissectors. SIEM: Splunk, Microsoft Sentinel; some SIEMs ship ICS correlation
content that can be adapted to this use case - verify what exists in your own
platform's rule library rather than assuming it. Switch infra: port security /
802.1X, dynamic ARP inspection.

## Detection Queries

Protocol function values below are **illustrative** — verify against your
dissector and a live capture; the authorized-master allowlist and new-asset
baseline are the vendor-agnostic anchors.

### Zeek (ICSNPP) — write/control from a non-authorized master

```
# Pseudo-Zeek over icsnpp-modbus / icsnpp-dnp3.
# Verify is_write_fc()/function-code values against your dissector.
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    if ( is_orig && is_write_fc(headers$function_code) && ! is_authorized_master(c$id$orig_h) )
        NOTICE([$note=Rogue_Master_Write, $conn=c,
                $msg=fmt("write FC %d from %s", headers$function_code, c$id$orig_h)]);
}
# Pair with ARP monitoring for duplicate-IP / changed-binding alerts.
```

### Suricata — control function from outside the authorized-master set (local SID)

```
# Verify dnp3_func/modbus keyword values in your Suricata build; tune against
# a live capture. sid is a local placeholder.
alert dnp3 !$AUTHORIZED_MASTERS any -> $OUTSTATIONS 20000 ( \
  msg:"Rogue DNP3 master: control from unauthorized source (verify func)"; \
  flow:to_server; \
  sid:1000001; rev:1; )
```

### Splunk — first-seen master-to-outstation tuple + ARP/DHCP new host

```spl
index=ot sourcetype=ics_proto role=master
| stats earliest(_time) as first_seen by src_mac, dest_outstation, protocol
| where first_seen >= relative_time(now(), "-1d@d")
| lookup authorized_masters src_mac OUTPUT authorized
| where authorized!="true"
/* Correlate on src_mac: `append` would only stack uncorrelated ARP/DHCP rows
   under the table. $OT_VLANS is Suricata/Snort variable syntax and does not
   resolve in SPL - list your OT VLANs explicitly or define an `ot_vlans` macro
   / lookup. */
| join type=left src_mac
    [ search index=ot sourcetype IN (dhcp,arp)
        event IN ("new_lease","arp_announce","ip_mac_change") vlan IN ("10","20")
    | stats earliest(_time) as host_first_seen values(event) as host_events by src_mac ]
| table first_seen, src_mac, dest_outstation, protocol, host_first_seen, host_events
```

## Common Scenarios

- **New station issuing control:** an unknown IP/MAC appears on an OT VLAN and
  begins DNP3 OPERATE to outstations — new-asset + non-authorized-master alert.
- **Rogue HMI with AiTM:** a device announces a duplicate IP / changed binding
  and both intercepts the real master's traffic and issues writes.
- **Known device, rogue behavior:** an authorized historian begins issuing
  write/control functions it never used — caught only by the function-level
  allowlist.
- **False positive:** a sanctioned maintenance laptop registered in the asset
  inventory for an approved task — auto-closed by enrichment.

## Output Format

```
ROGUE MASTER DETECTION
  Suspect device:  <IP + MAC + switch port if known>
  Verdict:         <confirmed-rogue | suspected | known-maintenance>
  Basis:           <new asset | non-authorized-master write/control | ARP anomaly | new flow>
  Master behavior: <polling | writes | SELECT/OPERATE | unsolicited enable/disable>
  Target(s):       <outstation(s) reached>
  AiTM:            <duplicate IP / changed binding observed | none>
  Function check:  <function outside device allowlist | n/a>
  ATT&CK:          T0848
  Actions taken:   <port disabled | device located/isolated | outstation writes reviewed/rolled back>
```

## Response

- **Locate** the rogue device physically (switch port / MAC), **isolate** it
  (disable the port), and verify no outstation received malicious writes/control
  during its presence; roll back any unauthorized parameter/program changes.
- **Harden:** switch port security / 802.1X / MAC allowlisting on OT access
  ports, static ARP or ARP inspection on critical segments, strict segmentation
  and conduit allowlists so only sanctioned masters reach outstations (IEC
  62443), protocol-level authentication where available (DNP3 Secure
  Authentication, OPC UA security), and continuous asset-baseline monitoring.
