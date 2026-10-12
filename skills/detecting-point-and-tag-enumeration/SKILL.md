---
name: detecting-point-and-tag-enumeration
description: 'Detects reconnaissance that enumerates ICS points and tags - OPC UA and OPC Classic browse and read walks, Modbus register sweeps, DNP3 class-0 polls, EtherNet/IP CIP tag-list reads, and S7comm block reads, plus historian tag-list queries - used to map I/O to physical functions before an operation (ATT&CK T0861; Backdoor.Oldrea and INCONTROLLER read OPC tags). Discriminates hostile enumeration from legitimate engineering by source (new or unauthorized client), breadth (wide sequential sweep), and timing, using Zeek ICSNPP, Suricata SCADA rules, OPC UA audit logs, SIEM distinct-count analytics, and Claroty, Nozomi, or Dragos baselines. Use when an unexpected host browses OPC namespaces, a register or tag sweep appears, or you are building OT recon detection. Keywords: point and tag identification, OPC UA browse, tag enumeration, Modbus register sweep, ICS recon, T0861. Do not use for a PLC logic or program upload from the controller - use detecting-plc-program-upload.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- point-and-tag-identification
- opc-ua
- tag-enumeration
- modbus
- dnp3
- ics-recon
- zeek-icsnpp
- t0861
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
- T0861
- T0845
- T0868
---

# Detecting Point and Tag Enumeration

## When to Use

Use this skill to detect **reconnaissance** in which an adversary enumerates the
points and tags operators use to represent process data — inputs, outputs, memory
locations, and their human-readable identifiers — to map I/O to physical control
functions and pick targets for a later operation (ATT&CK T0861). ATT&CK ties this
to Backdoor.Oldrea (enumerates OPC tags) and INCONTROLLER/PIPEDREAM (reads OPC UA
structures). Reach for it when:

- An unexpected host issues OPC UA Browse or OPC Classic tag-browse requests.
- A single source sweeps a wide, mostly sequential register/node range.
- You are building OT recon detection ahead of an operation.

The challenge is that browse/read looks exactly like legitimate engineering, so
the discriminators are **source**, **breadth**, and **timing** — not the operation
itself. For detection of a PLC logic/program upload from the controller, use
`detecting-plc-program-upload`.

## Prerequisites

- **Passive network monitoring** (SPAN/TAP) with ICSNPP dissection, especially
  `icsnpp-opcua-binary`, `icsnpp-modbus`, `icsnpp-enip`, `icsnpp-s7comm`.
- **A known-client baseline per server:** which client normally browses which OPC
  server, polls which outstation, reads which register ranges. This is the
  load-bearing input — learn and review it.
- **OPC UA server audit logs** where available (CreateSession + Browse with
  application URI / certificate); provide a passive-only Zeek fallback when absent.
- **Historian tag-list query logs** (PI AF / PI Points, AVEVA) with account and
  time of access.
- **A maintenance/work-order calendar** to suppress scheduled engineering.

## Workflow

1. **Baseline known clients and read volumes.** Record per-server client sets and
   each client's normal distinct-tag / distinct-register read cardinality and
   timing from a clean capture plus asset inventory (Claroty, Nozomi, Dragos).
2. **New-client browse/read (strongest signal).** Alert when an OPC UA Browse, a
   Modbus Read sweep, a DNP3 class-0 poll, a CIP tag-list read, or an S7comm block
   read originates from a host not in the known-client set for that server.
3. **Sweep heuristic (breadth).** Count distinct register addresses / node IDs
   read per source per minute; a single source reading a wide, mostly sequential
   range far above its baseline cardinality is enumeration.
4. **Timing.** Weight off-hours and burst activity; enrich with the work-order
   calendar to suppress ticketed engineering.
5. **Provenance from audit logs.** Where OPC UA audit events exist, tie a Browse
   to an unknown application URI / certificate for recon with provenance.
6. **Treat as early warning.** Raise monitoring on the implicated assets and
   proceed per *Response*.

## Key Concepts

- **The operation is normal; the context is not.** Source, breadth, and timing —
  never the browse/read verb — are the signal.
- **False positives are the central risk.** Ship a baseline-plus-maintenance-window
  method and tune the sweep threshold per site.
- **Wide and sequential beats a single read.** Address-space walks and distinct-count
  spikes expose mapping behaviour that a legitimate point read does not.
- **Audit logs add provenance but vary by vendor.** Always keep the passive Zeek
  path so detection survives servers without audit logging.
- Enumeration is a **staging foothold**, likely before a command-injection or
  program-change operation — treat a hit as early warning, not a closed case.

## Tools & Systems

Zeek + CISA/INL ICSNPP parsers (`icsnpp-opcua-binary`, `icsnpp-modbus`,
`icsnpp-enip`, `icsnpp-s7comm`), Suricata (Emerging Threats SCADA / Digital Bond
Quickdraw), Claroty CTD, Nozomi Guardian, Dragos Platform (baseline + recon
analytics), OPC UA server audit logs, Splunk OT add-ons, Microsoft Sentinel,
Wireshark.

## Detection Queries

### Zeek (icsnpp-opcua-binary) -- browse from an unknown client

```
# PSEUDO-CODE, not a real Zeek event. icsnpp-opcua-binary logs service
# request/response headers carrying a numeric service id and stubs most service
# details, so key off the Browse service id in its service log rather than a
# per-service event. Verify the id against your parser version and a live
# capture before deploying.
# KNOWN_OPCUA_CLIENTS[resp_h] = set of permitted client hosts for that server.
event opcua_service_request(c: connection, service_id: count) {   # pseudo-code
    if ( service_id == OPCUA_BROWSE_SERVICE_ID &&     # verify id for your parser
         c$id$orig_h !in KNOWN_OPCUA_CLIENTS[c$id$resp_h] )
        NOTICE([$note=OPCUA::Unexpected_Browse, $conn=c]);
}
```

### Splunk -- distinct-count sweep from a new/low-baseline source

```spl
`ot_reads` (protocol=modbus func IN (1,2,3,4)) OR (protocol=opcua op=browse OR op=read)
| bin _time span=1m
| stats dc(address) as distinct_points values(dest) as servers by src_ip, _time
/* bring known / baseline_card / sweep_threshold in from the baseline: none of
   them is produced by the stats above, so a join on an `eval known="true"`
   subsearch leaves the comparison below evaluating against nulls. */
| lookup client_baseline src_ip OUTPUT known baseline_card sweep_threshold
| where distinct_points > sweep_threshold AND (isnull(known) OR distinct_points > baseline_card*3)
| table _time, src_ip, servers, distinct_points
```

### Suricata -- Modbus read sweep from outside the master net (local SID)

```
# Use the modbus app-layer protocol and keyword: an `ip` header with no Modbus
# keyword alerts on every Modbus request from a non-master. One rule per read
# function code; keep the distinct-address rate logic in the SIEM.
# Confirm the rules load with `suricata -T`.
alert modbus !$SCADA_MASTERS any -> $SCADA_SLAVES any (
  msg:"OT-LOCAL Modbus FC3 read from unexpected source";
  flow:to_server,established;
  modbus: function 3;
  sid:1000001; rev:1;
)
alert modbus !$SCADA_MASTERS any -> $SCADA_SLAVES any (
  msg:"OT-LOCAL Modbus FC4 read from unexpected source";
  flow:to_server,established;
  modbus: function 4;
  sid:1000002; rev:1;
)
```

## Common Scenarios

- **Oldrea-style OPC walk:** an unexpected host enumerates the OPC address space —
  new-client browse + distinct-count spike fire.
- **Register mapping:** one source reads holding registers across a wide
  sequential range far above baseline — sweep heuristic fires.
- **Off-hours historian dump:** a bulk tag-list query from an unusual account at
  night — timing + account enrichment fire.
- **False positive:** a ticketed commissioning engineer browsing a new server —
  suppressed by baseline review and the work-order calendar.

## Output Format

```
POINT & TAG ENUMERATION DETECTION
  Server/target: <OPC server | historian | PLC/outstation>
  Verdict:       <confirmed | suspected | scheduled-engineering>
  Source:        <src host — in client baseline? y/n>
  Method:        <OPC UA browse | OPC Classic | Modbus read sweep | DNP3 class-0 | CIP tag-list | S7comm block read>
  Breadth:       <distinct points/nodes read in window> (baseline <N>)
  Timing:        <off-hours? burst? vs work-order calendar>
  Provenance:    <OPC UA app URI / cert from audit log | passive only>
  ATT&CK:        T0861
  Actions taken: <host isolated | monitoring raised on implicated assets | OPC UA auth enforced>
```

## Response

- **Investigate the enumerating host** as a likely staging foothold; isolate it if
  unauthorized and preserve the capture.
- **Raise monitoring** on the servers and assets whose tags were enumerated — the
  next step is often a command or program-change operation.
- **Harden:** enforce authorization on point/tag data and field-controller access
  management; require OPC UA with certificate-based auth and signed+encrypted
  channels (reject anonymous/None); segment OPC/historian servers into their own
  IEC 62443 conduit so only engineering stations browse those namespaces.
