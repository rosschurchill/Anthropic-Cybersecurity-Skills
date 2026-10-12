---
name: detecting-blocked-ot-messages
description: 'Detects blocked OT messages where an adversary selectively drops or withholds specific command or reporting messages while the link still looks up, freezing the operator view or denying control (ATT&CK T1691; 2015 Ukraine serial-converter firmware example). Uses an expected-message cadence baseline over DNP3, Modbus, EtherNet/IP cyclic I/O, IEC 61850 GOOSE and MMS, and OPC UA subscriptions, request-without-response gap detection, GOOSE stNum and sqNum stall rules, and historian stale-quality flags, correlated with SCADA comms-fail alarms in Zeek, Suricata, Claroty, Nozomi, and Dragos. Use when telemetry freezes, an expected message is missing, outstations go quiet, or commands are not acknowledged while the link is still reachable. Keywords: blocked OT message, missing expected message, request without response, GOOSE stall, stale quality, T1691. Do not use for wholesale link or comms denial affecting all traffic - use detecting-ics-communication-blocking.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- blocked-ot-message
- missing-traffic
- dnp3
- modbus
- iec-61850
- goose
- historian
- t1691
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- DE.AE-04
- RS.MI-01
mitre_attack:
- T1691
- T1691.001
- T1691.002
- T1695
---

# Detecting Blocked OT Messages

## When to Use

Use this skill to detect **selective interference** with OT messages — an
adversary preventing specific command or reporting messages from reaching their
target while the link otherwise appears up (ATT&CK T1691). Blocking **reporting**
messages hides the attacker's actions and freezes the operator's view; blocking
**command** messages denies control. ATT&CK's example is the 2015 Ukraine power
attack, where adversaries used malicious firmware to render serial-to-Ethernet
converters inoperable. Reach for it when:

- Historian tags freeze at last-known value or go stale while the RTU is pingable.
- A master's poll or Operate is seen on the wire with no matching response.
- Outstations go quiet one-sidedly or commands are not acknowledged.

The distinguishing condition here is **one path lost while the link is still
reachable**. For wholesale link/medium denial affecting all traffic, use
`detecting-ics-communication-blocking`.

## Prerequisites

- **Passive network monitoring** (SPAN/TAP) with protocol dissection for DNP3,
  Modbus, EtherNet/IP cyclic I/O, IEC 61850 GOOSE/MMS, and OPC UA.
- **A learned expected-message cadence** per link: DNP3 unsolicited responses and
  integrity polls, Modbus poll/response round-trips, GOOSE heartbeat
  republication, MMS report-control-block reports, CIP Class 1 cyclic packets,
  OPC UA subscription keep-alive/PublishResponse. Learn-then-review; tune the miss
  factor per link because bursty protocols are noisy.
- **Historian quality/staleness telemetry** (OSIsoft PI / AVEVA / Ignition):
  frozen values, BAD/UNCERTAIN/COMM_FAIL quality, timestamps not advancing.
- **SCADA/HMI alarm feed:** comms-fail, poll-timeout, stale-data,
  outstation-not-responding events.
- **L2/L3 reachability probing** (ARP/ICMP) to confirm the host is still live.

## Workflow

1. **Baseline per-link cadence.** Record the inter-message interval and the
   request/response pairing for each monitored link from a clean capture.
2. **Missing-expected-message detection (reporting path).** Fire when a link's
   inter-message interval exceeds the learned cadence by the miss factor **while
   the host still answers ARP/ICMP** — the still-reachable condition is what
   separates a blocked message from a dead link.
3. **Request-without-response detection (command path).** Alert on a master
   command/poll with no response inside the protocol timeout. A **one-sided**
   conversation (requests present, responses absent, or vice versa) marks a
   blocked message; **both** directions vanishing is wholesale blocking (route to
   the sibling skill).
4. **GOOSE stall rule.** Publisher MAC still link-live but sqNum not advancing
   past timeAllowedToLive indicates suppressed GOOSE — a rule-based check that
   meets the real-time bound.
5. **Correlate and confirm.** Join protocol-gap notices with SCADA comms-fail
   alarms and historian stale-quality flags. A cluster across several outstations
   at once is a strong block/suppression indicator versus one flaky RTU.

## Key Concepts

- **One-sided loss is the signature.** Link up + reachable host + a missing
  direction = blocked message. Both directions gone = T1695 territory.
- **Detection is corroborative by design.** A gap alone can be an idle link; pair
  it with alarm and quality telemetry to earn confidence.
- **Frozen telemetry is untrusted, not merely late.** Treat a stalled tag as a
  loss-of-view event, not a cosmetic glitch.
- **Clusters beat singletons.** Simultaneous gaps across a zone separate an attack
  from a single failing device.
- PLCs rarely run endpoint agents — this is network + historian + HMI telemetry.

## Tools & Systems

Zeek + CISA/INL ICSNPP parsers, Suricata (Emerging Threats SCADA), Claroty CTD,
Nozomi Guardian, Dragos Platform (comms baselining + missing-traffic analytics),
Wireshark, SCADA/historian comms-fail alarming (OSIsoft PI / AVEVA / Ignition),
Splunk OT add-ons, Microsoft Sentinel.

## Detection Queries

### Zeek -- per-link heartbeat watchdog (sketch)

```
# CADENCE[k] learned per link; MISS_FACTOR tuned per link.
global last_seen: table[conn_id] of time;
event dnp3_application_response(c: connection) { last_seen[c$id] = network_time(); }
event check_cadence() {
    for ( k in EXPECTED_LINKS )
        if ( network_time() - last_seen[k] > CADENCE[k]*MISS_FACTOR )
            NOTICE([$note=DNP3::Reporting_Gap]);   # confirm ARP/ICMP liveness before escalating
    schedule 1sec { check_cadence() };
}
```

### Splunk -- correlate protocol gap + comms-fail alarm + stale quality

```spl
(`zeek_notice` note="*Reporting_Gap*") OR (`scada_alarms` alarm="comms-fail")
  OR (`historian_quality` quality IN ("BAD","UNCERTAIN","COMM_FAIL"))
| bin _time span=60s
| stats dc(outstation) as affected values(source) as sources by _time
| where affected >= 2   # zone-wide cluster = block/suppression, not one flaky RTU
```

### GOOSE stall (concept)

```
# Publisher MAC still ARP/link-live but sqNum not advancing past
# timeAllowedToLive => suppressed GOOSE publication. Rule-based, meets real-time bound.
```

## Common Scenarios

- **Suppressed reporting:** operator screen frozen, RTU still pingable, historian
  quality degrading — missing-message + stale-quality correlation fires.
- **Blocked command:** master Operate repeated with no response while reads still
  flow — request-without-response fires on the one-sided conversation.
- **GOOSE suppression:** publisher live but sqNum stalled — GOOSE stall rule fires.
- **False positive:** a genuinely idle link during a planned low-activity window —
  suppressed by reachability check and maintenance calendar.

## Output Format

```
BLOCKED OT MESSAGE DETECTION
  Scope:         <single link | zone cluster (<N> outstations)>
  Verdict:       <confirmed | suspected | idle-link>
  Blocked path:  <reporting (T1691.002) | command (T1691.001)>
  Link state:    <host reachable (ARP/ICMP) : yes/no>  conversation: <one-sided | intact>
  Evidence:      <cadence gap | request-without-response | GOOSE stall>
  Corroboration: <SCADA comms-fail alarm | historian stale quality>
  ATT&CK:        T1691(.001/.002)
  Actions taken: <operators to out-of-band confirmation | gateway firmware verified | path restored>
```

## Response

- **Treat frozen telemetry as untrusted:** operators switch to out-of-band/manual
  confirmation of field state before acting.
- **Keep a redundant/alternate comms path** so blocking one path does not blind
  the SOC.
- **Verify gateway integrity:** check serial-to-Ethernet converter and
  comms-processor firmware; restore from known-good (the 2015 Ukraine vector was
  bricked converters).
- **Harden:** comms allowlists, IEC 62443 conduit segmentation, and hardwired
  safety interlocks that do not depend on the blocked path.
