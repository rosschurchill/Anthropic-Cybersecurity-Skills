# Detecting Blocked OT Messages — research notes

- **Proposed slug:** detecting-blocked-ot-messages
- **ATT&CK (ICS):** T1691 Block Operational Technology Message (v19 restructure — verify exact v19.2 wording) — sub-techniques T1691.001 Command Message and T1691.002 Reporting Message. Closely related: T1695 Block Communications, T0878 Alarm Suppression, T0881 Service Stop, T0837 Loss of Protection. Legacy IDs T0803 Block Command Message / T0804 Block Reporting Message appear folded into T1691 (verify).
- **Status:** research (not yet a skill)

## Defensive goal
Detect selective interference with OT messages where an adversary prevents
specific command or reporting messages from reaching their target while the
link otherwise appears up. Blocking reporting messages hides the attacker's
actions and freezes the operator's view of the process; blocking command
messages denies control. ATT&CK's listed example is the 2015 Ukraine power
attack, where Sandworm used malicious firmware to render serial-to-Ethernet
converters inoperable. The skill distinguishes a blocked-message condition from
routine quiet traffic and surfaces it fast.

## Data sources / telemetry
- **Expected-message cadence baseline:** DNP3 unsolicited responses and integrity
  polls, Modbus poll/response round-trips, IEC 61850 GOOSE heartbeat republication
  (retransmission on timeAllowedToLive), MMS report-control-block reports, EtherNet/IP
  CIP implicit-I/O (Class 1) cyclic packets, OPC UA subscription keep-alive /
  PublishResponse cadence. A learned inter-message interval per link is the baseline.
- **Request-without-response gaps:** a master's poll/Operate seen on the wire with
  no matching response (reporting or command path dropped mid-conversation).
- **GOOSE/Sampled-Values sequence integrity:** stNum/sqNum stall or absence while
  the publisher MAC is otherwise live = suppressed publication.
- **Historian quality/staleness flags:** tags frozen at last-known value, quality
  degrading to BAD/UNCERTAIN/COMM_FAIL, or timestamp not advancing.
- **HMI/SCADA alarms:** comms-fail, poll-timeout, "stale data", RTU/outstation
  not-responding events from the SCADA master.
- **Asset/firmware telemetry:** serial-to-Ethernet gateway and PLC comms-processor
  health (the Ukraine vector was bricked converters).

## Detection logic / approach
MITRE strategy DET0903: monitor OT protocols for missing/absent expected messages
and correlate with alarm and comms-loss telemetry (an indirect, corroborating
strategy by design).

- **Missing-expected-traffic (Zeek + ICSNPP).** Maintain per-link last-seen
  timestamps for DNP3/Modbus/ENIP/GOOSE; a Zeek scheduled check fires when the
  interval exceeds the learned cadence while the host is still L2/L3 reachable:
```
# Zeek — per-link heartbeat watchdog (sketch)
global last_seen: table[conn_id] of time;
event dnp3_application_response(c: connection, ...) { last_seen[c$id] = network_time(); }
event check_cadence() {
    for ( k in EXPECTED_LINKS )
        if ( network_time() - last_seen[k] > CADENCE[k]*MISS_FACTOR )
            NOTICE([$note=DNP3::Reporting_Gap]);
    schedule 1sec { check_cadence() };
}
```
- **Request/response pairing:** alert on master command/poll with no response
  within the protocol timeout; a one-sided conversation distinguishes a *blocked
  message* from a jammed link (where both directions vanish — that is T1695).
- **GOOSE stall rule:** publisher MAC still ARP/link-live but sqNum not advancing
  past timeAllowedToLive = suppressed GOOSE (meets real-time bound as a rule).
- **SIEM correlation (Splunk/Sentinel):** join protocol-gap notices with SCADA
  comms-fail alarms and historian stale-quality flags; a cluster across several
  outstations at once is a strong block/suppression indicator vs a single flaky RTU.

## Response / mitigation
Treat frozen telemetry as untrusted — operators switch to out-of-band / manual
confirmation of field state before acting. Keep a redundant/alternate comms path
(ATT&CK M0810 Out-of-Band Communications Channel) so blocking one path does not
blind the SOC. Verify serial-to-Ethernet gateway and comms-processor firmware
integrity; restore from known-good. Enforce comms allowlists (M0807) and
segment conduits (IEC 62443). Independent hardwired safety interlocks must not
depend on the blocked path.

## Real tools
Zeek + ICSNPP (INL), Suricata (Emerging Threats SCADA), Claroty CTD, Nozomi
Guardian, Dragos Platform (comms baselining + missing-traffic analytics),
Wireshark, SCADA/historian comms-fail alarming (OSIsoft PI / AVEVA, Ignition),
Splunk OT add-ons, Microsoft Sentinel.

## Draft frontmatter mappings
- mitre_attack: [T1691, T1691.001, T1691.002, T1695, T0878]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, DE.AE-04, RS.MI-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling: detecting-attacks-on-scada-systems

## Draft description (<=1024 chars)
Detects blocked OT messages where an adversary drops specific command or
reporting messages while the link still looks up, freezing the operator view or
denying control (ATT&CK T1691; 2015 Ukraine serial-converter example). Uses an
expected-message cadence baseline over DNP3, Modbus, EtherNet/IP cyclic I/O, IEC
61850 GOOSE/MMS, and OPC UA subscriptions, request-without-response gap
detection, GOOSE stNum/sqNum stall rules, and historian stale-quality flags,
correlated with SCADA comms-fail alarms in Zeek, Suricata, Claroty, Nozomi,
Dragos, and SIEM. Use when telemetry freezes, outstations go quiet, or commands
are not acknowledged. Keywords: blocked OT message, missing traffic, comms
timeout, GOOSE heartbeat gap, DNP3 unsolicited, stale quality, T1691. Do not use
for full link jamming or interface takedown affecting all traffic - use
detecting-ics-communication-blocking.

## Key references
- MITRE ATT&CK T1691 Block Operational Technology Message: https://attack.mitre.org/techniques/T1691/
- T1691.001 Command Message: https://attack.mitre.org/techniques/T1691/001/
- T1691.002 Reporting Message: https://attack.mitre.org/techniques/T1691/002/
- DET0903 Detection of Block Operational Technology Message: https://attack.mitre.org/detectionstrategies/DET0903/
- CISA / E-ISAC & SANS, Analysis of the Cyber Attack on the Ukrainian Power Grid (2016): https://www.cisa.gov/
- ICSNPP Zeek parsers (INL/CISA): https://github.com/cisagov/icsnpp

## Open questions / scope boundaries
- Confirm v19.2 name/ID and legacy T0803/T0804 deprecation mapping (verify).
- Cadence baseline is noisy on bursty protocols; ship a learn-then-review method,
  not fixed timeouts; tune MISS_FACTOR per link.
- Boundary with T1695: selective message drop (link up) = this skill; whole-link
  loss/jamming = detecting-ics-communication-blocking. Boundary with T0878 Alarm
  Suppression (blocking the alarm specifically).
- Detection here is corroborative (DET0903 is indirect) — pair with alarm and
  quality telemetry to avoid false positives on genuinely idle links.
