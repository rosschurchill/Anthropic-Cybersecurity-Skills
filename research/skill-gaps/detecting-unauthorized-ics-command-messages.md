# Detecting Unauthorized ICS Command Messages — research notes

- **Proposed slug:** detecting-unauthorized-ics-command-messages
- **ATT&CK (ICS):** T1692 Unauthorized Message (v19 restructure — verify exact v19.2 wording) — sub-techniques T1692.001 Command Message and T1692.002 Reporting Message. Closely related: T0830 Adversary-in-the-Middle, T0848 Rogue Master, T0855 Unauthorized Command Message (legacy ID now folded into T1692.001 — verify), T0856 Spoof Reporting Message (legacy, now T1692.002 — verify).
- **Status:** research (not yet a skill)

## Defensive goal
Detect illegitimate control/command and spoofed reporting messages injected into
an ICS network from a source not authorized to originate them — a rogue master,
a compromised EWS/HMI, or an adversary-in-the-middle. Command messages drive an
actuator outside its intended function or without expected preconditions
(ATT&CK's example is the Dallas emergency-siren activation); reporting messages
spoof I/O/telemetry so the process looks normal or operators chase a false fault.
The skill flags the unauthorized source and the semantically anomalous value.

## Data sources / telemetry
- **Passive protocol capture** on the process/control LAN: Modbus/TCP write
  function codes (FC 5 Write Single Coil, FC 6 Write Single Register, FC 15/16
  multi-write), DNP3 control objects (g12 CROB / Operate, Direct Operate,
  Select-Before-Operate sequences), EtherNet/IP + CIP Forward_Open / SetAttribute
  service writes, S7comm/S7comm-plus write-var and PLC start/stop/download jobs,
  IEC 61850 MMS control (Operate/SelectWithValue) and GOOSE publications, OPC UA
  Write service calls, BACnet WriteProperty.
- **Source-identity baseline:** which IP/MAC/engineering-station legitimately
  issues writes to which outstation (Claroty / Nozomi Guardian / Dragos asset +
  comms-matrix baselines). Any write from an off-baseline source = candidate.
- **IEC 61850 GOOSE integrity fields:** stNum/sqNum sequencing (poisoning/takeover
  rewrites these), GOOSE timeAllowedToLive, and the published-vs-received timing
  delta (practitioner validity bound ~4 ms).
- **Historian value + quality flags:** a reported value whose quality flag says
  GOOD but diverges from an out-of-band physical measurement = spoofed report.
- **EWS/HMI auth + session logs** to attribute the originating operator/session.

## Detection logic / approach
MITRE strategy DET0902 (and DET0794 for the command sub-technique): review
automation-protocol content for unexpected values and compare against
out-of-band process data; watch for the Rogue Master / AiTM activity that
precedes injection.

- **Source allowlisting (strongest signal).** Zeek ICSNPP analyzers
  (`icsnpp-modbus`, `icsnpp-dnp3`, `icsnpp-enip`, `icsnpp-s7comm`,
  `icsnpp-bacnet`, `icsnpp-opcua-binary` — Idaho National Laboratory) log
  function code + src/dst. Alert on any write-class function code whose
  `id.orig_h` is not in the known-master set for that `id.resp_h`:
```
# Zeek (icsnpp-modbus) — write from a non-authorized master
event modbus_message(c: connection, h: ModbusHeader, is_orig: bool) {
    if ( is_orig && h$function_code in WRITE_FCS &&
         c$id$orig_h !in AUTHORIZED_MASTERS[c$id$resp_h] )
        NOTICE([$note=Modbus::Unauthorized_Write, $conn=c]);
}
```
- **Suricata ICS rules** (Emerging Threats SCADA / Digital Bond Quickdraw):
  match Modbus write FCs or DNP3 operate objects from outside a defined
  `$SCADA_MASTERS` net to `$SCADA_SLAVES`; alert, do not inline-drop in safety
  contexts.
- **GOOSE semantic check (rule-based, meets real-time bound):** stNum increments
  without a real state change, duplicate/low sqNum (replay/takeover), or two
  publishers for one GOOSE control block (gocbRef). ML detectors (e.g. ED4GAP,
  GOOSEIDRS) exist but miss the GOOSE delivery deadline, so cryptographic auth
  (IEC 62351) or lightweight semantic rules drive real-time mitigation.
- **Out-of-band value corroboration (Splunk/Sentinel):** join the protocol
  write/report stream against an independent sensor/historian tag; flag
  reported-vs-measured divergence beyond physical tolerance.

## Response / mitigation
Isolate the unauthorized source; fail the actuator to a safe state per the
process safety plan (do not auto-command in safety-critical loops). Enforce
authorization (ATT&CK M0800) and field-controller access management (M0801),
network allowlists (M0807), and conduit segmentation (IEC 62443 zones/conduits).
Deploy IEC 62351 authentication for GOOSE/MMS. Rotate EWS creds if an engineering
station was the source. Preserve pcap for the DFIR timeline.

## Real tools
Zeek + ICSNPP parsers (INL), Suricata with Emerging Threats SCADA and Digital
Bond Quickdraw rules, Claroty Continuous Threat Detection, Nozomi Networks
Guardian, Dragos Platform, Wireshark (modbus/dnp3/s7comm/goose/mms dissectors),
Splunk (OT add-ons), Microsoft Sentinel, GRASSMARLIN (passive mapping).

## Draft frontmatter mappings
- mitre_attack: [T1692, T1692.001, T1692.002, T0830, T0848]
- nist_csf: [ID.AM-03, PR.AA-05, DE.CM-01, DE.AE-02, DE.AE-03, RS.MI-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling: detecting-modbus-command-injection-attacks

## Draft description (<=1024 chars)
Detects unauthorized ICS command and spoofed reporting messages injected by a
rogue master, compromised EWS/HMI, or adversary-in-the-middle (ATT&CK T1692).
Uses passive protocol monitoring of Modbus write function codes, DNP3 operate
objects, EtherNet/IP CIP writes, S7comm, OPC UA Write, and IEC 61850 MMS/GOOSE,
plus a source allowlist baseline (Claroty, Nozomi, Dragos), Zeek ICSNPP, and
Suricata SCADA rules, and corroborates reported values against out-of-band
historian data. Use when a control write or telemetry report comes from an
off-baseline source, operators see values that do not match the physical
process, or you are building authorized-source detection. Keywords: unauthorized
command message, rogue master, spoofed telemetry, Modbus write, DNP3 operate,
GOOSE spoofing, T1692. Do not use for malformed Modbus payload injection against
a known master - use detecting-modbus-command-injection-attacks.

## Key references
- MITRE ATT&CK T1692 Unauthorized Message: https://attack.mitre.org/techniques/T1692/
- T1692.001 Command Message: https://attack.mitre.org/techniques/T1692/001/
- T1692.002 Reporting Message: https://attack.mitre.org/techniques/T1692/002/
- DET0902 Detection of Unauthorized Message: https://attack.mitre.org/detectionstrategies/DET0902/
- ICSNPP Zeek parsers (Idaho National Laboratory): https://github.com/cisagov/icsnpp
- Digital Bond Quickdraw SCADA IDS rules: https://github.com/digitalbond/Quickdraw-Snort
- INCIBE-CERT, Security in the GOOSE protocol: https://www.incibe.es/en/incibe-cert/blog/security-goose-protocol

## Open questions / scope boundaries
- Confirm final v19.2 technique name/ID and whether legacy T0855/T0856 are
  deprecated in favour of T1692.001/.002 (flagged verify).
- Authorized-source baseline is the load-bearing input; ship the method
  (comms-matrix learning + review) not hard IP lists.
- Keep strictly to recognition/response — no message-forging procedures.
- Decide overlap boundary with Rogue Master (T0848) and AiTM (T0830): those are
  the delivery mechanisms; this skill is the message-level detection.
