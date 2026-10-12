# Detecting I/O Image Manipulation — research notes

- **Proposed slug:** detecting-io-image-manipulation
- **ATT&CK (ICS):** T0835 Manipulate I/O Image (tactic: impact) — closely related:
  T0836 Modify Parameter, T0806 Brute Force I/O, T0889 Modify Program, T0855 Unauthorized
  Command Message, T0831 Manipulation of Control
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary manipulating a PLC's process image — the memory map mirroring physical inputs
and outputs (PII/PIQ in Siemens terms) — so logic reads falsified input values or drives outputs
that do not reflect the real field state. This decouples the controller's view from physical
reality, masking an attack or driving actuators directly. The skill catches forced/overridden I/O,
direct writes to I/O data blocks, and mismatches between field sensors, the PLC image, and the
historian.

## Data sources / telemetry
- **PLC program / data-block inspection (primary):** MITRE's DET0773 (analytic AN1905) states
  detection requires obtaining and analyzing the PLC application program for specific data-block
  writes — pulled from the device or from an asset-management platform (data component Software
  DC0111, Asset). Look for logic or external writes targeting the I/O image data blocks and for
  force/override flags set on I/O points.
- **Passive ICS network sensor:** write commands to I/O/coil/register addresses — Modbus write-coil
  (FC 0x05 / 0x0F) and write-register (FC 0x06 / 0x10), CIP tag writes (0x4D — verify), S7comm
  writes to PII/PIQ areas, DNP3 control-relay-output-block (CROB) / analog-output. Watch forcing
  services where the protocol exposes them.
- **Controller force/override state:** engineering tools and some controllers expose "forced I/O"
  status; an unexpected force is a strong signal (also surfaced in HMI/engineering alarms).
- **Historian (PI / Ignition) + field cross-check:** compare the PLC image value against the
  historian-recorded value and, where independently sensed, the physical field reading. A divergence
  among field sensor, PLC image, and historian indicates image manipulation (a data-integrity check
  the controller cannot self-report).
- **Engineering workstation (Sysmon/EDR):** programming/forcing-tool activity correlated to the
  affected controller.

## Detection logic / approach
DET0773 centers on program/data-block analysis because, unlike a download, image manipulation may be
a quiet memory write with no protocol "download" event. Two complementary layers:

1. **Program/data-block diff:** upload the program and check for unexpected writes to I/O-image data
   blocks and for set force/override flags, against a golden master.
2. **Network write anomaly:** alert on write commands to I/O addresses from a non-allowlisted source,
   or writes that drive an output while the corresponding input path is bypassed/forced.

Historian cross-check analytic (Splunk/Sentinel pseudo-logic):
```
for each I/O tag:
  if abs(plc_image_value - historian_value) > tolerance for N samples
     OR force_flag(tag) == set and no approved change:
       ALERT "I/O image / field divergence" (tag, plc_value, hist_value, force_state)
```
Zeek (ICSNPP): Modbus logging extension and `icsnpp-enip` `cip.log` to flag write bursts to I/O
addresses; correlate with forced-state anomalies. Distinguish legitimate control-loop writes from
manipulation using the write *pattern* (persistent override, out-of-range value, non-EWS source).

## Response / mitigation
Baseline I/O-image data blocks and force state; alert on unexpected forces and on logic writes to
I/O image areas (M0947 Audit). Restrict write access to I/O addresses to authorized control paths —
protocol-aware firewall, read-only replication to the historian, authorization enforcement (M0800),
software/device authentication (M0813). Deploy out-of-band/independent instrumentation for critical
measurements so a manipulated image can be cross-checked (M0810 Out-of-Band Communications — verify).
On confirmed manipulation: move to safe state, clear forces through change control, restore
golden-master logic, verify field instruments.

## Real tools
Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT; Zeek + CISA ICSNPP
(Modbus extension, `icsnpp-enip`); historian analytics (OSIsoft/AVEVA PI, Ignition); vendor
engineering tools' force/monitor views (TIA Portal Watch/Force tables, Studio 5000 force status);
Wireshark Modbus/CIP/S7comm dissectors; Malcolm.

## Draft frontmatter mappings
- mitre_attack: [T0835, T0806, T0836, T0889]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, PR.PS-01, ID.AM-02]
- suggested subdomain: ot-ics-security
- nearest existing sibling (for the negative trigger): monitoring-scada-modbus-traffic-anomalies

## Draft description (<=1024 chars)
Detects manipulation of a PLC's I/O process image — forced or overridden I/O, logic or external
writes to I/O data blocks, and divergence among field sensor, PLC image, and historian value that
decouples the controller's view from physical reality (ATT&CK ICS T0835). Combines PLC data-block
and force-state baselining, network write-command monitoring (Modbus write coil/register, CIP tag
write, DNP3 CROB), and historian cross-checks. Use when triaging suspected falsified I/O, unexpected
forced points, or actuator behavior that does not match sensed field state. Keywords: manipulate I/O
image, process image, forced I/O, PII PIQ, write coil, CROB, historian divergence, DET0773, T0835.
Do not use for general Modbus traffic baselining and anomaly detection - use
monitoring-scada-modbus-traffic-anomalies.

## Key references
- MITRE ATT&CK T0835 + DET0773: https://attack.mitre.org/techniques/T0835/ , https://attack.mitre.org/detectionstrategies/DET0773
- CISA ICSNPP: https://github.com/cisagov/ICSNPP
- Suricata Modbus keyword (write functions): https://docs.suricata.io/en/latest/rules/modbus-keyword.html
- CISA ICS advisories: https://www.cisa.gov/news-events/cybersecurity-advisories

## Open questions / scope boundaries
- Author must define the field/historian/PLC cross-check tolerances per tag and how to read force
  state per vendor (TIA Portal vs Studio 5000 vs Modicon).
- Boundary vs T0836 Modify Parameter (set-points/config) and T0806 Brute Force I/O (volume/iteration)
  — this skill is the *process-image* falsification. Must NOT include offensive I/O-forcing procedures.
- Verify CIP tag-write and DNP3 output service codes against captures before shipping signatures.
