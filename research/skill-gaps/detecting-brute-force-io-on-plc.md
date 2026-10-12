# Detecting Brute Force I/O on PLC — research notes

- **Proposed slug:** detecting-brute-force-io-on-plc
- **ATT&CK (ICS):** T0806 Brute Force I/O (tactic: impair-process-control) — closely related:
  T0835 Manipulate I/O Image, T0855 Unauthorized Command Message, T0831 Manipulation of Control,
  T0836 Modify Parameter
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary repeatedly or exhaustively writing to I/O points — issuing write commands to a
large number of I/O addresses, or changing a single value an excessive number of times — to force a
process into an unsafe state, wear/cycle actuators, or overwhelm control. The skill catches the
volume/iteration signature of brute-forced I/O that a single-write detector would miss.

## Data sources / telemetry
- **Operational process data + network traffic (primary):** MITRE DET0737 (analytic AN1870) watches
  operational process data and network traffic for write commands touching an excessive number of
  I/O points, or manipulating one value an excessive number of times. The write commands are the
  signal — count and rate, not a single event.
- **Passive ICS network sensor:** write-command volume/rate per source and per target —
  Modbus write-coil (FC 0x05 / 0x0F), write-register (FC 0x06 / 0x10); CIP tag writes (0x4D —
  verify); DNP3 control-relay-output-block; S7comm writes. Count distinct I/O addresses written and
  write frequency per value within a window.
- **Asset application logs (DC0038 — supporting):** some controllers log which I/O points received
  write commands; use to attribute and confirm.
- **Historian (PI / Ignition):** rapid oscillation / abnormal cycling of process values and actuator
  state as impact corroboration.

## Detection logic / approach
MITRE is explicit that DET0737 **will not directly confirm** the technique — it provides supporting
evidence and complements other detections. The hard part is separating brute force from legitimate
control loops, commissioning, testing, and maintenance, so alerts must be triaged against
approved-change records.

Threshold/rate analytic (pseudo-logic over a sliding window):
```
window = 60s
if (distinct_io_addresses_written(src -> plc, window) > BASELINE_DISTINCT * k)
   OR (writes_to_single_point(src -> plc, point, window) > BASELINE_RATE * k):
      if src not in approved-change feed:
         ALERT "possible brute-force I/O" (src, plc, n_points, max_rate)
```
Zeek (ICSNPP Modbus extension / `icsnpp-enip`): aggregate write events per src/dst and per address;
emit a summary metric and alert on deviation from the learned baseline (Dragos/Nozomi/Claroty learn
these write baselines automatically). Suricata can rate-limit with `threshold`/`detection_filter` on
Modbus write function codes, but thresholds alone are noisy — use the passive-sensor baseline as the
primary and Suricata as a coarse backstop:
```
alert modbus any any -> $PLC 502 (msg:"ICS high-rate Modbus writes (possible brute-force I/O)";
  flow:to_server; app-layer-protocol:modbus;
  detection_filter:track by_src, count 50, seconds 10; sid:XXXXXXX; rev:1;)
```
(Tune `count`/`seconds` to the process; many control loops legitimately write fast — **baseline
first.**)

## Response / mitigation
Learn per-process write baselines and alert on deviation rather than fixed thresholds. Rate-limit and
allowlist control write paths at a protocol-aware OT firewall; restrict write access to authorized
control sources (M0800 Authorization Enforcement, M0813 Software/Device Authentication). Enforce
command validation / safe-operating envelopes in logic and in safety instrumented systems (SIS) so
brute-forced writes cannot drive an unsafe state. Correlate every alert with change/maintenance
records before escalation (high false-positive domain). On confirmed attack: move to safe state,
block the source, investigate upstream compromise.

## Real tools
Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD (write-rate baselining), Microsoft Defender
for IoT; Zeek + CISA ICSNPP (Modbus extension, `icsnpp-enip`); Suricata + Emerging Threats SCADA;
historian analytics (PI/Ignition); Wireshark Modbus/CIP/DNP3 dissectors; Malcolm.

## Draft frontmatter mappings
- mitre_attack: [T0806, T0835, T0855]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, DE.CM-09, PR.PS-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling (for the negative trigger): detecting-modbus-command-injection-attacks

## Draft description (<=1024 chars)
Detects brute-force I/O on a PLC — write commands touching an excessive number of I/O points, or one
value changed an excessive number of times, to force the process into an unsafe state or cycle
actuators (ATT&CK ICS T0806). Uses write-command volume and rate baselining on the OT network
(Modbus write coil/register, CIP tag write, DNP3 output), asset application logs, and historian
oscillation corroboration, triaged against approved-change records because it is a high-false-positive
signal. Use when triaging abnormal write bursts, rapid actuator cycling, or suspected impair-process
activity. Keywords: brute force I/O, write flood, write-rate anomaly, write coil, DET0737, oscillation,
safe state, T0806. Do not use for detecting single malformed or unauthorized Modbus control commands -
use detecting-modbus-command-injection-attacks.

## Key references
- MITRE ATT&CK T0806 + DET0737: https://attack.mitre.org/techniques/T0806/ , https://attack.mitre.org/detectionstrategies/DET0737
- CISA ICSNPP: https://github.com/cisagov/ICSNPP
- Suricata Modbus keyword / thresholding: https://docs.suricata.io/en/latest/rules/modbus-keyword.html
- CISA ICS advisories: https://www.cisa.gov/news-events/cybersecurity-advisories

## Open questions / scope boundaries
- Author must define "excessive" per process — this is inherently site-specific; the skill should
  teach baseline-then-deviation, not ship fixed thresholds.
- Boundary vs T0835 (image falsification) and single-command injection (sibling) — this skill is the
  *volume/iteration* signature. Must NOT include offensive I/O-flooding procedures.
- Verify Modbus/CIP/DNP3 write function codes and Suricata threshold semantics against captures.
