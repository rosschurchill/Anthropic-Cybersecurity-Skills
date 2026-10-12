---
name: detecting-brute-force-io-on-plc
description: 'Detects brute-force I/O on a PLC - high-rate write-command flooding that touches an excessive number of I/O points, or changes one value an excessive number of times, to force the process into an unsafe state, wear or cycle actuators, or overwhelm control (ATT&CK ICS T0806). Uses write-command volume and rate baselining on the OT network (Modbus write coil and register, CIP tag write, DNP3 output), asset application logs, and historian oscillation corroboration, triaged against approved-change records because it is a high-false-positive signal. Use when triaging abnormal write bursts, rapid actuator cycling, or suspected impair-process activity. Keywords: brute force I/O, write flood, write-rate anomaly, write coil, oscillation, safe state, T0806. Do not use for detecting single malformed or unauthorized Modbus control commands - use detecting-modbus-command-injection-attacks.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- brute-force-io
- write-flood
- modbus
- enip-cip
- dnp3
- historian
- t0806
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- PR.PS-01
mitre_attack:
- T0806
- T0835
---

# Detecting Brute Force I/O on PLC

## When to Use

Use this skill to detect an adversary repeatedly or exhaustively writing to I/O
points (ATT&CK ICS T0806): issuing write commands to a large number of I/O
addresses, or changing a single value an excessive number of times, to force a
process into an unsafe state, wear or cycle actuators, or overwhelm control. The
signal is the **volume and rate** of writes - a count and frequency over a window
- that a single-write detector would miss. Reach for it when:

- Triaging an abnormal write burst against a controller.
- A historian shows rapid oscillation or actuator cycling.
- You suspect impair-process-control activity driven by many writes.

Do not use for detecting a single malformed or unauthorized Modbus control command
- use `detecting-modbus-command-injection-attacks`. For falsifying the process
image (forced/overridden points) use `detecting-io-image-manipulation`.

## Prerequisites

- Passive ICS network sensor that can count and rate-aggregate write commands per
  source and per target.
- Learned per-process write baselines (OT monitoring platforms learn these
  automatically) - fixed thresholds alone are noisy in this domain.
- Asset application logs where the controller records which points were written.
- Historian access (PI, Ignition) for oscillation and actuator-cycling
  corroboration.
- A change-management feed - this is a high-false-positive signal and every alert
  must be triaged against approved-change records.
- Note: separating brute force from legitimate control loops, commissioning,
  testing, and maintenance is the hard part - baseline first, then deviate.

## Workflow

1. **Baseline** the normal write behavior per source-to-controller path: the
   distinct I/O addresses written and the write rate to any single point over a
   window.
2. **Rate and volume analytic:** over a sliding window, flag a source that writes
   far more distinct I/O addresses than its baseline, or writes one point far more
   often than its baseline. Modbus write-coil and write-register, CIP tag writes,
   and DNP3 output are the common carriers (verify the exact function/service codes
   against a live capture).
3. **Triage against change records.** Suppress commissioning, testing, and
   approved maintenance; a source not in the change feed with abnormal volume is
   the alert.
4. **Corroborate** with historian oscillation or abnormal actuator cycling as
   impact evidence.
5. **Attribute** with asset application logs showing which points received writes.
6. **Respond** (see Response).

## Key Concepts

- **Count and rate, not a single event.** The technique is defined by excessive
  volume or iteration, so the detector must aggregate over a window, not match one
  command.
- **Supporting, not confirming.** Network volume evidence rarely confirms the
  technique on its own; it complements other detections and the historian impact
  view - treat it as supporting evidence and triage it.
- **High false-positive domain.** Many control loops legitimately write fast;
  baseline per process and alert on deviation rather than a fixed count.
- **Boundary with single-command injection.** One crafted or unauthorized command
  is a different skill; this one is the flood/iteration signature.

## Tools & Systems

Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD (write-rate baselining),
Microsoft Defender for IoT; Zeek with CISA ICSNPP (Modbus extension,
`icsnpp-enip`); Suricata or Snort with the Emerging Threats SCADA ruleset;
historian analytics (OSIsoft/AVEVA PI, Ignition); Wireshark Modbus/CIP/DNP3
dissectors; CISA Malcolm.

## Detection Queries

### Rate/volume analytic (primary, pseudo-logic over a sliding window)

```
window = 60s
if distinct_io_addresses_written(src -> plc, window) > BASELINE_DISTINCT * k
   OR writes_to_single_point(src -> plc, point, window) > BASELINE_RATE * k:
      if src not in approved-change feed:
         ALERT "possible brute-force I/O" (src, plc, n_points, max_rate)
```

### Zeek (ICSNPP) -- aggregate write events per source/target (concept)

```
# Modbus extension / icsnpp-enip: aggregate write events per src/dst and
# per address; emit a summary metric and alert on deviation from the learned
# baseline. OT platforms (Dragos/Nozomi/Claroty) learn these automatically.
```

### Suricata -- coarse rate backstop (baseline first; tune to the process)

```
# PREREQUISITE: Suricata's modbus app-layer parser is DISABLED BY DEFAULT, so an
# `alert modbus` rule silently never matches on a stock install. Set
# app-layer.protocols.modbus.enabled: yes in suricata.yaml first.
# (app-layer-protocol:modbus; is redundant once the rule protocol is `modbus`.)
alert modbus any any -> $PLC 502 ( \
  msg:"ICS-LOCAL high-rate Modbus writes (possible brute-force I/O)"; \
  flow:to_server; \
  detection_filter:track by_src, count 50, seconds 10; \
  sid:1000003; rev:1; \
)
# count/seconds are placeholders - many control loops write fast; use the
# passive-sensor baseline as primary and this only as a coarse backstop.
```

## Common Scenarios

- **Address sweep:** a source writes to hundreds of distinct coils far above its
  baseline in seconds, none in the change feed - likely brute force.
- **Single-point hammering:** one setpoint is rewritten thousands of times to cycle
  an actuator; historian shows rapid oscillation.
- **Unsafe-state push:** repeated writes drive a value toward an unsafe envelope
  until the SIS intervenes.
- **False positive:** a commissioning test or a fast but approved control loop -
  excluded by the baseline and change feed.

## Output Format

```
BRUTE-FORCE I/O DETECTION
  Controller:      <plc id / ip>
  Verdict:         <suspected | corroborated | approved-activity>
  Signature:       <many distinct points | single-point high-rate>
  Volume:          <n distinct addresses / max writes-per-point> over <window>
  Baseline:        <distinct baseline / rate baseline> (factor k over baseline)
  Source:          <host ip> change-feed: <present | absent>
  Corroboration:   <historian oscillation | actuator cycling | asset log>
  ATT&CK:          T0806 (related T0835)
  Actions taken:   <safe state | source blocked | upstream investigated>
```

## Response

- **Contain:** on a confirmed attack, move the process to a safe state, block the
  source, and investigate the upstream compromise that reached the control path.
- **Harden:** learn per-process write baselines and alert on deviation rather than
  fixed thresholds; rate-limit and allowlist control write paths at a
  protocol-aware OT firewall; restrict write access to authorized sources with
  authorization enforcement and software/device authentication; and enforce
  command validation and safe-operating envelopes in logic and in the safety
  instrumented system so brute-forced writes cannot drive an unsafe state.
