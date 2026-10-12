---
name: detecting-io-image-manipulation
description: 'Detects manipulation of a PLC process image - forced or overridden I/O, logic or external writes to the I/O data blocks, and divergence among field sensor, PLC image, and historian value that decouples the controller view from physical reality so an HMI shows normal while the process is driven elsewhere (ATT&CK ICS T0835). Combines PLC data-block and force-state baselining, network write-command monitoring (Modbus write coil and register, CIP tag write, DNP3 control-relay-output-block), and historian cross-checks. Use when triaging suspected falsified I/O, unexpected forced points, or actuator behavior that does not match sensed field state. Keywords: manipulate I/O image, process image, forced I/O, PII PIQ, write coil, CROB, historian divergence, T0835. Do not use for general Modbus traffic baselining and anomaly detection - use monitoring-scada-modbus-traffic-anomalies.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- io-image-manipulation
- forced-io
- process-image
- modbus
- enip-cip
- historian
- t0835
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
- T0835
- T0836
- T0806
---

# Detecting I/O Image Manipulation

## When to Use

Use this skill to detect an adversary manipulating a PLC process image - the
memory map that mirrors physical inputs and outputs (the PII and PIQ areas in
Siemens terms) - so logic reads falsified input values or drives outputs that do
not reflect the real field state (ATT&CK ICS T0835). This decouples the
controller view from physical reality, letting an HMI show normal while an attack
proceeds or actuators are driven directly. The skill catches forced or overridden
I/O, direct writes to I/O data blocks, and mismatches among field sensors, the PLC
image, and the historian. Reach for it when:

- Triaging suspected falsified I/O or an unexpected forced point.
- Actuator behavior does not match the sensed field state.
- The HMI and historian disagree with an independently sensed measurement.

Do not use for general Modbus traffic baselining and anomaly detection - use
`monitoring-scada-modbus-traffic-anomalies`. For the volume/iteration signature of
flooding writes use `detecting-brute-force-io-on-plc`.

## Prerequisites

- A safe read-only path to the PLC program and data blocks, or an asset-management
  platform that retains them, to inspect writes to I/O-image areas and force flags.
- A baseline of the I/O-image data blocks and the normal force/override state.
- Passive ICS network sensor to see write commands to I/O addresses.
- Historian access (PI, Ignition) and, where available, independent field
  instrumentation for a three-way cross-check.
- Engineering-workstation telemetry (Sysmon/EDR) for forcing-tool activity.
- Note: image manipulation can be a quiet memory write with no protocol download
  event, so program/data-block analysis and the historian cross-check matter as
  much as the network view.

## Workflow

1. **Baseline** the I/O-image data blocks and the force/override state for each
   controller; record which write paths are legitimate.
2. **Program/data-block diff:** read the program and check for unexpected writes
   targeting I/O-image data blocks and for set force or override flags, against the
   golden master.
3. **Network write anomaly:** flag write commands to I/O addresses from a
   non-allowlisted source, or a write that drives an output while the corresponding
   input path is bypassed or forced. Modbus write-coil and write-register, CIP tag
   writes, and DNP3 control-relay-output-block are the common carriers (verify the
   exact function/service codes against a live capture before matching a byte).
4. **Historian/field cross-check:** compare the PLC image value against the
   historian value and, where independently sensed, the physical field reading. A
   divergence among the three indicates image manipulation the controller cannot
   self-report.
5. **Correlate** force state and write source with EWS forcing-tool activity.
6. **Respond** (see Response).

## Key Concepts

- **The image is the controller view, not reality.** Manipulating it is how an
  attacker hides an attack from logic and operators - which is why an independent
  field cross-check, not the controller reading, is the integrity anchor.
- **Forcing is a strong signal.** An unexpected forced or overridden I/O point is
  high-signal; baseline the normal force state so a new force stands out.
- **Quiet writes.** Unlike a download, image manipulation may be a direct memory
  write with no download event - program/data-block analysis catches what the
  network misses.
- **Pattern over single write.** Distinguish legitimate control-loop writes from
  manipulation by the pattern: a persistent override, an out-of-range value, or a
  non-EWS source.

## Tools & Systems

Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT;
Zeek with CISA ICSNPP (Modbus extension, `icsnpp-enip`); historian analytics
(OSIsoft/AVEVA PI, Ignition); vendor engineering force/monitor views (TIA Portal
Watch/Force tables, Studio 5000 force status, Unity Pro / EcoStruxure Control
Expert); Wireshark Modbus/CIP/S7comm dissectors; CISA Malcolm; Suricata or Snort
with the Emerging Threats SCADA ruleset.

## Detection Queries

### Historian / field cross-check (primary analytic, pseudo-logic)

```
for each I/O tag:
  if abs(plc_image_value - historian_value) > tolerance for N samples
     OR force_flag(tag) == set and no approved change:
       ALERT "I/O image / field divergence" (tag, plc_value, hist_value, force_state)
```

### Program / data-block diff (pseudo-logic)

```
upload program (read-only); check for:
  - external or logic writes targeting I/O-image data blocks
  - set force/override flags on I/O points
against the golden master; flag any not matching an approved change.
```

### Zeek (ICSNPP) -- write burst to I/O addresses from non-EWS (concept)

```
# Modbus extension / icsnpp-enip cip.log: flag write commands to I/O/coil/
# register addresses from a host not in the allowlist; correlate with a
# forced-state anomaly. Verify write function/service codes against capture.
```

## Common Scenarios

- **Falsified inputs (Stuxnet-style):** the image feeds logic a normal sensor
  value while the real process is driven elsewhere; the field cross-check reveals
  the divergence the HMI hides.
- **Persistent force:** an output is forced ON with no change ticket; the force
  baseline flags it and the historian shows the actuator stuck.
- **Direct output write:** a non-EWS host writes a coil driving an actuator while
  the input interlock is bypassed.
- **False positive:** a commissioning engineer forcing a point during an approved
  maintenance window - excluded by the change feed.

## Output Format

```
I/O IMAGE MANIPULATION DETECTION
  Controller:      <plc id / ip>
  Verdict:         <confirmed | suspected | approved-maintenance>
  Method:          <forced/override point | I/O data-block write | direct write>
  Tag/point:       <tag> plc=<value> historian=<value> field=<value | n/a>
  Force state:     <set | cleared> source: <host ip> (EWS: <yes/no>)
  Corroboration:   <data-block diff | historian divergence | forcing-tool launch>
  ATT&CK:          T0835 (related T0836, T0806)
  Actions taken:   <safe state | forces cleared | golden master restored>
```

## Response

- **Contain:** on confirmed manipulation, move the process to a safe state, clear
  forces through change control, restore golden-master logic, and verify the field
  instruments.
- **Harden:** baseline I/O-image data blocks and force state and alert on
  unexpected forces and on logic writes to I/O-image areas; restrict write access
  to I/O addresses to authorized control paths with a protocol-aware firewall and
  authorization enforcement; and deploy out-of-band independent instrumentation for
  critical measurements so a manipulated image can be cross-checked.
