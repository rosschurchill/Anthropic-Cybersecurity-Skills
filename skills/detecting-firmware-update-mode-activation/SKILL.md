---
name: detecting-firmware-update-mode-activation
description: 'Detects an adversary placing a PLC, RTU, IED or protection relay into firmware update or bootloader mode to inhibit its response functions as a denial of response (ATT&CK ICS T0800), including the Industroyer SIPROTEC relay case, using passive protocol monitoring, device alarms, asset logs and loss-of-traffic corroboration, correlated against approved change windows. Use when a safety or protection device unexpectedly enters update mode, when cyclic traffic or GOOSE from a relay goes silent, or when building detections for firmware-mode transitions on OT. Keywords: Activate Firmware Update Mode, T0800, SIPROTEC, Industroyer, update mode, bootloader, inhibit response, CIP File Object, device alarm, change window, Zeek ICSNPP. Do not use for installing or analysing an actual malicious or altered firmware image - use detecting-ot-firmware-modification or performing-plc-firmware-security-analysis.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- firmware-update-mode
- activate-firmware-update-mode
- inhibit-response
- plc
- relay
- zeek
- t0800
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- RS.MI-01
mitre_attack:
- T0800
- T1693
---

# Detecting Firmware Update Mode Activation

## When to Use

Use this skill to detect an adversary placing a field controller, RTU, PLC,
IED or safety/protection relay into **firmware update / bootloader mode**
(ATT&CK ICS T0800, Activate Firmware Update Mode). Update mode is a legitimate
feature, but triggering it halts the device's protective response functions,
and if no firmware is ever written the device can be left in an inactive
holding state — a **denial of response with no firmware change at all**. Reach
for it when:

- A safety or protection device unexpectedly enters update/bootloader mode.
- Cyclic polling, reports, or GOOSE heartbeats from a relay suddenly go silent.
- Building detections for firmware-mode transitions on OT protocols.

This skill is about **entering the mode** (availability / inhibit response). For
detection of an actual malicious or altered firmware **image** being installed,
use `detecting-ot-firmware-modification`; for offline analysis of a suspect
firmware image, use `performing-plc-firmware-security-analysis`.

## Prerequisites

- **Passive protocol monitoring** on SPAN/TAP ports (Zeek + CISA/INL ICSNPP, or
  an OT IDS) covering the relay/controller management segments.
- **Device-alarm ingestion**: many devices emit an alarm on entering update
  mode — but not all do, so do not rely on it alone.
- **Asset / controller application logs** and vendor engineering-software update
  logs (TIA Portal, Studio 5000 / ControlFLASH, EcoStruxure).
- **Expected-traffic baseline** per device (polling interval, report cadence,
  GOOSE heartbeat `timeAllowedtoLive`) so a silenced device is noticed.
- **Change-window / maintenance calendar** to separate sanctioned updates from
  attacks.
- PLCs and relays rarely run endpoint agents: detection is network + device
  alarms + asset/historian telemetry, not controller host logs.

## Workflow

1. **Baseline** which hosts may reach update ports/services, and each device's
   normal cyclic traffic and heartbeat cadence.
2. **Catch the mode transition** on the wire or in a device alarm: a
   firmware/update service, a vendor update session, or a documented DoS vector
   that forces the mode.
3. **Corroborate with loss of traffic.** After a mode trigger, expected
   polling / reports / GOOSE from the device typically drop — treat the silence
   as corroboration, not noise.
4. **Check the change window.** Alert when an update-mode entry on a
   protection/safety device is **not** covered by an approved window or
   authorized engineer.
5. **Verify protective function.** Confirm whether the device is still
   performing its protective role; prepare to fail over or trip to a safe state.
6. **Respond** (see *Response*).

## Key Concepts

- **Inhibit-response, not image tampering.** The impact here is availability:
  the device stops protecting the process. No firmware need ever be written.
- **Silence is a signal.** The inactive-holding-state tell is the loss of a
  device's expected cyclic traffic; model every critical reporting flow's
  liveness so a gap raises an alert on its own.
- **Named-incident reference.** Industroyer's SIPROTEC module put Siemens
  protection relays into an unresponsive state via crafted UDP packets to a
  management port, requiring a manual restart. Treat this as a behavioral
  pattern (crafted datagrams to a relay management port followed by loss of
  traffic); verify the exact port, packet pattern, and whether the semantics
  are "update mode" vs a DoS crash for your specific device model before
  signaturing. Refer to the incident by name — do not pin a CVE number.
- **Protocol specifics vary.** CIP firmware/file operations ride the File
  Object and vendor update services; Siemens firmware updates typically go via
  the device web server / MMC card / TIA Portal rather than classic S7comm job
  codes; Modbus has no standard firmware function (vendor overlays only). Verify
  the exact class/service/sub-codes against your dissector before signaturing,
  and prefer behavioral framing.

## Tools & Systems

Zeek + ICSNPP (`icsnpp-enip`, `icsnpp-bacnet`, GOOSE/`icsnpp-genisys`),
Suricata, Snort, Dragos Platform, Nozomi Guardian, Claroty CTD/xDome, Microsoft
Defender for IoT, CISA Malcolm, Wireshark ICS dissectors. Historians:
OSIsoft/AVEVA PI, AVEVA Historian. Vendor update tooling as the legitimate
baseline: Rockwell ControlFLASH / ControlFLASH Plus, Siemens TIA Portal. SIEM:
Splunk, Microsoft Sentinel. CISA ICS advisories / malware analysis reports for
SIPROTEC and Industroyer.

## Detection Queries

Ports, patterns, and function codes below are **illustrative** — verify each
against the relevant advisory, your dissector, and a live capture; prefer the
device-alarm + loss-of-traffic correlation, which is vendor-agnostic.

### Suricata — crafted datagrams to a relay management port (local SID)

```
# Behavioral signature for the SIPROTEC/Industroyer-style relay DoS pattern.
# Verify the exact port and payload against the CISA advisory and a live
# capture for your relay model; the port below is a placeholder to tune.
alert udp any any -> $RELAY_NET $RELAY_MGMT_PORT ( \
  msg:"Possible protection-relay firmware/DoS mode trigger (verify port/pattern)"; \
  dsize:>0; \
  threshold:type limit, track by_src, count 1, seconds 60; \
  sid:1000002; rev:1; )
```

### Splunk — device update-mode alarm outside an approved change window

```spl
index=ot (sourcetype=device_alarm alarm_text="*firmware update*")
   OR (sourcetype=device_alarm event="update_mode")
   OR (sourcetype=asset_log event="entered_bootloader")
| lookup change_windows device_id OUTPUT window_active
| where window_active!="true"
| table _time, device_id, alarm_text, src_host
```

### Splunk — corroborate with loss of expected cyclic traffic

```spl
index=ot sourcetype=ics_proto
| bin _time span=60s
| stats count as msgs by device_id, _time
| eventstats avg(msgs) as baseline by device_id
| where msgs=0 AND baseline>0   /* silence from a device that normally reports */
| table _time, device_id, baseline
```

## Common Scenarios

- **Protection relay silenced:** crafted datagrams to a relay management port,
  then its reports/GOOSE heartbeats stop and it needs a manual restart —
  classic inhibit-response pattern.
- **Out-of-window bootloader entry:** a PLC reports an update-mode alarm with no
  matching change ticket and no engineer logged in.
- **Mode entry with no firmware follow-on:** device enters update mode and sits
  there — the holding-state DoS, with no version/hash change to find.
- **False positive:** a sanctioned relay firmware upgrade inside an approved
  window by an authorized engineer — closed by the change-window lookup.

## Output Format

```
FIRMWARE UPDATE MODE ACTIVATION DETECTION
  Target device:   <relay/PLC/RTU id + IP>  role: <protection/safety/control>
  Verdict:         <confirmed-inhibit | suspected | authorized-maintenance>
  Trigger:         <protocol update service | crafted datagrams to mgmt port | device alarm>
  Source:          <src host/IP/MAC>  (on/off allowlist)
  Traffic loss:    <cyclic/report/GOOSE silence since <time> | none>
  Firmware follow: <none (holding-state DoS) | image write observed -> pivot>
  Change window:   <matched | none>
  ATT&CK:          T0800
  Actions taken:   <protective function verified | failover/trip prepared | device isolated | restored>
```

## Response

- **Treat as a potential inhibit-response attack** on a protection/safety
  device: verify the device is still performing its protective function and
  prepare to fail over or trip to a safe state.
- **Restore** from a known-good signed firmware image via a trusted path if the
  device is stuck in update mode; confirm whether an image was actually written
  (if so, pivot to `detecting-ot-firmware-modification`).
- **Harden:** patch the enabling vulnerabilities, restrict update-mode triggers
  to local/authenticated actions, allowlist which hosts may reach update
  ports/services, segment relays (IEC 62443 zones/conduits), and keep
  out-of-band liveness monitoring so a silenced device is noticed immediately.
