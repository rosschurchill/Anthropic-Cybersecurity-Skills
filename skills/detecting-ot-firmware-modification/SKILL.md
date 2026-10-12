---
name: detecting-ot-firmware-modification
description: 'Detects malicious or altered firmware installed on OT devices and modules (ATT&CK ICS T1693, system .001 and module .002) via network firmware and file-transfer functions (CIP File Object, DNP3 file transfer, IEC 61850 MMS FileRead, S7comm download sequence), device alarms, asset logs, and firmware version and hash drift against a known-good golden image and asset baseline, correlated with approved patch windows. Use when a PLC, RTU or IED firmware version changes unexpectedly, when investigating a suspected firmware implant or supply-chain firmware, or when building firmware-integrity monitoring for OT. Keywords: Modify Firmware, T1693, module firmware, CIP File Object, ControlFLASH, DNP3 file transfer, MMS FileRead, golden image, firmware hash drift, signed firmware. Do not use for entering firmware update mode as a denial of response - use detecting-firmware-update-mode-activation; for offline PLC firmware image analysis use performing-plc-firmware-security-analysis.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- firmware-modification
- modify-firmware
- plc
- firmware-integrity
- cip
- zeek
- t1693
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- ID.AM-02
- PR.PS-01
- PR.PS-02
mitre_attack:
- T1693
- T1693.001
- T1693.002
- T0800
---

# Detecting OT Firmware Modification

## When to Use

Use this skill to detect an adversary **installing malicious or altered
firmware** on OT devices — PLCs, RTUs, IEDs — and on separately-flashed
modules such as communications/I-O cards, via a device's built-in update
feature, removable media, the supply chain, or remote services (ATT&CK ICS
T1693, Modify Firmware; system firmware .001 and module firmware .002). The
goal is persistence, impaired process control, or inhibited response. Reach for
it when:

- A PLC/RTU/IED firmware version or hash changes unexpectedly.
- Investigating a suspected firmware implant or supply-chain firmware.
- Building firmware-integrity monitoring across OT asset classes.

This skill is about an actual firmware **image** being changed. For detection of
a device merely being forced **into** update/bootloader mode as a denial of
response, use `detecting-firmware-update-mode-activation`; for offline
reverse-engineering of a suspect firmware image, use
`performing-plc-firmware-security-analysis`.

## Prerequisites

- **Golden-image library.** A known-good firmware version **and hash** per asset
  class — the single strongest comparison point. Without it, drift detection is
  blind.
- **Asset-management baseline** of expected firmware versions (Claroty / Nozomi
  / Dragos inventory), including module firmware, not just the CPU image. Note
  that passive OT inventory yields firmware **version strings** and model data,
  not a cryptographic hash of the running image — no OT platform hashes a live
  PLC image, so the hash half needs an offline image pull (see below).
- **A path to pull the image itself** when a hash comparison is required: vendor
  engineering tooling, removable media (MMC/CF card), or physical extraction,
  performed offline on the device or on the distributed update package.
- **Passive protocol monitoring** (Zeek + CISA/INL ICSNPP, or an OT IDS) on
  management and file-transfer segments.
- **Device alarms and asset/application logs**: firmware-change alarms where the
  device emits them; vendor engineering-software update session logs (TIA
  Portal, ControlFLASH, EcoStruxure).
- **Change-window / patch calendar** and the allowlist of authorized patch
  servers and EWS.
- PLCs rarely run endpoint agents: detection is network + asset baseline +
  device alarms + EWS/historian telemetry, not controller host logs.

## Workflow

1. **Baseline** the golden firmware version/hash per asset class and the hosts
   authorized to deliver firmware.
2. **Diff versions continuously (core signal).** Pull the live firmware
   **version** per device from the asset inventory and alert on any delta from
   the golden version — especially one outside a change window. This is the
   continuous signal, because inventory carries versions, not image hashes.
   Then **confirm with a hash on demand**: once a device is suspect, pull the
   image via vendor tooling, removable media or physical extraction and compare
   its hash to the golden image offline.
3. **Watch firmware/file-transfer traffic.** Flag firmware or file-transfer
   functions reaching a device from a host not on the EWS/patch-server
   allowlist; record the 5-tuple and device.
4. **Treat unsigned / unexpected-source firmware as high priority.** Firmware
   from an unexpected network location, or that fails vendor signature
   verification where supported, is a strong indicator.
5. **Build a per-device timeline.** Correlate firmware-version change + update
   event + device reboot into one timeline, and extend version/hash baselining
   to comms/I-O **module** firmware (.002), which is easy to overlook.
6. **Respond** (see *Response*).

## Key Concepts

- **Version drift detects, hash drift confirms.** Version strings can be
  spoofed, so a cryptographic hash against a known-good image is the stronger
  evidence — but it is an on-demand, offline step (image pulled via vendor
  tooling, removable media or physical extraction), not something passive
  inventory supplies. Run version drift continuously against the change window
  to cut false positives, and escalate to a hash comparison on the devices it
  flags.
- **Modules are separately flashable.** T1693.002 covers communications and I-O
  module firmware that carries its own image — baseline these, not only the CPU.
- **Signature support varies.** Firmware code-signing/verification is not
  universal; document which asset classes actually support it before relying on
  "unsigned equals malicious."
- **Protocol framing is illustrative.** CIP firmware/file operations ride the
  File Object and vendor services (e.g. ControlFLASH over CIP); IEC 61850 MMS
  uses FileOpen/FileRead/ObtainFile and domain download; DNP3 uses its
  file-transfer objects; classic S7comm uses a block download sequence (request
  download, download block, download ended) that on many platforms carries
  program/data blocks rather than firmware — S7-1200/1500 firmware usually goes
  via web/MMC. Verify the exact class/service/function codes against your
  dissector and a live capture before signaturing, and prefer behavioral
  framing. S7comm-plus (S7-1500) is encrypted, so classic codes do not apply —
  fall back to asset-baseline drift and EWS telemetry.

## Tools & Systems

Zeek + ICSNPP (`icsnpp-enip`, `icsnpp-dnp3`, `icsnpp-s7comm`, `icsnpp-bacnet`),
Suricata, Snort, Dragos Platform, Nozomi Guardian, Claroty CTD/xDome
(firmware-version inventory), Microsoft Defender for IoT, CISA Malcolm,
Wireshark ICS dissectors. Reference/forensic: binwalk; vendor ControlFLASH /
TIA Portal as the legitimate update baseline (sibling
`performing-plc-firmware-security-analysis` for offline image analysis).
Historians: OSIsoft/AVEVA PI. SIEM: Splunk, Microsoft Sentinel.

## Detection Queries

Protocol function/class values below are **illustrative** — verify against your
dissector and a live capture; the version-drift check is vendor-agnostic and
should anchor the detection, with a hash comparison as the on-demand
confirmation on the devices it flags.

### Splunk — firmware version drift outside a change window (core)

```spl
/* asset_inventory only: including device_alarm adds rows carrying neither
   firmware field, which can make latest() return null and drop the device from
   the diff. `firmware_hash` is only present if you ingest it from an OFFLINE
   image pull - passive inventory gives version strings only, so version drift
   is the continuous signal and the hash comparison is the on-demand
   confirmation. */
index=ot sourcetype=asset_inventory
| stats latest(firmware_version) as cur latest(firmware_hash) as hash by device_id
| lookup golden_firmware device_id OUTPUT golden_version golden_hash
| where cur!=golden_version OR (isnotnull(hash) AND hash!=golden_hash)
| lookup change_windows device_id OUTPUT window_active
| where window_active!="true"
| table device_id, cur, golden_version, hash, golden_hash
```

### Zeek (ICSNPP) — firmware/file transfer from a non-allowlisted host

```
# Pseudo-Zeek over icsnpp-enip / icsnpp-dnp3 / icsnpp-s7comm.
# Verify which service/function actually carries firmware for your device;
# alert when the source is not an authorized EWS or patch server.
event ics_file_transfer(c: connection, device: string, op: string) {
    if ( is_firmware_op(op) && ! is_authorized_patch_source(c$id$orig_h) )
        NOTICE([$note=OT_Firmware_Transfer_From_Unexpected_Host, $conn=c]);
}
```

### Splunk — tie version change to an update event and a reboot

```spl
index=ot (sourcetype=asset_inventory event=firmware_version_change)
   OR (sourcetype=device_alarm event IN ("update_session","device_reboot"))
| transaction device_id maxspan=1h
| search event=firmware_version_change AND event=device_reboot
| table _time, device_id, firmware_version, src_host
```

## Common Scenarios

- **Implant via built-in update:** a firmware transfer from an unknown host,
  then a version/hash change and reboot, with no change ticket.
- **Module firmware swap:** the CPU image is unchanged but a comms module's hash
  drifts from golden — caught only because module firmware is baselined.
- **Supply-chain firmware:** a device ships/returns with firmware whose hash
  does not match the vendor's published golden image.
- **False positive:** an authorized patch inside a change window from an
  allowlisted patch server, matching the new vendor golden hash — closed by the
  change-window and golden-image lookups.

## Output Format

```
OT FIRMWARE MODIFICATION DETECTION
  Target device:   <PLC/RTU/IED id + IP>  scope: <system .001 | module .002>
  Verdict:         <confirmed-modified | suspected | authorized-patch>
  Drift:           <version cur vs golden> / <hash cur vs golden>
  Delivery:        <protocol+source host | removable media | supply chain | unknown>
  Signed:          <valid | failed | not-supported-on-model>
  Timeline:        <transfer -> version change -> reboot @ times>
  Change window:   <matched | none>
  ATT&CK:          T1693(.001/.002)
  Actions taken:   <device isolated | image captured for diff | golden image restored | source blocked>
```

## Response

- **Isolate** the device and **capture its current firmware** for a forensic
  diff against the golden image before changing anything.
- **Restore** a known-good signed image via a trusted path; confirm module
  firmware as well as the CPU image.
- **Harden:** enforce vendor firmware **code signing** and verification where
  supported, restrict firmware update to authenticated local actions and
  allowlisted patch servers, control removable media, vet supply-chain
  firmware, segment management networks (IEC 62443 conduits), and keep a signed
  golden-image library per asset class for continuous comparison.
