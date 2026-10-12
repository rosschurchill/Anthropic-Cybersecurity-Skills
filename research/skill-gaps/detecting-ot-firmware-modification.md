# Detecting OT Firmware Modification — research notes

- **Proposed slug:** detecting-ot-firmware-modification
- **ATT&CK (ICS):** T1693 Modify Firmware (tactics: Persistence, Impair Process Control, Inhibit Response Function) — detection strategy DET0904 / analytic AN2047. Sub-techniques: T1693.001 System Firmware (DET0904) and T1693.002 Module Firmware (DET0790 / AN1922). Closely related: T0800 Activate Firmware Update Mode, T0857 System Firmware, T0859 Valid Accounts, T0862 Supply Chain Compromise.
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries installing malicious or vulnerable firmware on OT devices — PLCs, RTUs, IEDs, and separately-firmwared modules such as communications/I/O cards — via a device's built-in update feature, removable media, supply chain, or remote services, to gain persistence, impair control, or inhibit response. The skill catches the firmware-write traffic, the device/asset log evidence, and the integrity drift against a known-good image and asset-management baseline, correlated with approved patch activity.

## Data sources / telemetry
- **Network traffic content (DC0085):** ICS management and file-transfer protocols carrying firmware-related functions:
  - **EtherNet/IP + CIP:** File Object (class 0x37) read/write and vendor firmware services (Rockwell ControlFLASH/ControlFLASH Plus over CIP) — **verify class/service codes**.
  - **IEC 61850 MMS (TCP/102):** `FileOpen` / `FileRead` / `ObtainFile` and domain download services used to push firmware/config to IEDs.
  - **S7comm:** block download sequence — Request Download (job 0x1A), Download Block (0x1B), Download Ended (0x1C) — carries program/data and, on some platforms, firmware-adjacent blocks; S7-1200/1500 firmware usually via web/MMC, not S7comm — **verify**.
  - **DNP3 (20000):** file-transfer objects (group 70) used for firmware/config delivery to outstations.
  - **Modbus/TCP (502):** vendor overlays (Schneider UMAS FC 0x5A bootloader steps) — **verify sub-codes**.
- **Device alarms (DC0108):** firmware-change alarms where the device emits them.
- **Application log content (DC0038):** controller logs, vendor engineering-software update logs (TIA Portal, ControlFLASH session logs, EcoStruxure), and read/write attempts to BIOS/firmware storage.
- **Integrity / baseline:** firmware version + hash compared to a **known-good image** and the **asset-management record** (Claroty/Nozomi/Dragos inventory of expected firmware versions); reboot events after a flash.

## Detection logic / approach
Core idea (AN2047 / AN1922): watch for firmware changes shown as device alarms and in app logs, monitor ICS management + file-transfer protocols for firmware functions, log read/write to firmware storage, and compare current firmware to known-good images and the asset baseline.

- **Zeek (ICSNPP):** record `icsnpp-enip` CIP File-Object transfers, `icsnpp-dnp3` group-70 file ops, `icsnpp-s7comm` download sequences; alert when a firmware/file transfer originates from a host not on the EWS/patch-server allowlist.
- **Asset-baseline drift (SIEM / Splunk/Sentinel):** the strongest signal is **version/hash change outside a change window**:
  ```
  index=ot (sourcetype=asset_inventory OR sourcetype=device_alarm)
  | stats latest(firmware_version) as cur latest(firmware_hash) as hash by device_id
  | lookup golden_firmware device_id OUTPUT golden_version golden_hash
  | where cur!=golden_version OR hash!=golden_hash
  | lookup change_windows device_id OUTPUT window_active
  | where window_active!="true"
  ```
- **Unsigned / unauthorized-source heuristic:** treat firmware delivered from an unexpected network location, or that fails vendor signature verification, as high priority. Correlate firmware-version change + update event + device reboot into one timeline per device.
- **Module firmware (T1693.002):** extend version/hash baselining to comms/I/O module firmware, not just the CPU image — modules are separately flashable and easier to overlook.

## Response / mitigation
Isolate the device, capture its current firmware for forensic diff against the golden image, and restore a known-good signed image via a trusted path. Harden: enforce vendor firmware **code signing** and verification, restrict firmware update to authenticated local actions and allowlisted patch servers, control removable media, vet supply-chain firmware, segment management networks (IEC 62443 conduits), and keep a signed golden-image library per asset class for continuous comparison.

## Real tools
Zeek + ICSNPP (`icsnpp-enip`, `icsnpp-dnp3`, `icsnpp-s7comm`, `icsnpp-bacnet`), Suricata, Dragos Platform, Nozomi Guardian, Claroty CTD/xDome (firmware-version inventory), Microsoft Defender for IoT, CISA Malcolm. Reference/forensic: binwalk, vendor ControlFLASH/TIA Portal (as the legitimate update baseline). Historians: OSIsoft/AVEVA PI. Overlaps sibling performing-plc-firmware-security-analysis for offline image analysis.

## Draft frontmatter mappings
- mitre_attack: [T1693, T1693.001, T1693.002, T0800, T0857, T0862]
- nist_csf: [DE.CM-01, DE.CM-09, ID.AM-02, PR.PS-01, PR.PS-02, RS.MI-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling: performing-plc-firmware-security-analysis (also detecting-firmware-corruption-attacks for host SPI/BIOS)

## Draft description (<=1024 chars)
Detects malicious or vulnerable firmware installed on OT devices and modules (ATT&CK ICS T1693, system .001 and module .002) via network firmware/file-transfer functions (CIP File Object, DNP3 group 70, MMS FileRead, S7comm download), device alarms, asset logs, and firmware version/hash drift against a known-good image and asset baseline, correlated with approved patch windows. Use when a PLC/RTU/IED firmware version changes unexpectedly, when investigating suspected firmware implants or supply-chain firmware, or when building firmware-integrity monitoring for OT. Keywords: Modify Firmware, T1693, module firmware, CIP File Object, ControlFLASH, DNP3 file transfer, MMS FileRead, golden image, firmware hash drift, signed firmware. Do not use for entering firmware update mode as a DoS — use detecting-firmware-update-mode-activation; for offline PLC firmware image analysis use performing-plc-firmware-security-analysis.

## Key references
- MITRE ATT&CK ICS T1693: https://attack.mitre.org/techniques/T1693/
- Sub-techniques T1693.001 / T1693.002: https://attack.mitre.org/techniques/T1693/001/ , https://attack.mitre.org/techniques/T1693/002/
- Detection strategies DET0904 / DET0790: https://attack.mitre.org/detectionstrategies/DET0904/ , https://attack.mitre.org/detectionstrategies/DET0790/
- INL/CISA ICSNPP Zeek parsers: https://github.com/cisagov/icsnpp
- Dragos MITRE ATT&CK for ICS: https://www.dragos.com/mitre-attack-for-ics

## Open questions / scope boundaries
- **Verify** CIP File-Object/firmware service codes, DNP3 file-transfer group usage, and whether S7comm download sequences carry firmware vs. only program blocks on each platform.
- Firmware signature verification support varies by vendor/model — document which asset classes actually support it before relying on "unsigned = malicious".
- Boundary: this is firmware *modification/implant*. Entering update mode as a DoS is T0800 (separate skill); host SPI/BIOS corruption is the enterprise sibling. Keep negative triggers sharp. Defensive framing only; no flashing procedures.
