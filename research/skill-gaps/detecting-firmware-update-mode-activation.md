# Detecting Firmware Update Mode Activation — research notes

- **Proposed slug:** detecting-firmware-update-mode-activation
- **ATT&CK (ICS):** T0800 Activate Firmware Update Mode (tactic: Inhibit Response Function) — detection strategy DET0802 / analytic AN1934. Closely related: T1693 Modify Firmware, T0857 System Firmware, T0814 Denial of Service, T0816 Device Restart/Shutdown, T0803 Block Command Message. Real example: Industroyer (S0604) SIPROTEC DoS module.
- **Status:** research (not yet a skill)

## Defensive goal
Detect when a field controller, RTU, PLC, IED or safety/protection relay is placed into firmware update mode. Update mode is a legitimate feature, but an adversary who triggers it halts the device's protective response functions and can leave it in an inactive holding state if no firmware follows — a denial-of-response with no firmware ever written. The skill catches the mode-transition on the wire, in device alarms, and in asset logs, and separates it from a sanctioned maintenance window.

## Data sources / telemetry
- **Network traffic content (DC0085) — passive protocol monitoring:**
  - **IEC 61850 / Siemens SIPROTEC relays:** Industroyer's SIPROTEC DoS targeted these; the documented vector was crafted **UDP packets to port 50000** (CVE-2015-5374) putting the relay into an unresponsive state requiring manual restart — **verify that the exact "firmware update mode" semantics vs. DoS-crash match the device model**.
  - **EtherNet/IP + CIP:** firmware/file operations ride the **File Object (class 0x37)** and vendor update services (Rockwell ControlFLASH/ControlFLASH Plus over CIP) — **verify class/service per device**.
  - **S7comm (TCP/102):** no standard "firmware update mode" opcode; Siemens firmware updates typically use the device web server / MMC card or TIA Portal, not S7comm job codes — scope carefully.
  - **Modbus/TCP (502):** no standard firmware function; vendor overlays (e.g. Schneider UMAS FC 0x5A) carry bootloader/update steps — **verify sub-codes**.
  - **BACnet:** `ReinitializeDevice` (confirm vs. `DeviceCommunicationControl`) can force reboot/update states — **verify**.
- **Device alarms (DC0108):** many devices emit an alarm on entering update mode — but not all do.
- **Application log content (DC0038):** asset/controller logs and vendor engineering-software logs; note some devices log "firmware update occurred" without logging the mode transition itself.
- **EWS telemetry:** TIA Portal, Studio 5000 / ControlFLASH, EcoStruxure — process execution and update-session logs on the engineering host.

## Detection logic / approach
Core idea (AN1934): watch ICS automation protocols for the signal that an asset entered firmware update mode, back it with device alarms, and corroborate with asset logs — then alert when no approved maintenance window covers it.

- **Zeek (ICSNPP):** flag CIP File-Object / firmware-service traffic and ENIP update sessions from non-engineering hosts; record the 5-tuple and device.
- **Suricata/Snort ICS:** signature on the SIPROTEC UDP/50000 pattern and on CIP firmware-service codes; example (verify port/pattern against the advisory and your Suricata CIP keyword support):
  ```
  alert udp any any -> $RELAY_NET 50000 (msg:"Possible SIPROTEC firmware/DoS mode trigger (CVE-2015-5374)"; \
    dsize:>0; threshold:type limit,track by_src,count 1,seconds 60; sid:X; rev:1;)
  ```
- **Historian/HMI + SIEM (Splunk/Sentinel):** alert on a device-alarm "firmware update mode" or an asset log firmware event **outside an approved change window**, and correlate with loss of that device's expected cyclic traffic / process values (the inactive-holding-state tell).
  ```
  (index=ot sourcetype=device_alarm alarm_text="*firmware update*" OR event="update_mode")
  | lookup change_windows device_id OUTPUT window_active
  | where window_active!="true"
  ```
- **Missing-traffic logic:** after a mode trigger, expected polling/GOOSE/report traffic from the device drops — treat the silence as corroboration.

## Response / mitigation
Treat an out-of-window update-mode entry on a protection/safety device as a potential inhibit-response attack: verify the device is still performing its protective function, prepare to fail over or trip to a safe state, and restore firmware from a known-good signed image. Harden: patch the enabling CVEs (e.g. SIPROTEC), restrict update-mode triggers to local/authenticated actions, allowlist which hosts may reach update ports/services, segment relays (IEC 62443), and keep out-of-band monitoring so a silenced device is noticed.

## Real tools
Zeek + ICSNPP (`icsnpp-enip`, `icsnpp-genisys`, `icsnpp-bacnet`), Suricata, Snort, Dragos Platform, Nozomi Guardian, Claroty CTD, Microsoft Defender for IoT, CISA Malcolm. Vendor update tooling as reference (Rockwell ControlFLASH, Siemens TIA Portal). Historians: OSIsoft/AVEVA PI, AVEVA Historian. CISA ICS advisories / MARs for SIPROTEC and Industroyer.

## Draft frontmatter mappings
- mitre_attack: [T0800, T1693, T0857, T0814, T0816]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, RS.MI-01, PR.PS-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling: detecting-attacks-on-scada-systems (also performing-plc-firmware-security-analysis)

## Draft description (<=1024 chars)
Detects an adversary placing a PLC, RTU, IED or protection relay into firmware update mode to inhibit its response functions (ATT&CK ICS T0800) — including the Industroyer SIPROTEC case — using network protocol monitoring, device alarms, asset logs and loss-of-traffic corroboration, correlated against approved change windows. Use when a safety or protection device unexpectedly enters update mode, when cyclic traffic from a relay goes silent, or when building detections for firmware-mode transitions. Keywords: Activate Firmware Update Mode, T0800, SIPROTEC, Industroyer, CVE-2015-5374, update mode, inhibit response, CIP File Object, device alarm, change window. Do not use for firmware image tampering or integrity drift — use performing-plc-firmware-security-analysis; for host SPI/BIOS firmware corruption use detecting-firmware-corruption-attacks.

## Key references
- MITRE ATT&CK ICS T0800: https://attack.mitre.org/techniques/T0800/
- MITRE detection strategy DET0802: https://attack.mitre.org/detectionstrategies/DET0802/
- ATT&CK Software S0604 Industroyer: https://attack.mitre.org/software/S0604/
- CISA / Siemens SIPROTEC advisory (CVE-2015-5374): https://www.cisa.gov/news-events/ics-advisories (verify exact advisory ID)
- Dragos CRASHOVERRIDE/Industroyer report: https://www.dragos.com/

## Open questions / scope boundaries
- **Verify** the precise update-mode semantics per device (SIPROTEC UDP/50000 is documented as a DoS crash; confirm it is the same as "firmware update mode" for the target model).
- **Verify** CIP File-Object/service codes and any Modbus/UMAS firmware sub-functions before shipping signatures.
- Boundary: T0800 is *entering the mode* (availability/inhibit-response). Actually writing malicious firmware is T1693 — keep the negative trigger to performing-plc-firmware-security-analysis sharp. Defensive framing only; no firmware-trigger payloads.
