# Detecting Alarm Setting Tampering — research notes

- **Proposed slug:** detecting-alarm-setting-tampering
- **ATT&CK (ICS):** T0838 Modify Alarm Settings (tactics: Inhibit Response Function, Impair Process Control) — detection strategy DET0777 / analytic AN1909. Closely related: T0878 Alarm Suppression, T0835 Manipulate I/O Image, T0836 Modify Parameter, T0889 Modify Program, T0832 Manipulation of View. Real example: Maroochy Water Breach (alarms disabled at four pumping stations).
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries changing alarm configuration — thresholds/setpoints, enable/disable flags, priorities, deadbands, or notification routing — so operators are not alerted to dangerous process conditions. Unlike transient suppression, this is a persistent config change. The skill flags alarm-config changes in HMI/SCADA/historian and controller logs, on automation/management protocols, and against the expected alarm baseline, and ties each change to an authenticated user, source system, and approved change window.

## Data sources / telemetry
- **Application log content (DC0038):** the primary source.
  - **HMI/SCADA alarm-config change records:** FactoryTalk Alarms & Events, Siemens WinCC alarm logging, AVEVA/Wonderware (InTouch/System Platform) alarm database, Ignition alarm config, GE iFIX/CIMPLICITY. Capture old→new value, who, and from where.
  - **Historian alarm/event journals:** OSIsoft/AVEVA PI (PI AF analyses / event frames, PI Notifications), AVEVA Historian — record alarm-limit and notification changes.
  - **Controller/gateway logs:** alarm limits that live in PLC logic or IED settings (e.g. IEC 61850 IED setting groups).
- **Network traffic content (DC0085):** writes to alarm-related points on automation/management protocols:
  - **Modbus/TCP:** write function codes (FC 0x06 / 0x10) to registers that hold alarm setpoints/limits — needs a point map to know which registers are alarm limits.
  - **DNP3:** WRITE (func 2) / SELECT+OPERATE to analog-output / config points for alarm limits; changes to class assignments affecting event reporting.
  - **IEC 61850 MMS:** `SetDataValues` / `SetSettingGroupValues` changing alarm/trip limits, or `SetRCBValues` altering Report Control Block trigger options (dchg/qchg) — **verify service names per stack**.
  - **OPC UA:** Write / Alarm & Conditions service changes (enable/disable, limit changes) — **verify**.
  - **BACnet:** `WriteProperty` to Notification Class recipient lists, Event Enrollment limits, or an object's `Limit_Enable` / high-low limits.
- **Asset inventory (DC0110) / baseline:** the expected alarm configuration (limits, enable flags, routing) per point, from engineering records or an OT monitoring platform.
- **Authentication logs:** accounts able to change alarm config (HMI operator/engineer accounts, EWS logins).

## Detection logic / approach
Core idea (AN1909): monitor ICS asset application logs for alarm-setting changes (not all assets log them), watch for the same on automation/management protocols, and compare against the asset-management record of expected configuration; out-of-bounds process data is corroborating, not direct, evidence.

- **HMI/historian config diff (SIEM — Splunk/Sentinel):** alert on any alarm-config change event not matched to an approved change ticket + authorized engineer:
  ```
  index=ot (sourcetype=ftae_audit OR sourcetype=wincc_alarm_cfg OR sourcetype=pi_notifications)
  action IN ("alarm_limit_changed","alarm_disabled","notification_recipient_changed")
  | lookup change_windows asset OUTPUT window_active
  | lookup authorized_engineers user OUTPUT authorized
  | where window_active!="true" OR authorized!="true"
  ```
- **Baseline reconciliation:** periodically pull live alarm config from HMI/controller and diff against the golden alarm-config baseline; alert on any delta (especially disabled alarms, widened limits, removed recipients).
- **Protocol writes (Zeek/Suricata):** with a point map, alert on writes to alarm-limit registers/points from non-EWS hosts; `icsnpp-modbus` / `icsnpp-dnp3` / `icsnpp-bacnet` to log the target address + value.
- **Process-condition cross-check:** flag when process values approach/exceed historical trip bounds but no alarm fires — points to a limit that was widened or disabled.

## Response / mitigation
Restore the alarm configuration from the golden baseline; verify which conditions went unalarmed during the gap and inspect the process state. Revoke/rotate the credentials used; confirm the change source. Harden: least-privilege on alarm configuration (separate from operation), mandatory change management with logged old→new values, role separation between engineering and operating accounts, segmentation so only sanctioned EWS can write alarm points (IEC 62443), and independent/out-of-band alarm paths so a tampered HMI config does not blind every channel.

## Real tools
HMI/SCADA + historian: Rockwell FactoryTalk Alarms & Events, Siemens WinCC, AVEVA System Platform / InTouch / Historian, Inductive Automation Ignition, GE iFIX/CIMPLICITY, OSIsoft/AVEVA PI (AF, Notifications, Event Frames). Network: Zeek + ICSNPP (`icsnpp-modbus`, `icsnpp-dnp3`, `icsnpp-bacnet`, `icsnpp-opcua-binary`), Suricata, Dragos Platform, Nozomi Guardian, Claroty CTD, Microsoft Defender for IoT. SIEM: Splunk, Microsoft Sentinel.

## Draft frontmatter mappings
- mitre_attack: [T0838, T0878, T0836, T0835, T0889]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, PR.AA-05, PR.PS-01, RS.MI-02]
- suggested subdomain: ot-ics-security
- nearest existing sibling: securing-historian-server-in-ot-environment (also performing-scada-hmi-security-assessment, detecting-alarm-suppression)

## Draft description (<=1024 chars)
Detects tampering with OT alarm configuration — changed thresholds, disabled alarms, altered priorities or notification routing (ATT&CK ICS T0838, Maroochy-style) — using HMI/SCADA and historian alarm-config change logs, controller/IED setting changes, protocol writes to alarm points (Modbus, DNP3, MMS SetSettingGroupValues, BACnet Notification Class), and diff against a golden alarm baseline, tied to authenticated user and change window. Use when an alarm limit or enable flag changed unexpectedly, when a process exceeded bounds with no alarm, or when building alarm-config change monitoring. Keywords: Modify Alarm Settings, T0838, alarm limit, alarm disabled, setpoint, Notification Class, FactoryTalk Alarms and Events, WinCC, PI Notifications, change window. Do not use for transient run-time alarm blocking/muting with no config change — use detecting-alarm-suppression; for HMI hardening assessment use performing-scada-hmi-security-assessment.

## Key references
- MITRE ATT&CK ICS T0838: https://attack.mitre.org/techniques/T0838/
- MITRE detection strategy DET0777: https://attack.mitre.org/detectionstrategies/DET0777/
- Maroochy Water Breach (MITRE / Marshall Abrams & Joe Weiss case study): https://attack.mitre.org/campaigns/ (verify campaign/reference page)
- INL/CISA ICSNPP Zeek parsers: https://github.com/cisagov/icsnpp
- CISA ICS recommended practices / SANS ICS alarm management guidance: https://www.cisa.gov/ , https://www.sans.org/

## Open questions / scope boundaries
- **Verify** exact IEC 61850 MMS service names (`SetSettingGroupValues` / `SetRCBValues`) and OPC UA Alarms & Conditions service calls per stack.
- Register/point-level alarm-limit detection on Modbus/DNP3 requires a per-site point map; the skill must state this dependency, not assume it.
- Boundary with T0878: this is a *persistent configuration change*; run-time suppression/muting with no config change is the sibling. Keep negative trigger sharp. Defensive only.
