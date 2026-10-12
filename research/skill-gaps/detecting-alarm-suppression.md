# Detecting Alarm Suppression — research notes

- **Proposed slug:** detecting-alarm-suppression
- **ATT&CK (ICS):** T0878 Alarm Suppression (tactic: Inhibit Response Function) — detection strategy DET0728 / analytic AN1861. Closely related: T0838 Modify Alarm Settings, T0803 Block Command Message, T0804 Block Reporting Message, T0837 Loss of Protection, T0832 Manipulation of View. Real example: Maroochy Water Breach (alarm reporting to the central computer suppressed).
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries suppressing alarms so operators are not notified of critical process conditions — by blocking/dropping the alarm message, muting it at the HMI, manipulating the I/O or flag bit that signals it, or disabling event reporting on the wire. Distinct from T0838 (a persistent config change), suppression is often transient and leaves a negative signal: the alarm that *should* have fired did not. The skill builds missing-expected-alarm and loss-of-signal logic across protocol, process and HMI telemetry.

## Data sources / telemetry
- **Network traffic content (DC0085) — the drop/block signals:**
  - **Cyclic/polling baselines:** expected periodic traffic from field devices (Modbus polls, DNP3 integrity/event polls, GOOSE heartbeats, OPC UA subscriptions) — a drop below baseline is a core tell.
  - **DNP3:** `DISABLE_UNSOLICITED` (function 21) issued to an outstation stops it from spontaneously reporting events/alarms; absence of expected unsolicited responses or event-class data.
  - **IEC 61850:** Report Control Block (RCB) disabled (`RptEna`=false) stops buffered/unbuffered reports; **GOOSE** gaps — a stalled `stNum`/`sqNum` or missed heartbeat within the configured `timeAllowedtoLive` indicates suppressed/blocked state messages.
  - **OPC UA:** removed/disabled Alarms & Conditions subscriptions or monitored items; absence of expected `Event`/`ConditionRefresh` notifications.
  - **BACnet:** disabled COV subscriptions, `Notification Class` recipients removed, or `DeviceCommunicationControl` silencing a device.
- **Operational process data (process state):** historian trends showing a value crossing a known alarm limit with no corresponding alarm event — loss of process data or a frozen/last-good value is itself suspicious.
- **Device alarms (DC0108):** expected device-generated alarms that are missing from the HMI/historian alarm journal.
- **HMI/historian alarm journals:** FactoryTalk A&E, WinCC, AVEVA, Ignition, PI — gaps, mass acknowledgements, or alarm-shelving/mute actions.

## Detection logic / approach
Core idea (AN1861): three corroborating checks — (1) a drop in expected network traffic, (2) loss of operational process data, (3) expected device alarms going missing. None directly proves suppression; together, and against a baseline, they do.

- **Missing-expected-alarm (SIEM — Splunk/Sentinel):** join process values against alarm journal; alert when a value breaches a limit but no alarm event exists in the window:
  ```
  index=ot sourcetype=historian value>=limit_high
  | join type=left device_id point [ search index=ot sourcetype=alarm_journal | stats count as alarms by device_id point ]
  | where isnull(alarms) OR alarms=0   // breach with no alarm -> suppression candidate
  ```
- **Traffic/heartbeat loss (Zeek):** per-asset expected-interval model; NOTICE when cyclic traffic, DNP3 unsolicited responses, or GOOSE heartbeats from a device stop. ICSNPP `icsnpp-dnp3` to flag `DISABLE_UNSOLICITED`; `icsnpp-genisys`/GOOSE monitoring for `stNum`/`sqNum`/TTL anomalies.
  ```
  # Zeek (pseudo): DNP3 disable-unsolicited from a non-master host
  event dnp3_application_request_header(c, fc) {
    if ( fc == 21 && ! is_known_master(c$id$orig_h) )   # DISABLE_UNSOLICITED
      NOTICE([$note=DNP3_DisableUnsolicited_Suspicious, $conn=c]);
  }
  ```
- **Suricata/Snort ICS:** signatures for DNP3 disable-unsolicited and for anomalous RCB-disable MMS writes (verify keyword support).
- **HMI action audit:** alert on bulk alarm shelving/suppression/mute at the HMI outside normal operator patterns.

## Response / mitigation
Treat missing alarms as a potential safety event: manually verify the physical process state, restore event reporting (re-enable unsolicited/RCB/COV/subscriptions), and check whether a limit was also changed (pivot to T0838). Harden: network allowlists and segmentation so only authorized masters/servers can issue reporting-control commands (IEC 62443), independent **out-of-band alarm channels** (annunciators, separate SIS/safety alarms) so one path cannot blind operators, heartbeat/liveness monitoring for every critical reporting flow, and baseline models of expected alarm/traffic rates.

## Real tools
Zeek + ICSNPP (`icsnpp-dnp3`, `icsnpp-modbus`, `icsnpp-bacnet`, `icsnpp-opcua-binary`, GOOSE/`icsnpp-genisys`), Suricata, Snort, Dragos Platform, Nozomi Guardian, Claroty CTD, Microsoft Defender for IoT, CISA Malcolm, Security Onion. HMI/historian: FactoryTalk A&E, Siemens WinCC, AVEVA, Ignition, OSIsoft/AVEVA PI. SIEM: Splunk, Microsoft Sentinel.

## Draft frontmatter mappings
- mitre_attack: [T0878, T0838, T0804, T0803, T0837]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, RS.MI-01, PR.IR-04]
- suggested subdomain: ot-ics-security
- nearest existing sibling: detecting-attacks-on-scada-systems (also detecting-alarm-setting-tampering, implementing-ot-network-traffic-analysis-with-nozomi)

## Draft description (<=1024 chars)
Detects alarm suppression in OT — alarms that should have fired but did not — via missing-expected-alarm logic (process value breaches a limit with no alarm event), loss of cyclic traffic or heartbeats, and protocol signals like DNP3 DISABLE_UNSOLICITED, IEC 61850 RCB disable, GOOSE stNum/TTL gaps, and BACnet COV/Notification removal (ATT&CK ICS T0878, Maroochy-style). Use when operators report missing alarms, when a process excursion raised no alarm, or when building liveness and missing-alarm monitoring across protocol, process and HMI telemetry. Keywords: Alarm Suppression, T0878, missing alarm, DISABLE_UNSOLICITED, DNP3, GOOSE heartbeat, Report Control Block, out-of-band alarm, heartbeat loss. Do not use for persistent alarm-configuration changes (thresholds/enable flags) — use detecting-alarm-setting-tampering; for SCADA intrusion detection broadly use detecting-attacks-on-scada-systems.

## Key references
- MITRE ATT&CK ICS T0878: https://attack.mitre.org/techniques/T0878/
- MITRE detection strategy DET0728: https://attack.mitre.org/detectionstrategies/DET0728/
- INL/CISA ICSNPP Zeek parsers: https://github.com/cisagov/icsnpp
- DNP3 (IEEE 1815) function-code reference / Zeek dnp3 analyzer: https://docs.zeek.org/
- Maroochy Water Breach case study (CISA / MITRE references): https://www.cisa.gov/

## Open questions / scope boundaries
- **Verify** IEC 61850 RCB-disable and GOOSE TTL/`stNum` anomaly detection against the deployed monitoring stack; confirm Suricata MMS keyword support.
- Missing-expected-alarm logic depends on a per-point alarm-limit baseline and expected-traffic model — document these prerequisites.
- Boundary with T0838: suppression here is transient blocking/muting/non-reporting; a persistent config change (new limit, disabled flag) is the sibling. The two frequently co-occur — cross-reference, keep triggers distinct. Defensive only.
