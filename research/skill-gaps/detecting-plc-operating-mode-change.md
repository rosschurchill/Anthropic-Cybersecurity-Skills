# Detecting PLC Operating Mode Change — research notes

- **Proposed slug:** detecting-plc-operating-mode-change
- **ATT&CK (ICS):** T0858 Change Operating Mode (tactic: evasion / execution) — closely related:
  T0843 Program Download (downloads often require a mode change), T0889 Modify Program,
  T0800 Activate Firmware Update Mode, T0834 Native API
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary changing a controller's operating mode — RUN, PROGRAM/STOP, REMOTE, or a
vendor service/firmware-update mode — to enable program downloads, suspend process control, or
access privileged functions. A mode change to PROGRAM/STOP is frequently the precursor to a
malicious download (T0843) and is itself an availability/evasion action. The skill catches both
API-driven mode changes on the network and, where the device reports it, physical key-switch
changes.

## Data sources / telemetry
- **Passive ICS network sensor (primary):** ICS management-protocol functions that change mode:
  - **S7comm (Siemens)** — PI-service 0x28 (start CPU) and 0x29 (PLC stop) carry RUN/STOP.
    **Verify against the Wireshark S7comm dissector — community-sourced codes.** S7comm-plus is
    encrypted; detect by session behavior.
  - **EtherNet/IP + CIP (Rockwell)** — CIP control-class services issue Stop/Run/Reset
    (unauthenticated at the CIP layer; Rapid7's Allen-Bradley module issues a CPU STOP). The exact
    CIP service/class code for processor mode is vendor-specific — **verify before writing a
    signature; 0x4C/0x4D are tag read/write, not mode change.**
  - **Modbus/UMAS (Schneider)** — UMAS over Modbus FC 90 / 0x5A performs unauthenticated STOP/RUN on
    Modicon/Unity (Rapid7 modicon_command). Parse the FC90 sub-function for the mode operation.
  - DNP3 / IEC 61850 MMS where the device supports remote mode control.
- **Device application logs / alarms (DC0038 / DC0108):** some controllers log mode transitions and
  raise alarms; coverage is device-dependent. Physical key-switch changes are only visible if the
  device emits a mode-change alarm/log — there is often no network event for a key-switch turn.
- **Asset baseline + EWS (Sysmon/EDR):** which hosts may issue mode changes; programming-software
  launch around the transition.
- **Historian:** a sudden halt/resume of process-value updates corroborates a STOP/RUN.

## Detection logic / approach
MITRE detection strategy **DET0755** (analytic AN1887): monitor ICS management protocols for
functions that change an asset's operating mode, plus device application logs and device alarms. A
concrete productized example: **Microsoft Defender for IoT emits a "PLC Operating Mode Changed"
alert mapped to T0858, queryable in Microsoft Sentinel (KQL)** — a real detection to reference.

Core logic: alert on any mode-change function to a controller, scored by context — source not an
allowlisted EWS, off-hours, no change ticket, or immediately followed by a program download
(T0843 chain = high confidence).

Zeek (CISA ICSNPP): `icsnpp-s7comm` logs PI-service start/stop; `icsnpp-enip` `cip.log` logs CIP
control services — alert on mode transitions from a non-EWS source.

Suricata (pseudo-rule, S7comm STOP — verify code/offset):
```
alert tcp !$EWS any -> $PLC 102 (msg:"ICS S7comm CPU STOP from non-EWS host";
  flow:to_server,established; content:"|32|"; offset:7; depth:1;   # S7comm ROSCTR
  content:"|29|"; distance:0; within:20;                           # PLC stop (VERIFY)
  sid:XXXXXXX; rev:1;)
```
Sentinel/Splunk: alert on the Defender-for-IoT "PLC Operating Mode Changed" event (or equivalent
sensor event); enrich with EWS session and change feed; correlate a STOP transition followed by a
download as the reprogramming kill-chain.

## Response / mitigation
Enforce the physical **key-switch in RUN** so remote mode changes are blocked by hardware — the
strongest control (M0801 Access Management). Protocol-aware OT firewall denying mode-change functions
from non-EWS sources; software/device and human-user authentication on management functions (M0813,
M0804); authorization enforcement (M0800). Gate any planned mode change behind change control and
maintenance windows. On an unauthorized STOP/mode change: treat as an active intrusion (likely
precursor to download), isolate the controller, verify logic integrity, restore service through
change control.

## Real tools
Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT (PLC Operating
Mode Changed alert) with Microsoft Sentinel; Zeek + CISA ICSNPP (`icsnpp-s7comm`, `icsnpp-enip`);
Suricata/Snort + Emerging Threats SCADA; CISA Malcolm; Wireshark S7comm/CIP dissectors; vendor
engineering software logs.

## Draft frontmatter mappings
- mitre_attack: [T0858, T0843, T0889]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, PR.AA-05, PR.PS-01, PR.IR-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling (for the negative trigger): detecting-attacks-on-scada-systems

## Draft description (<=1024 chars)
Detects unauthorized PLC/controller operating-mode changes — RUN, PROGRAM/STOP, REMOTE, or service
mode — issued over ICS management protocols (S7comm start/stop, CIP Stop/Run/Reset, Modbus UMAS
function code 90) or via key-switch where the device logs it, often as a precursor to a malicious
program download (ATT&CK ICS T0858). Flags mode changes from non-allowlisted sources, off-hours, or
with no change ticket, and chains STOP-then-download. References Microsoft Defender for IoT's PLC
Operating Mode Changed alert. Use when triaging unexpected controller STOP/RUN transitions, remote
mode changes, or building key-switch and management-function enforcement. Keywords: change operating
mode, PLC STOP, RUN mode, key switch, S7comm 0x29, UMAS FC90, CIP Stop, DET0755, T0858. Do not use
for broad SCADA intrusion detection - use detecting-attacks-on-scada-systems.

## Key references
- MITRE ATT&CK T0858 + DET0755: https://attack.mitre.org/techniques/T0858/ , https://attack.mitre.org/detectionstrategies/DET0755
- Microsoft Defender for IoT "PLC Operating Mode Changed" (Sentinel): https://learn.microsoft.com/azure/defender-for-iot/
- CISA ICSNPP: https://github.com/cisagov/ICSNPP , https://github.com/cisagov/icsnpp-s7comm
- Rapid7 Modicon command (UMAS STOP/RUN, verify): https://www.rapid7.com/db/modules/auxiliary/admin/scada/modicon_command

## Open questions / scope boundaries
- Verify S7comm start/stop codes, the CIP processor-mode service/class code, and the UMAS FC90
  sub-function against live captures before shipping signatures (flagged verify above).
- Physical key-switch changes may produce no network event — author must state this coverage limit
  and rely on device alarms where available.
- Boundary vs T0843 (download) and T0889 (logic change) — this skill is the *mode transition*. Must
  NOT include offensive stop/mode-change procedures.
