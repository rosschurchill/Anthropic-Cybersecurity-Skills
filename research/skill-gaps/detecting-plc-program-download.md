# Detecting PLC Program Download — research notes

- **Proposed slug:** detecting-plc-program-download
- **ATT&CK (ICS):** T0843 Program Download (tactic: lateral-movement) — sub-techniques
  T0843.001 Download All, T0843.002 Online Edit, T0843.003 Program Append. Closely related:
  T0889 Modify Program, T0821 Modify Controller Tasking, T0858 Change Operating Mode,
  T0845 Program Upload (the read counterpart)
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary transferring new or altered control logic *into* a PLC/controller —
a full download, an online edit, or a program append — over an engineering protocol or from
an engineering workstation (EWS). Catches the write side of logic tampering (Stuxnet-style
reprogramming, PLC-Blaster propagation) by flagging downloads from an unexpected source host,
outside an approved maintenance window, or without a matching change ticket, so defenders can
intervene before malicious logic runs the process.

## Data sources / telemetry
- **Passive ICS network sensor (span/tap at the cell/control layer):**
  - **S7comm (Siemens)** — classic S7comm program-transfer function codes: request download
    0x1A, download block 0x1B, download ended 0x1C (upload sequence 0x1D–0x1F is T0845).
    PI-service 0x28 starts/stops CPU, 0x29 PLC stop — downloads are usually bracketed by a
    STOP/RUN transition. **Verify these codes against the Wireshark S7comm dissector / Siemens
    docs — table sourced from community analysis.** S7comm-plus (S7-1500) is encrypted/anti-replay,
    so classic codes do not apply — detect on session/behavior, not raw function code.
  - **EtherNet/IP + CIP (Rockwell/Allen-Bradley)** — CIP control-class services on TCP 44818 /
    UDP 2222; mostly unauthenticated at the CIP layer. 0x4C/0x4D are CIP read/write tag (verified
    via Wireshark dev list), **not** program download — the firmware/logic download services are
    vendor-specific; **verify the exact CIP service/class codes before writing a signature.**
  - **Modbus/UMAS (Schneider Modicon/Unity/M580)** — UMAS rides Modbus TCP port 502 as vendor
    function code **90 / 0x5A** (a reserved Modbus FC); carries program/config transfer and
    unauthenticated STOP/RUN (Rapid7 modicon module). FC 0x5A sub-function parsing needed.
  - DNP3, OPC UA, IEC 61850 MMS — program/config transfer services where the controller supports them.
- **Engineering workstation (Sysmon/EDR):** process creation of vendor programming software
  (TIA Portal, Studio 5000 / RSLogix, Unity Pro / EcoStruxure Control Expert, GX Works),
  project-file opens/writes (`.ap1x`/`.zap`, `.acd`/`.l5x`, `.stu`/`.xef`), and the EWS-to-PLC
  session around the download.
- **Controller / engineering-software audit logs** where the device emits them (device alarms
  on download); **asset-inventory baseline** (Claroty/Nozomi/Dragos) giving the expected program
  version/hash to diff against.

## Detection logic / approach
MITRE detection strategy **DET0752** (analytic AN1884; sub-technique strategies DET0913
Download All, DET0914 Program Append, DET0915 Online Edit). Data components: network traffic
content (DC0085), device alarms (DC0108), software (DC0111).

Core logic: alert when a program-download function is observed from a source that is **not** an
allowlisted engineering station, or outside a change window, or with no corresponding change
ticket. Correlate with a preceding STOP transition and EWS programming-software launch.

Zeek (CISA **ICSNPP** parsers): `icsnpp-s7comm` emits a dedicated upload/download log — alert on
download events whose `id.orig_h` is not in the EWS allowlist. `icsnpp-enip` emits `cip.log` —
alert on control-class CIP services to a controller from a non-EWS host.

Suricata (pseudo-rule, Modbus/UMAS):
```
alert modbus any any -> $PLC 502 (msg:"ICS UMAS program/config to PLC (FC90) from non-EWS";
  flow:to_server; app-layer-protocol:modbus; content:"|5A|"; offset:7; depth:1;
  threshold:type limit, track by_src, count 1, seconds 60; sid:XXXXXXX; rev:1;)
```
(FC90 is in the Modbus PDU after the MBAP header — **verify byte offset** against capture; pair
with an IP allowlist via `$EWS`/`$PLC` variables rather than matching the byte alone.)

Splunk/Sentinel: join network download events to Sysmon EID 1 (programming-software launch on the
source) within a short window and to a change-management feed; fire when no approved change exists.

## Response / mitigation
Allowlist engineering sources (only named EWS may reach controller programming ports); enforce a
protocol-aware OT firewall / data diode at the conduit; require physical key-switch in RUN to block
remote downloads (M0801 Access Management). Software/device authentication (M0813), authorization
enforcement (M0800), code signing (M0945 where supported), and audit/integrity checks against a
golden-master logic repository after any download (M0947). Gate downloads behind change control and
maintenance windows; isolate the controller and restore known-good logic on an unauthorized download.

## Real tools
Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT; Zeek with CISA
ICSNPP (`icsnpp-s7comm`, `icsnpp-enip`); Suricata/Snort with Emerging Threats SCADA ruleset;
Malcolm (CISA network traffic analysis suite bundling Zeek+Suricata+Arkime); Wireshark S7comm/ENIP/CIP
dissectors; vendor engineering software (TIA Portal, Studio 5000, Unity/Control Expert) logs.

## Draft frontmatter mappings
- mitre_attack: [T0843, T0843.001, T0843.002, T0843.003, T0889, T0821]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, PR.AA-05, PR.PS-01, ID.AM-02]
- suggested subdomain: ot-ics-security
- nearest existing sibling (for the negative trigger): performing-s7comm-protocol-security-analysis

## Draft description (<=1024 chars)
Detects unauthorized PLC/controller program downloads — full downloads, online edits, and program
appends — over engineering protocols (S7comm/S7comm-plus, EtherNet/IP CIP, Modbus UMAS function code
90) and from engineering workstations. Flags downloads from non-allowlisted source hosts, off-hours,
or with no change ticket, correlating network function codes with EWS programming-software launches
and golden-master logic diffs (ATT&CK ICS T0843). Use when triaging suspected PLC reprogramming,
unexpected controller STOP/RUN transitions, downloads from an unknown host, or when building
engineering-source allowlisting. Keywords: PLC program download, S7comm, UMAS FC90, CIP, TIA Portal,
Studio 5000, online edit, ICSNPP, Stuxnet, T0843. Do not use for passive S7comm protocol assessment
or logic static analysis - use performing-s7comm-protocol-security-analysis.

## Key references
- MITRE ATT&CK T0843 + DET0752: https://attack.mitre.org/techniques/T0843/ , https://attack.mitre.org/detectionstrategies/DET0752
- CISA ICSNPP (Zeek ICS parsers): https://github.com/cisagov/ICSNPP , https://github.com/cisagov/icsnpp-s7comm , https://github.com/cisagov/icsnpp-enip
- Schneider UMAS FC90 (verify): https://www.rapid7.com/db/modules/auxiliary/admin/scada/modicon_command
- CISA Malcolm: https://github.com/cisagov/Malcolm

## Open questions / scope boundaries
- Confirm S7comm download/upload function-code table and Modbus/UMAS FC90 byte offset against live
  captures before shipping any signature (flagged verify above).
- Boundary vs T0889 (the *effect* — altered logic) and T0845 (the *read*/upload) — this skill is the
  download/write transfer event. Must NOT include any offensive reprogramming/payload procedures.
- Decide whether S7comm-plus / encrypted-session detection (behavioral) is in scope or deferred.
