# Detecting PLC Program Upload — research notes

- **Proposed slug:** detecting-plc-program-upload
- **ATT&CK (ICS):** T0845 Program Upload (tactic: collection) — closely related:
  T0843 Program Download (write counterpart), T0888 Remote System Information Discovery,
  T0801 Monitor Process State, T0889 Modify Program (upload is often recon before modify)
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary *reading* control logic off a PLC/controller (an upload, in vendor
terminology — the controller is the source). Program upload is a collection/recon step:
attackers pull the running logic to understand the process before crafting a Program Download
(T0843) or Modify Program (T0889). Catching unexpected uploads — from a non-engineering host or
outside maintenance — gives early warning of reconnaissance that precedes logic tampering.

## Data sources / telemetry
- **Passive ICS network sensor:**
  - **S7comm (Siemens)** — upload sequence function codes: start upload 0x1D, upload 0x1E,
    end upload 0x1F (download sequence 0x1A–0x1C is T0843). **Verify against Wireshark S7comm
    dissector / Siemens docs — community-sourced table.** S7comm-plus (S7-1500) is
    encrypted — detect on session behavior, not raw code.
  - **EtherNet/IP + CIP** — CIP read-class / Get_Attribute services and vendor upload services
    on TCP 44818; CIP 0x4C is tag read (verified), but full *program* upload uses vendor-specific
    services — **verify exact CIP service/class codes before signatures.**
  - **Modbus/UMAS (Schneider)** — UMAS over Modbus FC 90 / 0x5A on port 502 carries read/upload
    sub-functions; parse the sub-function, not just the FC.
  - OPC UA, IEC 61850 MMS read services for configuration/program objects where supported.
- **Engineering workstation (Sysmon/EDR):** launch of vendor programming software (TIA Portal,
  Studio 5000, Unity/Control Expert) and creation of exported project/listing files on the host
  that performed the upload.
- **Asset baseline (Claroty/Nozomi/Dragos):** which hosts are legitimate engineering stations;
  an upload from anything else is suspect. Device alarms where the controller logs upload events.

## Detection logic / approach
MITRE places T0845 under **Collection**; detection leans on network traffic content and device
application logs (device alarms where emitted). The upload itself is a legitimate engineering
action, so the signal is **context**, not the action: source host not in the EWS allowlist,
off-hours, no change/maintenance ticket, or an upload immediately followed later by a download.

Zeek (CISA ICSNPP): `icsnpp-s7comm` upload/download log — alert on upload events where
`id.orig_h` is not an allowlisted EWS. `icsnpp-enip` `cip.log` — CIP read-class to a controller
from a non-EWS host.

Suricata (pseudo-rule, S7comm upload — verify codes/offsets):
```
alert tcp !$EWS any -> $PLC 102 (msg:"ICS S7comm program UPLOAD from non-EWS host";
  flow:to_server,established; content:"|32|"; offset:7; depth:1;   # S7comm ROSCTR
  content:"|1d|"; distance:0; within:20;                           # start-upload (VERIFY)
  threshold:type limit, track by_src, count 1, seconds 60; sid:XXXXXXX; rev:1;)
```
Splunk/Sentinel: correlate upload network events with Sysmon EID 1 programming-software launch on
the source and with the change feed; alert when no approved change and source is non-EWS. Sequence
rule: an upload (T0845) followed by a download (T0843) to the same controller is a high-confidence
recon-then-tamper chain.

## Response / mitigation
Allowlist engineering sources and restrict controller programming ports to named EWS via a
protocol-aware OT firewall/data diode (M0801 Access Management, M0807 Network Allowlists — verify
mitigation ID). Software/device authentication (M0813) and human-user authentication (M0804) on
engineering sessions. Audit upload events against change control (M0947). Treat an unexpected upload
as reconnaissance: raise monitoring on that controller and verify logic integrity against the
golden master.

## Real tools
Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT; Zeek + CISA
ICSNPP (`icsnpp-s7comm`, `icsnpp-enip`); Suricata/Snort + Emerging Threats SCADA; CISA Malcolm;
Wireshark S7comm/CIP dissectors; vendor engineering software logs (TIA Portal, Studio 5000,
Control Expert).

## Draft frontmatter mappings
- mitre_attack: [T0845, T0843, T0889, T0888]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, PR.AA-05, ID.AM-02]
- suggested subdomain: ot-ics-security
- nearest existing sibling (for the negative trigger): detecting-plc-program-download

## Draft description (<=1024 chars)
Detects unauthorized PLC/controller program uploads — an adversary reading running control logic
off a controller (S7comm upload sequence, CIP read-class services, Modbus UMAS function code 90)
as reconnaissance before tampering. Flags uploads from non-allowlisted hosts, off-hours, or with no
change ticket, and chains an upload followed by a download as recon-then-tamper (ATT&CK ICS T0845).
Use when triaging suspicious engineering sessions, unexpected logic reads from an unknown host, or
when building engineering-source allowlisting. Keywords: PLC program upload, S7comm upload, CIP
read, UMAS FC90, TIA Portal, Studio 5000, reconnaissance, ICSNPP, T0845. Do not use for detecting
logic being written INTO a controller - use detecting-plc-program-download.

## Key references
- MITRE ATT&CK T0845: https://attack.mitre.org/techniques/T0845/
- CISA ICSNPP: https://github.com/cisagov/ICSNPP , https://github.com/cisagov/icsnpp-s7comm
- Wireshark S7comm dissector (code reference, verify): https://www.wireshark.org/
- CISA Malcolm: https://github.com/cisagov/Malcolm

## Open questions / scope boundaries
- Confirm S7comm upload function codes and CIP upload service codes against live captures (verify).
- Boundary vs T0843: this is the read/upload (collection); the write/download is its sibling. Must
  NOT include offensive logic-extraction procedures.
- Decide whether to treat upload-only as an alert or only as an enrichment that raises severity on a
  later download, since isolated uploads are frequently legitimate engineering backups.
