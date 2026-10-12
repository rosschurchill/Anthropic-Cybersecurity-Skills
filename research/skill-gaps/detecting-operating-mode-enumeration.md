# Detecting Operating Mode Enumeration — research notes

- **Proposed slug:** detecting-operating-mode-enumeration
- **ATT&CK (ICS):** T0868 Detect Operating Mode (tactic: Collection) — detection strategy DET0768 / analytic AN1900. Closely related: T0888 Remote System Information Discovery, T0846 Remote System Discovery, T0801 Monitor Process State, and the downstream abuse it enables — T0843 Program Download, T0889 Modify Program, T0800 Activate Firmware Update Mode.
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries reading a controller's operating mode (run / program / remote, or key-switch position) during reconnaissance. Mode state tells an attacker whether reprogramming, download, or firmware operations will succeed, so mode reads are a precursor to impactful actions. The skill flags mode-query functions seen on the wire or in engineering-software logs, especially from unexpected sources or via a read path not used in normal operations, so defenders can act before a program/firmware change follows.

## Data sources / telemetry
- **Passive ICS protocol monitoring (network traffic content, DC0085):**
  - **EtherNet/IP + CIP:** `Get_Attribute_Single` (service 0x0E) / `Get_Attributes_All` (0x01) against the **Identity Object (class 0x01, instance 1, attribute 8 = device State)**. ODVA State enum: 0 nonexistent, 1 self-test, 2 standby, 3 operational, 4 major recoverable fault, 5 major unrecoverable fault. Rockwell Logix run-vs-program / key-switch detail is read via vendor-specific objects, not the standard State attribute — **verify exact class/attribute against ODVA CIP Vol.1 and Rockwell docs before asserting a Logix run/prog mapping**.
  - **S7comm (Siemens, ISO-TSAP TCP/102):** userdata CPU-functions group reading CPU diagnostics / SZL (System Status List). Operating-mode / mode-transition SZL IDs (e.g. SZL 0x0424 mode-transition) — **verify SZL IDs**.
  - **Modbus/TCP (502):** no standard "read mode" function; vendor overlays carry it — e.g. Schneider **UMAS over FC 0x5A (90)** "read PLC status/info" sub-function — **verify UMAS sub-codes**. FC 0x2B/43 MEI type 14 (Read Device Identification) is an adjacent enumeration read.
  - **DNP3 (20000):** READ (func 1) of internal indication / class-0 that exposes device state.
  - **IEC 61850 MMS (102):** `GetVariableAccessAttributes` / Read of logical-node status (LN `LLN0` mode `Mod`/`Beh`).
- **Engineering-workstation (EWS) + vendor software logs:** TIA Portal, Studio 5000 (FactoryTalk), Unity Pro / EcoStruxure Control Expert "go online" / read-status actions, with host process-creation (Sysmon EID 1) for the engineering binary.
- **Asset-inventory baseline:** Claroty / Nozomi / Dragos records of which masters/EWS normally poll controller state.

## Detection logic / approach
Core idea (AN1900): monitor ICS automation protocols for mode-read functions, and alert when the read comes from an **unexpected source** or via a **path not normally used** for mode in this environment.

- **Zeek (ICSNPP analyzers from INL):** on `icsnpp-enip` log the CIP `service`+`class_id`+`attribute_id`; alert on Identity-Object (0x01) attribute-8 reads from a source not in the EWS/master allowlist. On `icsnpp-s7comm` alert on CPU-function/SZL mode reads from non-EWS hosts.
  ```
  # Zeek (pseudo): CIP Identity State read from a non-engineering host
  event cip_get_attribute(c, class_id, instance, attribute) {
    if ( class_id == 0x01 && attribute == 8 && ! is_known_ews(c$id$orig_h) )
      NOTICE([$note=CIP_OperatingMode_Read_From_Unexpected_Host, $conn=c]);
  }
  ```
- **Suricata (built-in `enip`/`cip`, `modbus`, `dnp3` keywords):** match CIP Get_Attribute_Single to Identity class/attr, or Modbus FC 0x2B/0x5A, with `ip_src` outside the master net. Example (verify keyword support for class/attr matching in the deployed Suricata version):
  ```
  alert enip any any -> $PLC_NET 44818 (msg:"ICS operating-mode read from non-EWS host"; \
    flow:to_server; cip.service:0x0E; cip.class:0x01; \
    threshold:type limit,track by_src,count 1,seconds 60; sid:X; rev:1;)
  ```
- **SIEM (Splunk/Sentinel):** correlate EWS "go online"/read-status events with the same host's subsequent program-download or firmware activity — a mode read tightly followed by a write is the high-value sequence.

## Response / mitigation
Investigate the source host and account; confirm whether a change window or maintenance task explains the read. Enforce host/master allowlists and segmentation so only sanctioned EWS can query controllers (IEC 62443 zones/conduits). Prefer controllers in **RUN with key-switch physically keyed** so program operations require a local action. Monitor for the follow-on (program download / firmware mode) as the escalation signal.

## Real tools
Zeek + ICSNPP (`icsnpp-enip`, `icsnpp-s7comm`, `icsnpp-modbus`, `icsnpp-dnp3`), Suricata, Snort, Dragos Platform, Nozomi Networks Guardian, Claroty CTD/xDome, Microsoft Defender for IoT, CISA Malcolm, Security Onion. EWS telemetry: Siemens TIA Portal, Rockwell Studio 5000 / FactoryTalk, Schneider EcoStruxure Control Expert (Unity Pro).

## Draft frontmatter mappings
- mitre_attack: [T0868, T0888, T0846, T0801]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, ID.AM-01, ID.AM-03]
- suggested subdomain: ot-ics-security
- nearest existing sibling: performing-ics-asset-discovery-with-claroty (also detecting-attacks-on-scada-systems)

## Draft description (<=1024 chars)
Detects operating-mode enumeration against PLCs, RTUs and IEDs — CIP Identity-Object state reads, S7comm CPU/SZL diagnostics, Modbus vendor status reads and DNP3/MMS status queries — on the wire and in engineering-workstation logs, flagging mode reads from unexpected sources or via unusual paths (ATT&CK ICS T0868). Use when hunting ICS reconnaissance, when a controller's run/program state is being queried by a non-engineering host, or when building Zeek/Suricata coverage for mode-read functions ahead of a program or firmware change. Keywords: Detect Operating Mode, T0868, key switch, run program remote, CIP Identity Object attribute 8, S7comm SZL, UMAS, DNP3, Zeek ICSNPP, Suricata enip. Do not use for program-logic download or modification detection — use detecting-attacks-on-scada-systems; for broad asset enumeration baselining use performing-ics-asset-discovery-with-claroty.

## Key references
- MITRE ATT&CK ICS T0868: https://attack.mitre.org/techniques/T0868/
- MITRE detection strategy DET0768 (Detect Operating Mode): https://attack.mitre.org/detectionstrategies/DET0768/
- INL ICSNPP Zeek parsers: https://github.com/cisagov/icsnpp (and https://github.com/idaholab)
- ODVA CIP / EtherNet/IP (Identity Object) — spec via https://www.odva.org/
- Dragos, MITRE ATT&CK for ICS overview: https://www.dragos.com/mitre-attack-for-ics

## Open questions / scope boundaries
- **Verify** the exact CIP object/attribute that exposes Logix run-vs-program and key-switch position (standard Identity State 0–5 does not encode run/prog); likely a Rockwell vendor object.
- **Verify** S7comm SZL IDs for operating-mode/mode-transition reads and Schneider UMAS status sub-function codes before hard-coding rule content.
- Mode names and read paths are vendor-specific; the skill must tailor the allowlist per controller family rather than assume a universal signal.
- Scope is *reconnaissance* (reading mode). Changing mode / downloading belongs to sibling skills — keep the negative trigger sharp. Defensive framing only.
