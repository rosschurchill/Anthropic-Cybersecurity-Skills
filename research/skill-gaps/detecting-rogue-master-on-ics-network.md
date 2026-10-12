# Detecting Rogue Master on ICS Network — research notes

- **Proposed slug:** detecting-rogue-master-on-ics-network
- **ATT&CK (ICS):** T0848 Rogue Master (tactic: Lateral Movement) — detection strategy DET0792 / analytic AN1924. Closely related: T0846 Remote System Discovery, T0859 Valid Accounts, T0855 Unauthorized Command Message, T0885 Commonly Used Port, T0830 Adversary-in-the-Middle (a rogue master can also capture traffic meant for the real master).
- **Status:** research (not yet a skill)

## Defensive goal
Detect an unauthorized/rogue master (control server, SCADA master, HMI, or engineering station) placed on the OT network to drive outstations via legitimate control-server functions — issuing reads, writes, and control commands — or to intercept traffic meant for the real master. The skill catches the new device by asset-baseline/ARP deviation, by control traffic from an address or MAC not on the authorized-master list, and by unexpected ICS protocol functions (writes/control) from both new and known devices.

## Data sources / telemetry
- **Asset inventory (DC0110) / baseline:** the authoritative list of authorized masters, HMIs and EWS and the master→outstation communication matrix (from Claroty / Nozomi / Dragos). New devices or new master→outstation flows are the primary signal.
- **Network traffic content (DC0085):**
  - **Source identity:** traffic from unknown/unexpected IPs; unfamiliar **source MAC** addresses opening sessions on operational protocol ports (Modbus 502, DNP3 20000, EtherNet/IP 44818/2222, S7comm 102, IEC 61850 MMS 102, OPC UA 4840, BACnet 47808).
  - **DHCP / ARP data:** new lease or ARP announcement for an unknown host; ARP anomalies (duplicate IP, changed IP→MAC binding) indicating a rogue master also doing AiTM.
  - **Master-role behavior:** a new device establishing master-side sessions with outstations — e.g. DNP3 requests from a new source address, Modbus master polling/writing, unsolicited-response enable/disable from a non-master.
  - **Unexpected protocol functions:** control/write functions from new *or existing* devices — Modbus write FCs (0x05/0x06/0x0F/0x10), DNP3 SELECT/OPERATE/DIRECT_OPERATE (func 3/4/5) and restart (13/14), CIP write-tag/forward-open, S7comm write-var (0x05) / PLC control (0x28) / PLC stop (0x29). Known devices are the hard case: distinguishing an authorized historian from a rogue one needs function-level insight, not just IP.
- **Switch/infra telemetry:** new MAC on a switch port (port-security / MAC-notification), new device on a span/tap segment.

## Detection logic / approach
Core idea (AN1924): compare observed masters and master→outstation flows against the authorized-master inventory and the normal communication matrix; alert on new devices, unexpected source IP/MAC on protocol ports, DHCP/ARP anomalies, new master-to-outstation sessions, and unexpected control/write functions from any device.

- **Zeek (ICSNPP) + allowlist:** maintain a known-master set; NOTICE on any master-role request from outside it:
  ```
  # Zeek (pseudo): Modbus/DNP3 write or control from a non-authorized master
  event modbus_message(c, headers, is_orig) {
    if ( is_orig && is_write_fc(headers$function_code) && ! is_authorized_master(c$id$orig_h) )
      NOTICE([$note=Rogue_Master_Write, $conn=c, $msg=fmt("FC %d from %s", headers$function_code, c$id$orig_h)]);
  }
  ```
  Pair with ARP monitoring (`zeek` + `known-hosts`, or `arp` events) for duplicate-IP / changed-binding alerts.
- **Suricata/Snort ICS:** `alert modbus`/`dnp3`/`enip` with `ip_src` NOT in `$AUTHORIZED_MASTERS` on write/control functions; e.g.
  ```
  alert dnp3 !$MASTERS any -> $OUTSTATIONS 20000 (msg:"Rogue DNP3 master: OPERATE from unauthorized source"; \
    flow:to_server; dnp3_func:operate; sid:X; rev:1;)
  ```
  (Verify `dnp3_func`/`modbus` keyword values in the deployed Suricata.)
- **OT monitoring platforms:** Dragos/Nozomi/Claroty "new asset" and "new communication" / baseline-deviation alerts; Fortinet FortiSIEM ships a `PH_RULE_ICS_Rogue_Master` that fires on T0848-tagged events from Dragos/Nozomi feeds — route to analyst to confirm legitimacy.
- **SIEM (Splunk/Sentinel):** alert on first-seen (src_mac, dst_outstation, protocol) tuples and on DHCP/ARP new-host events on OT VLANs; enrich with the asset inventory to auto-close known maintenance laptops.

## Response / mitigation
Locate the rogue device physically (switch port / MAC), isolate it (disable the port), and verify no outstation received malicious writes/control during its presence; roll back any unauthorized parameter/program changes. Harden: switch **port security / 802.1X / MAC allowlisting** on OT access ports, static ARP or ARP-inspection on critical segments, strict segmentation and conduit allowlists so only sanctioned masters reach outstations (IEC 62443), protocol-level authentication where available (DNP3 Secure Authentication, OPC UA security), and continuous asset-baseline monitoring.

## Real tools
Dragos Platform, Nozomi Networks Guardian, Claroty CTD/xDome (asset baseline + new-device/new-comms alerts), Zeek + ICSNPP (`icsnpp-modbus`, `icsnpp-dnp3`, `icsnpp-enip`, `icsnpp-s7comm`, `icsnpp-bacnet`), Suricata, Snort, Microsoft Defender for IoT, CISA Malcolm, Security Onion, FortiSIEM (`PH_RULE_ICS_Rogue_Master`). SIEM: Splunk, Microsoft Sentinel. Switch infra: port security / 802.1X, dynamic ARP inspection.

## Draft frontmatter mappings
- mitre_attack: [T0848, T0846, T0855, T0830, T0885]
- nist_csf: [DE.CM-01, DE.CM-07, ID.AM-01, ID.AM-03, PR.AA-05, PR.IR-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling: performing-ics-asset-discovery-with-claroty (also detecting-attacks-on-scada-systems, implementing-ot-network-traffic-analysis-with-nozomi)

## Draft description (<=1024 chars)
Detects a rogue master on an ICS network — an unauthorized control server, HMI or engineering station driving outstations with legitimate control functions, or intercepting the real master's traffic (ATT&CK ICS T0848). Uses asset-baseline and ARP/DHCP deviation, control/write traffic from IPs or MACs not on the authorized-master list, new master-to-outstation sessions, and unexpected protocol functions (Modbus writes, DNP3 SELECT/OPERATE, CIP write-tag, S7comm PLC control) from new or known devices. Use when an unknown device issues writes or control on OT, when a new master-to-outstation flow appears, or when building rogue-master detection on Zeek/Suricata/Dragos/Nozomi. Keywords: Rogue Master, T0848, unauthorized master, authorized-master allowlist, new asset, ARP anomaly, DNP3 OPERATE, Modbus write, port security. Do not use for Modbus payload/command-injection analysis alone — use detecting-modbus-command-injection-attacks; for baseline asset discovery use performing-ics-asset-discovery-with-claroty.

## Key references
- MITRE ATT&CK ICS T0848: https://attack.mitre.org/techniques/T0848/
- MITRE detection strategy DET0792: https://attack.mitre.org/detectionstrategies/DET0792/
- INL/CISA ICSNPP Zeek parsers: https://github.com/cisagov/icsnpp
- Fortinet FortiSIEM rule PH_RULE_ICS_Rogue_Master: https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_0/rules/PH_RULE_ICS_Rogue_Master.htm
- Dragos MITRE ATT&CK for ICS: https://www.dragos.com/mitre-attack-for-ics

## Open questions / scope boundaries
- **Verify** Suricata/Snort keyword support for DNP3 function matching (`dnp3_func`) and Modbus FC matching in the deployed version.
- The "known device, rogue behavior" case (authorized historian vs. rogue) needs function-level allowlisting (which device may issue which functions to which outstation) — document this as the hard requirement, not just IP allowlists.
- Boundary: this skill is *who is acting as master*; deep Modbus command-injection payload analysis is the sibling. Keep negative trigger sharp. Defensive framing only; no master-impersonation tooling.
