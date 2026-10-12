# Detecting Network Configuration Repository Theft — research notes

- **Proposed slug:** detecting-network-config-repository-theft
- **ATT&CK:** T1602 Data from Configuration Repository (tactic: collection) — sub-techniques T1602.001 SNMP (MIB Dump), T1602.002 Network Device Configuration Dump
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary collecting network-device configuration data — dumping the SNMP MIB or exfiltrating a router/switch running-config — which exposes credentials, routing tables, interface and ACL details that enable deeper intrusion. The skill focuses on the management plane: unauthorized SNMP reads (especially of config-related OIDs), spoofed SNMP Set-Requests that trigger a config copy, and config transfers off the device (TFTP/FTP/SCP). Because endpoint/EDR agents do not run on routers and switches, detection relies on network and device-plane telemetry, not host logs.

## Data sources / telemetry
- **SNMP:** NetFlow/IPFIX and firewall logs for UDP 161/162 from unexpected sources; packet capture (Zeek, Suricata) of SNMP GET/GETBULK/SET; SNMP traps forwarded to SIEM; device SNMP server logs. Watch for spoofed `SET` requests carrying Cisco config-copy OIDs — e.g. `CISCO-CONFIG-COPY-MIB` `1.3.6.1.4.1.9.9.96.1.1.1.1.x` (`ccCopyTable`) and `OLD-CISCO-SYS-MIB` `writeNet` `1.3.6.1.4.1.9.2.1.55` — which instruct the device to write its config to a remote server.
- **Config transfer:** firewall/NetFlow for TFTP (UDP 69), FTP (TCP 21), SCP/SFTP (TCP 22) egress from network devices to non-management hosts; Zeek `tftp.log`/`ftp.log`/`conn.log`.
- **Device plane:** router/switch AAA/TACACS+ accounting and syslog for `copy running-config`, `show running-config`, archive/config-replace events, and config-change notifications (`SYS-5-CONFIG_I`); NETCONF/RESTCONF access logs.
- **Smart Install:** TCP 4786 (Cisco Smart Install) traffic — abused to pull configs (CVE-2018-0171).
- MITRE provides mitigations but limited official detection text for T1602 — **verify on live attack.mitre.org v19.2**. Primary operational guidance is the joint advisory **AA26-194A** ("Improve Router Hygiene…", Jul 2026) on FSB Center 16 actors.

## Detection logic / approach
- **Spoofed SNMP config-copy (AA26-194A core signal):** IDS/IPS rule (Snort/Suricata) for inbound SNMP `SET` (PDU type 0xA3) targeting `CISCO-CONFIG-COPY-MIB` OID `1.3.6.1.4.1.9.9.96.*` or `writeNet`, from any source outside the SNMP management ACL. Example Suricata posture:
  ```
  alert udp !$SNMP_MGMT any -> $NET_DEVICES 161 (msg:"SNMP SET to config-copy OID from unauthorized source";
    content:"|a3|"; content:"|2b 06 01 04 01 09 09 60|"; sid:100xxxx; rev:1;)
  # 2b0601040109 09 60 = 1.3.6.1.4.1.9.9.96 (CISCO-CONFIG-COPY-MIB) — verify OID byte-encoding in lab
  ```
- **MIB dump (T1602.001):** flag a single source issuing high-volume SNMP GETBULK walks across many OIDs, and any SNMP read from a host not on the management allowlist; alert on SNMPv1/v2c with default community strings (`public`/`private`).
- **Config egress (T1602.002):** NetFlow/Zeek rule — a network device as the *source* of a TFTP (UDP 69) or FTP/SCP flow to a destination that is not an approved config-backup/TFTP server. Correlate the SNMP SET and the subsequent TFTP flow within a short window (the SET names the server, the transfer follows).
- **Device-plane corroboration:** TACACS+ accounting showing `show/copy running-config` or NETCONF `get-config` from an unusual session, and config-change syslog without a corresponding change ticket.
- **FP reduction:** allowlist the real NMS/backup servers and their scheduled SNMP polls and nightly config backups; alert on source/destination and OID outside that baseline.

## Response / mitigation
- Containment: block the offending source at the edge, rotate all credentials present in the exposed config, audit for config changes. Hardening (AA26-194A / MITRE M-series): move to SNMPv3 `authPriv` and disable SNMPv1/v2c + default community strings; apply SNMP views to allowlist MIB objects; restrict management protocols with ACLs on an out-of-band network; block UDP 69 (TFTP), TCP 4786 (Smart Install) and SNMP at edge firewalls; disable Smart Install after provisioning; use Cisco Type 8 password hashing; patch/replace EOL devices (CVE-2018-0171, CVE-2008-4128 cited as exploited).

## Real tools
Zeek (tftp/ftp/conn logs), Suricata/Snort (SNMP SET IDS rules), NetFlow/IPFIX collectors, SNMP trap receivers, TACACS+/RADIUS accounting, device syslog, RANCID/Oxidized (legitimate config-backup baselines to allowlist), SIEM (Splunk/Sentinel). OIDs: CISCO-CONFIG-COPY-MIB `1.3.6.1.4.1.9.9.96`, OLD-CISCO-SYS-MIB `writeNet`. (no invented endpoints.)

## Draft frontmatter mappings
- mitre_attack: [T1602, T1602.001, T1602.002]
- nist_csf: [DE.CM-01, DE.CM-07, DE.AE-02, PR.PS-01, PR.AA-05, RS.MI-01]
- d3fend (optional): D3-NTA (Network Traffic Analysis), D3-ITF (Inbound Traffic Filtering) — verify current D3FEND IDs
- suggested subdomain: network-security
- nearest existing sibling (for the negative trigger): detecting-network-boundary-bridging

## Draft description (<=1024 chars)
Detects theft of network-device configuration data — SNMP MIB dumps and router/switch running-config exfiltration (often via spoofed SNMP config-copy Set-Requests to CISCO-CONFIG-COPY-MIB OIDs followed by a TFTP transfer, per CISA AA26-194A) — using management-plane telemetry: SNMP packet capture, NetFlow/firewall logs for UDP 161/69 and TCP 4786, Zeek tftp/ftp logs, SNMP traps, and TACACS+ accounting. Use when hunting for router/switch config collection, unauthorized SNMP reads, or config egress to unapproved hosts. Keywords: T1602, SNMP MIB dump, config copy OID, writeNet, TFTP config exfil, Smart Install, CVE-2018-0171, default community string, network device. Do not use for routing/tunnel manipulation that bridges segments - use detecting-network-boundary-bridging.

## Key references
- https://attack.mitre.org/techniques/T1602/ , /001/ , /002/ — verify detection text against v19.2
- https://www.cisa.gov/ (joint advisory AA26-194A, Improve Router Hygiene, Jul 2026) — confirm exact URL/date
- https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/improve-router-hygiene-to-protect-against-russian-state-sponsored-targeting
- Cisco CISCO-CONFIG-COPY-MIB / OLD-CISCO-SYS-MIB OID documentation

## Open questions / scope boundaries
- Author must confirm the exact OID byte-encodings in a lab before shipping IDS signatures, and build the per-environment NMS/backup allowlist (RANCID/Oxidized traffic is benign and must not alert). Confirm whether MITRE added official T1602 detection text / a DET strategy in v19.2 — **verify**.
- Strictly defensive: observe management-plane theft only; no procedures for issuing the SNMP SET or pulling configs. Must NOT cover network boundary bridging / routing manipulation (that is the sibling) or generic credential dumping from a compromised host.
