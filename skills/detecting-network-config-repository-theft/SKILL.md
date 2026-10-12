---
name: detecting-network-config-repository-theft
description: 'Detects theft of network-device configuration data (MITRE T1602) - SNMP MIB dumps and router/switch running-config exfiltration, often via spoofed SNMP config-copy Set-Requests to CISCO-CONFIG-COPY-MIB OIDs followed by a TFTP transfer - using management-plane telemetry: SNMP packet capture, NetFlow/firewall logs for UDP 161/69 and TCP 4786 (Smart Install), Zeek tftp/ftp logs, SNMP traps, and TACACS+ accounting. Endpoint agents do not run on routers/switches, so detection is network and device-plane, not host logs. Use when hunting router/switch config collection, unauthorized SNMP reads, or config egress to unapproved hosts. Keywords: T1602, SNMP MIB dump, config copy OID, writeNet, TFTP config exfil, Smart Install, CVE-2018-0171, default community string, network device. Do not use for routing/tunnel manipulation that bridges segments - use detecting-network-boundary-bridging.'
domain: cybersecurity
subdomain: network-security
tags:
- network-security
- threat-detection
- collection
- snmp
- network-devices
- config-exfiltration
- tftp
- zeek
- t1602
- router-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.AA-05
- RS.MI-01
mitre_attack:
- T1602
- T1602.001
- T1602.002
---

# Detecting Network Configuration Repository Theft

## When to Use

Use this skill to detect an adversary **collecting network-device configuration
data** (ATT&CK T1602) — dumping the SNMP MIB or exfiltrating a router/switch
running-config — which exposes credentials, routing tables, interface and ACL
details that enable deeper intrusion. The focus is the **management plane**:
unauthorized SNMP reads (especially of config-related OIDs), spoofed SNMP
Set-Requests that trigger a config copy, and config transfers off the device
(TFTP/FTP/SCP). Because EDR agents do not run on routers and switches, detection
relies on **network and device-plane telemetry**, not host logs. Reach for it
when:

- Hunting router/switch config collection or unauthorized SNMP reads.
- A network device sends a config to an unapproved destination.

For routing/tunnel manipulation that bridges segments use
`detecting-network-boundary-bridging`.

## Prerequisites

- **SNMP**: NetFlow/IPFIX + firewall logs for UDP 161/162 from unexpected
  sources; packet capture (Zeek/Suricata) of SNMP GET/GETBULK/SET; SNMP traps to
  SIEM; device SNMP-server logs.
- **Config transfer**: firewall/NetFlow for TFTP (UDP 69), FTP (TCP 21), SCP/SFTP
  (TCP 22) egress from network devices; Zeek `tftp.log`/`ftp.log`/`conn.log`.
- **Device plane**: AAA/TACACS+ accounting and syslog for `copy running-config`,
  `show running-config`, archive/config-replace, and `%SYS-5-CONFIG_I`;
  NETCONF/RESTCONF access logs.
- **Smart Install**: TCP 4786 traffic (abused to pull configs — CVE-2018-0171).
- An **allowlist** of the real NMS/backup servers (RANCID/Oxidized) and their
  scheduled polls/backups.

## Workflow

1. **Baseline legitimate management.** Record the NMS/backup servers, their SNMP
   polling, and nightly config-backup flows (TFTP/SCP to the backup host).
2. **Spoofed SNMP config-copy.** IDS rule for inbound SNMP `SET` (PDU 0xA3)
   targeting `CISCO-CONFIG-COPY-MIB` OID `1.3.6.1.4.1.9.9.96.*` (`ccCopyTable`) or
   `OLD-CISCO-SYS-MIB` `writeNet` `1.3.6.1.4.1.9.2.1.55`, from any source outside
   the SNMP management ACL — this instructs the device to write its config to a
   remote server.
3. **MIB dump (T1602.001).** Flag a single source issuing high-volume SNMP
   GETBULK walks, any SNMP read from a non-allowlisted host, and SNMPv1/v2c with
   default community strings (`public`/`private`).
4. **Config egress (T1602.002).** NetFlow/Zeek rule — a network device as the
   **source** of a TFTP/FTP/SCP flow to a destination that is not an approved
   config-backup server. Correlate the SNMP SET and the subsequent TFTP flow
   within a short window (the SET names the server; the transfer follows).
5. **Device-plane corroboration.** TACACS+ accounting showing `show`/`copy
   running-config` or NETCONF `get-config` from an unusual session, and
   config-change syslog without a change ticket.
6. **Respond** (see *Response*).

## Key Concepts

- **No host agent on the device:** detection is network/device-plane
  (SNMP/flow/syslog/TACACS+), which is why the backup-server allowlist and OID
  focus matter so much.
- **The SET names the thief's server:** a config-copy SET carries the destination
  address — pairing it with the ensuing TFTP flow is the high-confidence chain.
- **Default community strings are the open door:** SNMPv1/v2c with `public`/
  `private` let anyone read the MIB — flag their use outright.
- **Device as flow source is the tell:** routers/switches should only send configs
  to the approved backup host; any other destination is exfil.

## Tools & Systems

Zeek (tftp/ftp/conn logs), Suricata/Snort (SNMP SET IDS rules), NetFlow/IPFIX
collectors, SNMP trap receivers, TACACS+/RADIUS accounting, device syslog,
RANCID/Oxidized (legitimate backup baselines to allowlist), SIEM
(Splunk/Sentinel). OIDs: CISCO-CONFIG-COPY-MIB `1.3.6.1.4.1.9.9.96`,
OLD-CISCO-SYS-MIB `writeNet` `1.3.6.1.4.1.9.2.1.55`.

## Detection Queries

### Suricata -- SNMP SET to a config-copy OID from an unauthorized source

```
alert udp !$SNMP_MGMT any -> $NET_DEVICES 161 ( \
  msg:"SNMP SET to CISCO-CONFIG-COPY-MIB from unauthorized source"; \
  content:"|a3|"; content:"|2b 06 01 04 01 09 09 60|"; \
  sid:1000001; rev:1; )
# 2b 06 01 04 01 09 09 60 = 1.3.6.1.4.1.9.9.96 — verify OID byte-encoding in a lab
```

### Splunk -- network device as source of TFTP egress to a non-backup host

```spl
`netflow` (dest_port=69 OR dest_port=21 OR dest_port=22)
| search src_ip IN ($network_devices$)
| search NOT [ | inputlookup approved_config_backup_servers | fields dest_ip ]
| stats count values(dest_port) by src_ip, dest_ip
| `comment("a router/switch pushing its config to a non-approved host = T1602.002")`
```

### Splunk -- correlate SNMP SET then config transfer

```spl
`snmp_ids` signature="*config-copy*"
| eval setTime=_time, server=dest_from_set
| join server [ search `netflow` dest_port=69 | rename dest_ip as server | eval xferTime=_time ]
| where xferTime>=setTime AND (xferTime-setTime) < 120
| table _time, src_ip, device, server
```

## Common Scenarios

- **Config-copy + TFTP:** an off-ACL host sends an SNMP SET to `ccCopyTable`
  naming its own TFTP server; the router then TFTPs its running-config out — the
  correlation query fires.
- **MIB walk:** a single source GETBULK-walks a switch with `public` community.
- **Smart Install pull:** TCP 4786 to an unpatched switch (CVE-2018-0171).
- **False positive:** RANCID/Oxidized nightly backup to the approved server —
  allowlisted.

## Output Format

```
CONFIG REPOSITORY THEFT DETECTION
  Device:          <router/switch>
  Verdict:         <confirmed | suspected | approved-backup>
  Vector:          <SNMP config-copy SET | MIB dump (GETBULK) | config egress (TFTP/FTP/SCP) | Smart Install 4786>
  Source/dest:     <attacker src> -> device -> <exfil server>
  SNMP:            <version / community> ; OID <ccCopyTable/writeNet if applicable>
  ATT&CK:          T1602(.001/.002)
  Actions taken:   <source blocked | device creds rotated | config audited | SNMPv3 enforced>
```

## Response

- **Contain:** block the offending source at the edge, **rotate all credentials
  present in the exposed config**, and audit the device for config changes.
- **Harden:** move to SNMPv3 `authPriv` and disable SNMPv1/v2c + default community
  strings; apply SNMP views to allowlist MIB objects; restrict management
  protocols with ACLs on an out-of-band network; block UDP 69 (TFTP) and TCP 4786
  (Smart Install) at edge firewalls and disable Smart Install after provisioning;
  use modern password hashing; patch/replace EOL devices (CVE-2018-0171)
  (NIST CSF PR.AA-05).
