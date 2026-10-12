---
name: detecting-network-boundary-bridging
description: 'Detects network boundary bridging (MITRE T1599) - an adversary who controls a perimeter or segmentation device (router/firewall/VPN) reconfiguring NAT, ACLs, routing, or tunnels to bridge trusted and untrusted networks and bypass segmentation, including NAT traversal (T1599.001). Correlates device config-change and NAT/ACL/routing events (Cisco syslog %SYS-5-CONFIG_I, RANCID/Oxidized running-config diffs, AAA/TACACS+ logs) with anomalous cross-trust-boundary flows in NetFlow/Zeek against an allowed-zone matrix. Use when hunting for compromised network devices or unexpected inter-segment traffic. Keywords: network boundary bridging, NAT traversal, router firewall config change, cross-VLAN flow, segmentation bypass, Cisco IOS, GRE tunnel, T1599. Do not use for host-based firewall changes - use detecting-host-firewall-tampering.'
domain: cybersecurity
subdomain: network-security
tags:
- network-security
- threat-detection
- boundary-bridging
- defense-evasion
- nat-traversal
- segmentation
- netflow
- cisco
- t1599
- network-devices
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-03
- PR.IR-01
- PR.AA-05
mitre_attack:
- T1599
- T1599.001
- T1601
- T1542.005
---

# Detecting Network Boundary Bridging

## When to Use

Use this skill to detect when an adversary who has compromised a **perimeter or
internal segmentation device** (router, firewall, VPN concentrator)
reconfigures it to **bridge trusted and untrusted networks** (ATT&CK T1599) —
bypassing routing/ACL restrictions, or (T1599.001) altering NAT so outbound-only
paths become bidirectional. Reach for it when:

- Unexpected traffic appears between segments that policy says must not
  communicate (OT↔IT, DMZ↔internal, guest↔corp).
- A boundary device's running-config changes outside change control.
- You suspect a compromised network device.

For **host-based** firewall changes use `detecting-host-firewall-tampering`; for
endpoint-to-endpoint movement use `detecting-lateral-movement-in-network`. This
skill is **boundary/segmentation devices** only.

## Prerequisites

- **Network flow records** (primary data source): NetFlow/IPFIX/sFlow, Zeek
  `conn.log`, firewall flow logs — with a **subnet→trust-zone lookup** and an
  **allowed-zone-pair matrix** derived from segmentation policy.
- **Device config & management logs**: router/firewall syslog
  (`%SYS-5-CONFIG_I`), AAA/TACACS+/RADIUS accounting, running-config diffs from
  RANCID/Oxidized/NCM, SNMP config-change traps.
- **Device admin access logs**: successful/failed admin logins, privilege-level
  changes, VPN admin sessions.
- Span/tap IDS (Zeek/Suricata) on segment boundaries.

## Workflow

1. **Baseline the allowed zone pairs.** Map subnets to trust zones and record
   which zone-to-zone flows (and ports) are permitted.
2. **Config/NAT change detection.** Alert on modifications to NAT rules, ACLs,
   routing, or tunnel interfaces on a boundary device — compare periodic
   running-config snapshots and alert on `%SYS-5-CONFIG_I`, new `ip nat`
   statements, new GRE/IPIP tunnels, or ACL permit additions.
3. **Anomalous cross-boundary flow.** Alert on flows whose src/dst pair crosses a
   trust boundary not in the allowed matrix, or uses a port not permitted across
   it (new inter-segment pairs are the signal).
4. **Correlate (2)+(3)** within a short window — a config change then anomalous
   cross-boundary flow — especially when preceded by an admin login or
   privilege change on the device from an unusual source.
5. **NAT-traversal specific (T1599.001).** Watch for new static NAT/port-forward
   entries (not in change control) that let an external host reach an
   internal-only service.
6. **Respond** (see *Response*) — revert unauthorized changes and validate the
   device image (bridging often accompanies a tampered image, T1601).

## Key Concepts

- **Multi-event correlation is the method:** a config change alone is noisy
  (admins change devices); a config change **plus** a new cross-boundary flow is
  the high-confidence signal (DET0006 / AN0015).
- **The allowed-zone matrix is the detection engine:** without a subnet→zone map
  and permitted-pair list, "crossing" is undefined. Ingesting segmentation
  policy is the key setup step.
- **Vendors differ:** Cisco `%SYS-5-CONFIG_I` vs Juniper/Palo Alto/Fortinet
  config events — provide per-vendor rules and verify non-Cisco ones.
- **Pairs with image integrity:** a bridged device is often a tampered device —
  validate the running image (T1601).

## Tools & Systems

Zeek, Suricata, NetFlow/IPFIX collectors (nfdump, Elastiflow), Cisco IOS/ASA +
syslog, RANCID / Oxidized, SolarWinds NCM (config diffing), TACACS+/RADIUS
(ISE), Splunk, Microsoft Sentinel.

## Detection Queries

### Splunk -- cross-trust-boundary flow against the allowed matrix

```spl
`netflow`
| lookup zone_map ip AS src_ip OUTPUT zone AS src_zone
| lookup zone_map ip AS dest_ip OUTPUT zone AS dest_zone
| where src_zone != dest_zone
| search NOT [ | inputlookup allowed_zone_pairs | fields src_zone, dest_zone ]
| stats count values(dest_port) as ports by src_ip, dest_ip, src_zone, dest_zone
| `comment("flows pairing two zones not in the allowed matrix = segmentation bypass")`
```

### Splunk -- boundary-device config change (Cisco syslog)

```spl
`network_syslog` (mnemonic="CONFIG_I" OR message="*%SYS-5-CONFIG_I*"
    OR message="*ip nat *" OR message="*interface Tunnel*")
| stats values(message) as changes min(_time) as t by host, user, src_ip
| `comment("correlate with a cross-boundary flow within the hour")`
```

### Config-diff (concept, RANCID/Oxidized)

```bash
# Alert on any NAT/ACL/route/tunnel delta from the known-good snapshot
diff known-good/edge-fw.cfg current/edge-fw.cfg \
  | grep -Ei '^[<>].*(ip nat|access-list|route |interface Tunnel|permit)' \
  && echo "ALERT: boundary-device policy drift on edge-fw"
```

## Common Scenarios

- **NAT traversal:** attacker adds a static port-forward so an external host
  reaches an internal DB — new `ip nat` entry + inbound flow to an internal-only
  service.
- **ACL loosening:** a permit rule is added bridging DMZ↔internal, then east-west
  flows appear across the boundary.
- **Rogue tunnel:** a new GRE tunnel interface bridges segments — config diff +
  tunnel flows.
- **False positive:** an approved firewall change in a maintenance window by the
  network team — suppressed by change-control correlation.

## Output Format

```
BOUNDARY BRIDGING DETECTION
  Device:          <router/firewall/vpn>
  Verdict:         <confirmed | suspected | approved-change>
  Config change:   <new NAT | ACL permit | route | tunnel> by <user> from <src>
  Flow anomaly:    <src_zone> -> <dest_zone> on port <n> (not in allowed matrix)
  Window:          config <t0> -> flow <t1>
  ATT&CK:          T1599(.001)[, T1601, T1542.005]
  Actions taken:   <config reverted | device rebuilt from trusted image | flows hunted>
```

## Response

- Treat boundary devices as **crown jewels**: config-change control with
  out-of-band approval, immutable/externalized config backups (RANCID/Oxidized),
  and alerting on any drift.
- Enforce **MFA admin auth**, a dedicated management VLAN/jump host, device
  credential rotation, and AAA-log monitoring (NIST CSF PR.AA-05).
- **Validate device image integrity** (pairs with T1601 detection) — bridging
  often accompanies a tampered image.
- **Respond:** compare running vs known-good config, revert unauthorized
  NAT/ACL/route/tunnel changes, rebuild from a trusted image, and hunt the flows
  that used the bridge.
