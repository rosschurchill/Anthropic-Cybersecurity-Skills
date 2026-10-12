# Detecting Network Boundary Bridging — research notes

- **Proposed slug:** detecting-network-boundary-bridging
- **ATT&CK:** T1599 Network Boundary Bridging (tactic: defense-evasion). Sub-technique: **T1599.001 Network Address Translation Traversal**. Related: T1601 Modify System Image, T1542.005 TFTP Boot, T1556 (device cred modification), T1200 Hardware Additions.
- **Status:** research (not yet a skill)

## Defensive goal
Detect when an adversary who has compromised a perimeter or internal segmentation device (router, firewall, VPN concentrator) reconfigures it to bridge trusted and untrusted networks — bypassing routing/ACL restrictions, or (T1599.001) altering NAT so outbound-only paths become bidirectional. The skill surfaces unexpected cross-boundary flows and the device-config/NAT changes that enable them. MITRE detection strategy: **DET0006** (analytic AN0015).

## Data sources / telemetry
- **Network flow records (NSM:Flow / DC0078 Network Traffic Flow):** NetFlow/IPFIX/sFlow, Zeek `conn.log`, firewall flow logs — the primary data source. Watch for flows between segments that policy says must not communicate, and flows on prohibited ports.
- **Network device configuration & management logs:** router/firewall syslog, AAA/TACACS+/RADIUS accounting, config-change events (`%SYS-5-CONFIG_I` on Cisco IOS), running-config diffs from RANCID/Oxidized/NCM, SNMP traps on config change.
- **Administrative access to devices:** device auth logs (successful/failed admin logins, privilege-level changes, line vty access), VPN admin sessions.
- **NAT/ACL/routing state:** before/after NAT translation tables, ACL hit counts, routing-table changes, GRE/IPIP/other tunnel interface creation.
- **Span/tap IDS:** Zeek, Suricata on segment boundaries to see east-west traffic that should not cross.

## Detection logic / approach
Per DET0006 / AN0015, bridging shows up as "network devices permitting traffic that conflicts with segmentation or access policy." Multi-event correlation is the method — a config change on a boundary device followed by anomalous flows:
1. **Config/NAT change** — alert on any modification to NAT rules, ACLs, or routing on a boundary device (compare periodic running-config snapshots; alert on `%SYS-5-CONFIG_I`, new `ip nat` statements, new tunnel interfaces, ACL permit additions).
2. **Anomalous cross-boundary flow** — Zeek/NetFlow analytic: flows whose src/dst pair crosses a defined trust boundary (e.g. OT↔IT, DMZ↔internal, guest↔corp) or uses a port not allowed across it. Baseline normal inter-VLAN/inter-segment pairs and alert on new ones.
3. **Correlate (1)+(2)** within a short window, especially when preceded by an admin login/privilege change on the device from an unusual source. Simultaneous ingress/egress anomalies and abrupt ACL/firewall rule changes are the AN0015 indicators.

Illustrative Zeek/SPL-style logic for cross-boundary flow (conceptual):
```
# define trust zones by subnet; alert when a flow pairs two zones not in the allowed matrix
index=netflow | lookup zone src_ip OUTPUT src_zone | lookup zone dest_ip OUTPUT dest_zone
| where src_zone!=dest_zone AND NOT [allowed_zone_pairs]
| stats count values(dest_port) by src_ip dest_ip src_zone dest_zone
```
NAT-traversal (T1599.001) specific: watch for a device translating addresses so an external host reaches an internal-only service, or new static NAT/port-forward entries not in change control.

## Response / mitigation
- Treat boundary devices as crown jewels: config-change control with out-of-band approval, immutable/externalized config backups (RANCID/Oxidized), and alerting on any drift.
- Enforce multi-factor admin auth, restrict management-plane access (dedicated mgmt VLAN/jump host), rotate device credentials, and monitor AAA logs.
- Validate device image integrity (pairs with T1601 Modify System Image detection) — bridging often accompanies a tampered image.
- Response: compare running vs. known-good config, revert unauthorized NAT/ACL/route/tunnel changes, rebuild the device from trusted image, hunt for the flows that used the bridge.

## Real tools
Zeek, Suricata, NetFlow/IPFIX collectors (nfdump, Elastiflow), Cisco IOS/ASA + syslog, RANCID / Oxidized, SolarWinds NCM (config diffing), TACACS+/RADIUS (ISE), Splunk, Microsoft Sentinel, CISA guidance on network device integrity.

## Draft frontmatter mappings
- mitre_attack: [T1599, T1599.001, T1601, T1542.005]
- nist_csf: [DE.CM-01, DE.CM-07, PR.IR-01, PR.AA-05, DE.AE-03]
- d3fend (optional): D3-NTA (Network Traffic Analysis), D3-ISVA (Inbound Session Volume Analysis), D3-NTF — verify exact ids
- suggested subdomain: network-security
- nearest existing sibling (for the negative trigger): detecting-lateral-movement-in-network

## Draft description (<=1024 chars)
Detects network boundary bridging — an adversary who controls a perimeter or segmentation device (router/firewall/VPN) reconfiguring NAT, ACLs, routing, or tunnels to bridge trusted and untrusted networks and bypass segmentation (including NAT traversal, T1599.001). Correlates device config-change and NAT/ACL/routing events (syslog %SYS-5-CONFIG_I, RANCID/Oxidized diffs, AAA logs) with anomalous cross-trust-boundary flows in NetFlow/Zeek against an allowed-zone matrix. Use when hunting for compromised network devices or unexpected inter-segment traffic. Keywords: network boundary bridging, NAT traversal, router/firewall config change, cross-VLAN flow, segmentation bypass, Cisco IOS, T1599, T1599.001. Do not use for host-based firewall changes (use detecting-host-firewall-tampering) or endpoint-to-endpoint lateral movement (use detecting-lateral-movement-in-network).

## Key references
- https://attack.mitre.org/techniques/T1599/
- https://attack.mitre.org/techniques/T1599/001/
- https://attack.mitre.org/detectionstrategies/DET0006
- https://mitre.ptsecurity.com/en-US/T1599
- https://redteam.y-security.de/MITRE/detectionstrategies/DET0006/

## Open questions / scope boundaries
- The allowed trust-zone matrix is environment-specific; the author must decide how the skill ingests segmentation policy (subnet→zone lookup) to compute "crossing" flows.
- Vendor config-event IDs differ (Cisco vs. Juniper vs. Palo Alto vs. Fortinet) — provide per-vendor examples and mark non-Cisco ones "verify."
- Must NOT cover host firewall tampering (T1686) or generic host-to-host lateral movement — this is boundary/segmentation devices only. Pairs with but does not duplicate a Modify System Image (T1601) skill.
