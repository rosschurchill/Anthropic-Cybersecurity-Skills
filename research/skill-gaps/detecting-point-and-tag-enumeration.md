# Detecting Point & Tag Enumeration — research notes

- **Proposed slug:** detecting-point-and-tag-enumeration
- **ATT&CK (ICS):** T0861 Point & Tag Identification (tactic: Collection; v1.1, last modified 2025-04-16). Closely related: T0888 Remote System Information Discovery, T0846 Remote System Discovery, T0887 Wireless Sniffing, T0801 Monitor Process State.
- **Status:** research (not yet a skill)

## Defensive goal
Detect reconnaissance in which an adversary enumerates the points and tags that
operators use to represent process data — inputs, outputs, memory locations and
their human-readable identifiers — to map I/O to physical control functions and
pick targets for a later operation. ATT&CK ties this to Backdoor.Oldrea
(enumerates OPC tags) and INCONTROLLER/PIPEDREAM (reads OPC UA structures). The
skill flags abnormal browse/read enumeration against OPC/historian/PLC tag
namespaces while tolerating the identical-looking legitimate engineering pattern.

## Data sources / telemetry
- **OPC UA:** Browse / BrowseNext address-space walks, TranslateBrowsePathsToNodeIds,
  bulk Read of NodeId attributes, GetEndpoints/CreateSession from an unexpected
  client — captured by Zeek `icsnpp-opcua-binary` or OPC UA server audit logs.
- **OPC Classic / DA (Backdoor.Oldrea pattern):** OPCEnum / `IOPCBrowseServerAddressSpace`
  tag browsing; DCOM activity to the OPC server from a non-EWS host.
- **Modbus:** sweeping Read Holding/Input Registers (FC 3/4) and Read Coils (FC 1/2)
  across wide/sequential address ranges = map-the-register-space behaviour.
- **DNP3:** class-0 integrity poll / wide object-range READ from a non-master.
- **EtherNet/IP + CIP:** Get_Attributes_All, List_Identity, symbolic-tag reads and
  tag-list uploads (Logix program/tag browsing).
- **S7comm / S7comm-plus:** SZL/block-list reads, read-var sweeps across DB ranges.
- **Historian:** bulk tag-list queries / point-configuration reads (PI AF/PI Points,
  AVEVA) from an unexpected account or at an unusual hour.
- **Asset baseline (Claroty/Nozomi/Dragos):** which client normally browses which
  server; a *new* asset issuing browse/enumeration functions is the key signal.

## Detection logic / approach
MITRE strategy DET0788: monitor ICS protocols for unusual reads of point/tag data
— new assets using those functions, or shifts in read volume/timing vs baseline.
Enumeration looks like legitimate engineering, so the discriminators are
**source (new/unauthorized client)**, **breadth (wide/sequential sweep)**, and
**timing (off-hours, burst)** — not the operation itself.

- **New-client browse (Zeek + ICSNPP).** Alert when an OPC UA Browse or a Modbus
  FC3 sweep originates from a host not in the known-client set for that server:
```
# Zeek (icsnpp-opcua-binary) — browse from unknown client
event opcua_browse(c: connection, ...) {
    if ( c$id$orig_h !in KNOWN_OPCUA_CLIENTS[c$id$resp_h] )
        NOTICE([$note=OPCUA::Unexpected_Browse, $conn=c]);
}
```
- **Sweep heuristic (Suricata/SIEM).** Count distinct register addresses / node
  IDs read per source per minute; a single source reading a wide, mostly
  sequential range far above its baseline cardinality = enumeration. Suricata
  Modbus keyword / ET SCADA rules flag FC3/FC4 from outside `$SCADA_MASTERS`.
- **SIEM analytics (Splunk/Sentinel).** `stats dc(tag) dc(node_id) by src_ip,
  _time span=1m`; alert on new src + distinct-count spike; enrich with asset
  baseline and work-order/maintenance calendar to suppress scheduled engineering.
- **OPC UA audit events:** server-side audit of CreateSession + Browse from
  unknown application URI / cert = recon with provenance.

## Response / mitigation
Investigate the enumerating host (likely a staging foothold before an operation);
isolate if unauthorized. Enforce authorization on point/tag data (ATT&CK M0800),
field-controller access management (M0801), and network allowlists (M0807) so
only engineering stations browse OPC/PLC namespaces. Require OPC UA with
certificate-based auth and signed+encrypted channels (reject anonymous/None).
Segment the OPC/historian servers into their own conduit (IEC 62443). Treat the
detection as early-warning — raise monitoring on the implicated assets.

## Real tools
Zeek + ICSNPP (INL, incl. `icsnpp-opcua-binary`, `icsnpp-modbus`, `icsnpp-enip`,
`icsnpp-s7comm`), Suricata (Emerging Threats SCADA, Digital Bond Quickdraw),
Claroty CTD, Nozomi Guardian, Dragos Platform (baseline + recon analytics),
OPC UA server audit logs, Splunk OT add-ons, Microsoft Sentinel, Wireshark.

## Draft frontmatter mappings
- mitre_attack: [T0861, T0888, T0846]
- nist_csf: [ID.AM-03, PR.AA-05, DE.CM-01, DE.AE-02, DE.AE-03]
- suggested subdomain: ot-ics-security
- nearest existing sibling: performing-ics-asset-discovery-with-claroty

## Draft description (<=1024 chars)
Detects reconnaissance that enumerates ICS points and tags - OPC UA and OPC
Classic browse/read walks, Modbus register sweeps, DNP3 class-0 polls, EtherNet/IP
CIP tag-list uploads, S7comm block reads, and historian tag-list queries - used
to map I/O to physical functions before an operation (ATT&CK T0861; Backdoor.Oldrea
and INCONTROLLER/PIPEDREAM read OPC tags). Discriminates hostile enumeration from
legitimate engineering by source (new/unauthorized client), breadth (wide
sequential sweep), and timing, using Zeek ICSNPP, Suricata SCADA rules, OPC UA
audit logs, SIEM distinct-count analytics, and Claroty, Nozomi, or Dragos
baselines. Use when an unexpected host browses OPC namespaces, a register sweep
appears, or you are building OT recon detection. Keywords: point and tag
identification, OPC UA browse, tag enumeration, Modbus register sweep, ICS recon,
T0861. Do not use for asset inventory/host discovery - use
performing-ics-asset-discovery-with-claroty.

## Key references
- MITRE ATT&CK T0861 Point & Tag Identification: https://attack.mitre.org/techniques/T0861/
- DET0788 Detection of Point & Tag Identification: https://attack.mitre.org/detectionstrategies/DET0788/
- M0800 Authorization Enforcement: https://attack.mitre.org/mitigations/M0800/
- ICSNPP Zeek parsers incl. OPC UA (INL/CISA): https://github.com/cisagov/icsnpp
- Dragos, PIPEDREAM / INCONTROLLER analysis: https://www.dragos.com/
- CISA advisory AA22-103A (APT tools incl. PIPEDREAM): https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-103a

## Open questions / scope boundaries
- The false-positive problem is central: browse/read is normal engineering.
  Ship a baseline-plus-maintenance-window method; threshold is tune-per-site.
- Boundary with T0846/T0888 (host/system discovery) and with the existing asset-
  discovery skill, which is a defender capability, not attacker detection.
- OPC UA audit-log availability varies by server/vendor; provide a passive-only
  fallback path (Zeek) when audit logs are absent.
- Verify current procedure-example attributions (Oldrea, INCONTROLLER) against
  the live T0861 page.
