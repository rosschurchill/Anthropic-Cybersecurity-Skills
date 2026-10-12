# Detecting ICS Communication Blocking — research notes

- **Proposed slug:** detecting-ics-communication-blocking
- **ATT&CK (ICS):** T1695 Block Communications (v19 restructure — verify exact v19.2 wording) — sub-techniques T1695.001 Serial COM, T1695.002 Ethernet, T1695.003 Wi-Fi. Closely related: T1691 Block Operational Technology Message, T0814 Denial of Service, T0816 Device Restart/Shutdown, T0826 Loss of Availability, T0827 Loss of Control.
- **Status:** research (not yet a skill)

## Defensive goal
Detect wholesale blocking of OT communications — jamming, link takedown, or
interface/converter disablement — so that reporting and command messages never
reach their target devices, disrupting the process and causing cyber-physical
impact. Differs from T1691 (selective message drop with the link otherwise up):
here the medium itself is denied, by serial loss, Ethernet interface takedown
(ATT&CK example: LockerGoga disabling NICs via `netsh.exe`), or RF/Wi-Fi jamming.
The skill detects total link loss and drives the loss-of-view/control response.

## Data sources / telemetry
- **Link/carrier state:** switch-port link-down and MAC-flap SNMP traps, interface
  up/down syslog, serial carrier-detect / RTS-CTS loss on terminal servers,
  wireless AP/radio RSSI drop, SNR collapse and noise-floor spikes (RF jamming).
- **Full-conversation loss (both directions):** Zeek `conn.log` connection
  termination / no new flows for a device pair; ICSNPP protocol logs going silent
  simultaneously in *both* directions (vs one-sided drop = T1691).
- **ARP/L2 reachability:** device no longer answering ARP / ICMP while previously
  steady — distinguishes blocked medium from a quiet-but-live link.
- **Endpoint command evidence (Ethernet sub-technique):** EDR/Sysmon on EWS/HMI
  for `netsh interface set interface ... disabled`, `ifconfig/ip link down`,
  firewall rules dropping OT ranges, route/ARP poisoning, driver disable.
- **GOOSE/SV total absence:** publisher MAC gone entirely from the station bus.
- **SCADA/HMI mass comms-fail:** many outstations unreachable at once; historian
  tags across a zone all going COMM_FAIL/BAD quality together.
- **Asset/firmware health:** serial-to-Ethernet converter/gateway offline or
  bricked (the 2015 Ukraine converter precedent, shared with T1691).

## Detection logic / approach
MITRE strategy DET0910 (analytic AN2053): monitor asset alarms and loss of
network communications and watch for missing operational process data — explicitly
an indirect/corroborating strategy (alarms may still appear if an alternate path
exists). Layer concrete signals on top:

- **Link-state watchdog (SIEM).** Alert on interface-down / carrier-loss traps
  for OT switch ports and terminal servers, especially clustered in time:
```
# pseudo-SPL
index=ot_syslog (link-down OR "carrier lost" OR "line protocol is down")
| stats count dc(host) as hosts by _time span=30s
| where hosts >= N    # simultaneous multi-device loss = blocking event
```
- **Bidirectional silence (Zeek).** Per device-pair, both request and response
  streams stop AND the host stops answering ARP/ICMP = medium blocked (one-sided
  = route to T1691). Combine `conn.log` + ICSNPP last-seen + an ARP liveness probe.
- **Endpoint NIC-disable detection (Sysmon/EDR + Sigma).** Process-create for
  `netsh.exe interface set interface * disable` / `admin=disabled`, or mass
  `ip link set * down` on an HMI/EWS — LockerGoga-style self-isolation.
- **RF jamming (Wi-Fi/radio):** AP controller alerts on sustained noise-floor rise,
  deauth floods, or RSSI/SNR collapse across a cell; spectrum-analyzer telemetry
  where available.
- **Correlation:** cluster link-loss + SCADA mass comms-fail + historian
  zone-wide BAD quality into one "communications blocked" incident.

## Response / mitigation
Activate the manual/out-of-band operating procedure and alternate comms path
(ATT&CK M0810) — the SOC must not go blind. Treat affected zone telemetry as
lost; confirm field state out-of-band. For the Ethernet case, isolate and
re-image the host that disabled interfaces and restore NIC/firewall config; for
serial/converter loss verify and reflash gateway firmware. For RF, locate and
remove the jammer, fail over to wired/redundant radio. Harden: redundant/diverse
comms paths, network segmentation (M0930), restrict interface-management rights,
hardwired safety interlocks independent of the network.

## Real tools
Zeek + ICSNPP (INL), Suricata, Claroty CTD, Nozomi Guardian, Dragos Platform,
SNMP/syslog collectors (LibreNMS, Zabbix) for OT switches/terminal servers,
Sysmon + Sigma + EDR on EWS/HMI, wireless controllers (Cisco/Aruba) and
spectrum analyzers for RF, Splunk OT add-ons, Microsoft Sentinel.

## Draft frontmatter mappings
- mitre_attack: [T1695, T1695.001, T1695.002, T1695.003, T1691, T0814]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, RS.MI-01]
- suggested subdomain: ot-ics-security
- nearest existing sibling: detecting-attacks-on-scada-systems

## Draft description (<=1024 chars)
Detects wholesale blocking of ICS communications - serial/Ethernet/Wi-Fi link
takedown, interface disablement, converter bricking, or RF jamming - so command
and reporting messages never reach target devices (ATT&CK T1695; LockerGoga NIC
disable via netsh example). Uses link-state and carrier-loss traps, bidirectional
traffic silence plus ARP liveness in Zeek, endpoint detection of netsh/ip-link
interface disable via Sysmon and Sigma, Wi-Fi noise-floor and deauth monitoring,
and SCADA mass comms-fail plus historian zone-wide BAD quality, correlated in a
SIEM with Claroty, Nozomi, or Dragos. Use when a whole OT link or zone goes dark,
NICs are disabled, or radios are jammed. Keywords: block communications, link
loss, jamming, netsh disable interface, comms failure, loss of view, T1695. Do
not use for selective message drop with the link still up - use
detecting-blocked-ot-messages.

## Key references
- MITRE ATT&CK T1695 Block Communications: https://attack.mitre.org/techniques/T1695/
- T1695.002 Ethernet: https://attack.mitre.org/techniques/T1695/002/
- DET0910 Detection of Block Communications: https://attack.mitre.org/detectionstrategies/DET0910/
- M0810 Out-of-Band Communications Channel: https://attack.mitre.org/mitigations/M0810/
- ICSNPP Zeek parsers (INL/CISA): https://github.com/cisagov/icsnpp
- CISA, Defending OT Operations Against Ongoing Threats: https://www.cisa.gov/

## Open questions / scope boundaries
- Confirm v19.2 name/ID and the three sub-technique split (Serial/Ethernet/Wi-Fi)
  plus whether cellular/satellite get sub-IDs (verify).
- Boundary with T1691 (selective drop) and T0814 Denial of Service (resource
  exhaustion/crash) — this is medium/link denial; route accordingly.
- RF-jamming detection needs spectrum/RSSI telemetry not every site has; ship a
  tiered method (L2 link-state when RF telemetry absent).
- DET0910 is indirect — require corroboration (link-state + mass comms-fail) to
  avoid flagging planned maintenance outages; integrate change/maintenance windows.
