---
name: detecting-ics-communication-blocking
description: 'Detects wholesale blocking of ICS communications - serial, Ethernet, or Wi-Fi link takedown, interface disablement, converter bricking, or RF jamming - so command and reporting messages never reach target devices (ATT&CK T1695; LockerGoga NIC disable via netsh example). Uses link-state and carrier-loss traps, bidirectional traffic silence plus ARP and ICMP liveness in Zeek, endpoint detection of netsh and ip-link interface disable via Sysmon and Sigma, Wi-Fi noise-floor and deauth monitoring, and SCADA mass comms-fail plus historian zone-wide BAD quality, correlated in a SIEM with Claroty, Nozomi, or Dragos. Use when a whole OT link or zone goes dark, NICs are disabled, serial carrier is lost, or radios are jammed. Keywords: block communications, link loss, RF jamming, netsh disable interface, bidirectional silence, loss of view, T1695. Do not use for selective dropping of specific messages with the link still up - use detecting-blocked-ot-messages.'
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot
- ics
- block-communications
- link-loss
- rf-jamming
- serial
- ethernet
- wifi
- sysmon
- t1695
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- RS.MI-01
mitre_attack:
- T1695
- T1695.001
- T1695.002
- T1695.003
- T1691
---

# Detecting ICS Communication Blocking

## When to Use

Use this skill to detect **wholesale blocking** of OT communications — jamming,
link takedown, or interface/converter disablement — so that reporting and command
messages never reach target devices, disrupting the process (ATT&CK T1695). This
differs from selective message dropping: here the **medium itself is denied**, by
serial carrier loss (T1695.001), Ethernet interface takedown (T1695.002 — the
ATT&CK example is LockerGoga disabling NICs via `netsh.exe`), or RF/Wi-Fi jamming
(T1695.003). Reach for it when:

- A whole OT link or zone goes dark at once.
- NICs are disabled on an HMI/EWS, or serial carrier is lost on a terminal server.
- Radios are jammed and wireless cells collapse.

For **selective** dropping of specific messages with the link still up, use
`detecting-blocked-ot-messages`.

## Prerequisites

- **Link/carrier-state telemetry:** switch-port link-down and MAC-flap SNMP traps,
  interface up/down syslog, serial carrier-detect / RTS-CTS loss on terminal
  servers, wireless AP/radio RSSI, SNR, and noise-floor readings.
- **Passive network monitoring** (Zeek + ICSNPP) for full-conversation loss, with
  an ARP/ICMP liveness probe to distinguish a blocked medium from a quiet link.
- **Endpoint telemetry on EWS/HMI** (Sysmon/EDR) for interface-disable commands.
- **SCADA/HMI comms-fail feed** and historian zone-wide quality telemetry.
- **Asset/firmware health** for serial-to-Ethernet converters and gateways.
- **Change/maintenance window feed** so planned outages are not flagged.

## Workflow

1. **Link-state watchdog.** Alert on interface-down / carrier-loss traps for OT
   switch ports and terminal servers, **especially clustered in time** —
   simultaneous multi-device loss is the blocking signature.
2. **Bidirectional silence (network).** Per device pair, confirm that **both**
   request and response streams have stopped **and** the host stops answering
   ARP/ICMP. Both directions gone = medium blocked; one-sided loss routes to the
   sibling (T1691) skill.
3. **Endpoint NIC-disable detection.** Process-create for `netsh interface set
   interface ... disabled` / `admin=disabled`, or mass `ip link set ... down` on
   an HMI/EWS — LockerGoga-style self-isolation.
4. **RF jamming.** AP-controller alerts on sustained noise-floor rise, deauth
   floods, or RSSI/SNR collapse across a cell; use spectrum-analyzer telemetry
   where available. Where RF telemetry is absent, fall back to L2 link-state.
5. **Correlate into one incident.** Cluster link-loss + SCADA mass comms-fail +
   historian zone-wide BAD quality into a single "communications blocked" event,
   checked against the maintenance calendar.

## Key Concepts

- **Both directions down + unreachable = medium denied.** One-sided silence with
  a reachable host is a blocked message, not a blocked link.
- **Clustering is the discriminator.** A single port flap is maintenance or a bad
  cable; many devices lost at once is an attack.
- **The strategy is indirect.** Alarms may still appear if an alternate path
  exists; require corroboration (link-state + mass comms-fail) before escalating.
- **Ethernet takedown leaves endpoint evidence;** serial and RF do not — pivot to
  carrier-state and spectrum telemetry for those sub-techniques.
- PLCs rarely run endpoint agents — detection is network + infrastructure traps +
  EWS/HMI host telemetry.

## Tools & Systems

Zeek + CISA/INL ICSNPP parsers, Suricata, Claroty CTD, Nozomi Guardian, Dragos
Platform, SNMP/syslog collectors (LibreNMS, Zabbix) for OT switches and terminal
servers, Sysmon + Sigma + EDR on EWS/HMI, wireless controllers (Cisco, Aruba) and
spectrum analyzers for RF, Splunk OT add-ons, Microsoft Sentinel.

## Detection Queries

### Splunk -- clustered link-down / carrier-loss (blocking event)

```spl
index=ot_syslog ("link-down" OR "carrier lost" OR "line protocol is down")
| bin _time span=30s
| stats dc(host) as hosts values(host) as devices by _time
| where hosts >= N      # simultaneous multi-device loss = blocking, not one flap
| join type=left [ search index=change_windows | eval planned="true" ]
| where isnull(planned)
```

### Zeek -- bidirectional silence plus ARP liveness (concept)

```
# Per device pair: both ICSNPP request and response streams stop AND the host
# no longer answers ARP/ICMP => medium blocked (one-sided = route to T1691).
# Combine conn.log termination + ICSNPP last-seen + an active ARP/ICMP probe.
```

### Sigma -- Ethernet interface disable on EWS/HMI (T1695.002)

```yaml
title: OT Host Network Interface Disabled
logsource: { product: windows, category: process_creation }
detection:
  netsh:
    Image|endswith: '\netsh.exe'
    CommandLine|contains|all: ['interface', 'set', 'interface', 'disable']
  condition: netsh
level: high
# Linux equivalent: monitor auditd execve for 'ip link set * down' / 'ifconfig * down'
```

## Common Scenarios

- **LockerGoga self-isolation:** an HMI runs `netsh ... disable` across adapters
  and drops off the network — endpoint rule + bidirectional silence both fire.
- **Serial converter bricking:** terminal-server carrier lost, outstations behind
  it all go COMM_FAIL together — carrier-loss + historian zone quality fire.
- **RF jamming:** wireless cell noise-floor spikes and RSSI collapses across
  several radios — AP-controller + mass comms-fail fire.
- **False positive:** a scheduled switch firmware upgrade — suppressed by the
  maintenance-window join.

## Output Format

```
ICS COMMUNICATION BLOCKING DETECTION
  Scope:         <single link | zone-wide (<N> devices)>
  Verdict:       <confirmed | suspected | planned-maintenance>
  Medium:        <serial (T1695.001) | ethernet (T1695.002) | wi-fi (T1695.003)>
  Link state:    bidirectional silence: <y/n>  host reachable (ARP/ICMP): <y/n>
  Endpoint:      <netsh/ip-link interface disable on <host> | n/a>
  RF:            <noise-floor rise | deauth flood | RSSI collapse | n/a>
  Corroboration: <SCADA mass comms-fail | historian zone-wide BAD quality>
  ATT&CK:        T1695(.001/.002/.003)
  Actions taken: <out-of-band procedure activated | host re-imaged | gateway reflashed | jammer located>
```

## Response

- **Activate the manual/out-of-band operating procedure and alternate comms path**
  — the SOC must not go blind; treat the affected zone's telemetry as lost and
  confirm field state out-of-band.
- **Ethernet case:** isolate and re-image the host that disabled interfaces;
  restore NIC/firewall configuration.
- **Serial/converter case:** verify and reflash gateway firmware from known-good.
- **RF case:** locate and remove the jammer; fail over to wired/redundant radio.
- **Harden:** redundant/diverse comms paths, network segmentation, restricted
  interface-management rights, and hardwired safety interlocks independent of the
  network.
