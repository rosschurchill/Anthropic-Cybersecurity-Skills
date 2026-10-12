---
name: detecting-traffic-signaling-and-port-knocking
description: 'Detects traffic signaling backdoors (MITRE T1205) - port-knock sequences and single-packet triggers that silently open a firewall hole or start a listener, and socket filters (raw socket/BPF) that sniff for a magic packet to wake a backdoor - by correlating a burst of failed connections to closed ports with a following firewall-rule change or new listening socket and then a successful connection. Uses Zeek, NetFlow/firewall logs, Sysmon Event ID 1/3, Windows Firewall events 2004/2005/2006, and auditd. These channels are quiet by design, so detection leans on the sequence then activation then connection correlation, not a single packet. Use when hunting dormant or on-demand backdoors activated by a knock. Keywords: traffic signaling, port knocking, magic packet, single-packet authorization, socket filter, BPF, knockd, fwknop, T1205. Do not use for staged loader-to-second-stage C2 - use detecting-multi-stage-c2-channels.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- command-and-control
- port-knocking
- traffic-signaling
- socket-filter
- zeek
- sysmon
- t1205
- backdoor
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
- T1205
- T1205.001
- T1205.002
---

# Detecting Traffic Signaling and Port Knocking

## When to Use

Use this skill to detect an adversary using **traffic signaling** — a specific
sequence or "magic packet" that silently activates hidden access (ATT&CK T1205):
a **port-knock** sequence that opens a firewall hole or starts a dormant
listener, or a **socket filter** (BPF / raw socket) that sniffs for a trigger
packet and wakes a backdoor. These channels are quiet by design, so the
detection is the **sequence → activation → connection** correlation, not any
single packet. Reach for it when:

- Hunting dormant / on-demand backdoors activated by a knock.
- A firewall rule or new listener appears right after a burst of rejected
  connections.

For staged loader-to-second-stage C2 use `detecting-multi-stage-c2-channels`.

## Prerequisites

- **Network**: Zeek `conn.log`/`notice.log` (bursts of short-lived attempts to
  multiple closed/filtered ports from one source); firewall/NetFlow showing
  rejected connections then an accepted one; packet capture for single-packet
  authorization (SPA) datagrams.
- **Host firewall change (the activation)**: Windows Firewall events **2004**
  (rule added), **2005** (modified), **2006** (deleted); Sysmon Event ID 1 for
  `netsh advfirewall`/`New-NetFirewallRule`; Linux `auditd` for iptables/nftables/
  ufw rule adds and `knockd` execution.
- **New listener**: Sysmon Event ID 3; osquery `listening_ports` /
  `process_open_sockets` diffs.
- **Socket filter (T1205.002)**: host telemetry for a process opening a raw socket
  (`AF_PACKET`/`SOCK_RAW`) or attaching a BPF filter (`SO_ATTACH_FILTER`) —
  auditd syscall auditing, eBPF/Falco.
- A SIEM capable of **stateful correlation** and an allowlist of legitimate
  signaling daemons (`knockd`, `fwknop`).

## Workflow

1. **Baseline** legitimate signaling (`knockd`/`fwknop` deployments), known
   sniffers, and vulnerability scanners (which also hit many closed ports).
2. **Knock → activation → connect correlation (core).** Within a window
   (~120 s): (a) source S makes ≥N (e.g. 3) failed/rejected connections to
   distinct closed ports on host H, (b) H logs a firewall rule add/modify (Win
   2004/2005; or auditd iptables/nftables add) **or** a new listening socket
   appears, (c) S or a related host completes a successful connection to H.
   Implement as a Splunk transaction / KQL join keyed on source IP + host.
3. **Zeek network-only variant.** Where host logging is absent, model per-source
   hits to closed/filtered ports and flag ordered sequences to a fixed port set
   followed by a successful session.
4. **SPA.** A lone UDP datagram to a filtered port immediately preceding a new
   allowed session — rely on the subsequent firewall/listener change for
   confidence.
5. **Socket filter (T1205.002).** Alert on a process opening a raw/packet socket
   or attaching a BPF filter that is **not** a known sniffer (tcpdump/Wireshark/
   Zeek/dhclient); correlate with a later inbound trigger and spawned child.
6. **Respond** (see *Response*).

## Key Concepts

- **The activation step is the discriminator:** scanners also hit many closed
  ports; what separates a true knock is the **firewall-rule change or new
  listener** that follows — require it to beat scan noise.
- **Quiet by design:** a knock may be one packet, so a single-event rule can't see
  it; the sequence→activation→connect chain is the signal.
- **Socket filters hide in plain sight:** a BPF/raw-socket sniffer lets malware
  watch a port already owned by another program — host raw-socket telemetry, not
  netstat, reveals it.
- **Stateful correlation required:** this is not a Sigma one-liner; it needs a
  windowed join on source + host.

## Tools & Systems

Zeek, Suricata, NetFlow collectors, Sysmon, Windows Firewall event logging,
`auditd`, osquery (`listening_ports`, `process_open_sockets`), Falco/eBPF, Sigma.
Legitimate signaling daemons to allowlist: `knockd`, `fwknop`, `ipt_pkd`.

## Detection Queries

### Splunk -- knock -> firewall change / new listener -> connect

```spl
`firewall` action=blocked
| bin _time span=120s
| stats dc(dest_port) as closedPorts values(dest_port) as ports min(_time) as knockStart by src_ip, dest_ip
| where closedPorts >= 3
| join dest_ip [ search (`wineventlog` EventCode IN (2004,2005))
                 OR (`sysmon` EventCode=3 (direction=inbound listening=true))
               | eval actTime=_time | rename dest_ip as dest_ip ]
| where actTime>=knockStart AND (actTime-knockStart) < 120
| join dest_ip [ search `firewall` action=allowed | eval connTime=_time ]
| where connTime>=actTime
| table knockStart, src_ip, dest_ip, ports, actTime, connTime
```

### Linux auditd -- raw/packet socket or BPF attach by a non-sniffer

```
-a always,exit -F arch=b64 -S socket -F a0=17 -k raw_socket   # AF_PACKET
-a always,exit -F arch=b64 -S setsockopt -k bpf_attach        # filter on SO_ATTACH_FILTER in analysis
# alert when the executing binary is not tcpdump/wireshark/zeek/dhclient
```

### Zeek -- ordered knock to a fixed port set then success (concept)

```
# Track per-source attempts to closed ports; when the exact ordered set is seen
# followed by an accepted connection to another port, raise a NOTICE
# (adapts the "Don't Knock Bro" approach)
```

## Common Scenarios

- **Port-knock firewall hole:** 3 rejected SYNs to closed ports, then a Windows
  Firewall 2004 rule add, then an accepted RDP — correlation fires.
- **fwknop-style SPA backdoor:** one UDP packet then a new listener and session.
- **BPF sniffer backdoor:** a non-sniffer process attaches a BPF filter and wakes
  on a trigger packet.
- **False positive:** a vuln scanner hitting many closed ports with **no**
  activation step — excluded by requiring the firewall/listener change.

## Output Format

```
TRAFFIC SIGNALING DETECTION
  Host:            <target host>
  Verdict:         <confirmed | suspected | scanner-no-activation>
  Signal:          <port-knock sequence | single-packet (SPA) | socket filter/BPF>
  Knock:           <N closed ports from <src> in <window>s> -> ports <...>
  Activation:      <firewall rule 2004/2005 | new listener :port | iptables add>
  Connection:      <successful session from <src> to :port>
  ATT&CK:          T1205(.001/.002)
  Actions taken:   <host isolated | added rule reverted | listener/process killed | source blocked>
```

## Response

- **Contain:** isolate the host, capture the added firewall rule and the newly
  opened listener, identify and kill the signaling/backdoor process, and revert
  unauthorized firewall rules.
- **Harden:** application control over `netsh`/PowerShell firewall cmdlets; alert
  on **all** runtime firewall-rule changes; restrict raw-socket / `CAP_NET_RAW`
  on Linux; run a host firewall with change monitoring; use network IPS (ATT&CK
  M1031) and ingress/egress allowlisting so an opened port is still unreachable
  from untrusted networks (NIST CSF DE.CM-09).
