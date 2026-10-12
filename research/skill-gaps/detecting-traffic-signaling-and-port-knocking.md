# Detecting Traffic Signaling and Port Knocking — research notes

- **Proposed slug:** detecting-traffic-signaling-and-port-knocking
- **ATT&CK:** T1205 Traffic Signaling (tactic: command-and-control; also persistence/defense-evasion in some mappings) — sub-techniques T1205.001 Port Knocking, T1205.002 Socket Filters
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary using traffic signaling — a specific sequence or "magic packet" that silently activates hidden access: a port-knock sequence that opens a firewall hole or starts a dormant listener, or a socket filter (BPF/raw socket) that sniffs for a trigger packet and wakes a backdoor. The skill focuses on what a *defender observes*: the knock pattern in network flow data, the firewall-rule change or new listening socket that follows, and host-side signs of a process installing a packet sniffer / raw socket to watch for triggers. These channels are quiet by design, so detection leans on the *sequence → activation → connection* correlation rather than any single packet.

## Data sources / telemetry
- **Network:** Zeek `conn.log` (bursts of short-lived attempts to multiple closed/filtered ports from one source — the knock), `notice.log`; firewall/NetFlow logs showing rejected connections to several ports followed by an accepted connection on another; packet capture for single-packet-authorization (SPA) UDP datagrams.
- **Host firewall change (the activation):** Windows Firewall event logs **2004** (rule added), **2005** (rule modified), **2006** (rule deleted); Sysmon Event ID 1 for `netsh advfirewall` / `New-NetFirewallRule`; Linux auditd for `iptables`/`nftables`/`ufw` rule additions and `knockd` execution.
- **New listener:** Sysmon Event ID 3 (network connection) / `netstat`-style socket inventory showing a new listening port appearing shortly after the knock; osquery `listening_ports` / `process_open_sockets` diffs.
- **Socket filter (T1205.002):** host telemetry for a process opening a raw socket (`AF_PACKET`/`SOCK_RAW`) or attaching a BPF filter (`setsockopt SO_ATTACH_FILTER`, `libpcap`) — auditd syscall auditing, eBPF/Falco; this lets malware watch ports already owned by another program.
- MITRE detection strategy **DET0524** (v1.0, Oct 2025): analytic **AN1448** = a remote host's short run of failed connections to closed ports, then within a window a firewall-rule change or a new listening socket, then a successful connection. Log sources: Sysmon EventCode 1 and 3 (and 22 DNS in a later rev), Windows Firewall events 2004/2005/2006. Tunable params: correlation window (~120 s), minimum distinct closed ports (~3); watched binaries `netsh.exe`, `powershell.exe`, packet-capture tools. **Verify IDs against v19.2.**

## Detection logic / approach
- **Knock → activation → connect (core DET0524 / AN1448 logic):**
  ```
  1) Source S makes >=N (e.g. 3) failed/rejected connections to distinct closed ports on host H
  2) within W seconds (e.g. 120) H logs a firewall rule add/modify (Win 2004/2005; or
     auditd iptables/nftables add) OR a new listening socket appears
  3) S (or a related host) then completes a successful connection to H
  -> alert: probable port-knock activation
  ```
  Implement as a stateful SIEM correlation (Splunk transaction / KQL join) keyed on source IP + host, not a single-event rule.
- **Zeek network-only variant (no host logging):** model per-source hits to closed/filtered ports; flag ordered sequences to a fixed port set followed by a successful session — adapts the "Don't Knock Bro" Zeek approach.
- **SPA detection:** a lone UDP datagram to a filtered port immediately preceding a new allowed session (e.g. `ipt_pkd`/`fwknop` single-packet authorization) — the knock is one packet, so rely on the subsequent firewall/listener change for confidence.
- **Socket filter (T1205.002):** alert on a process that opens a raw/packet socket or attaches a BPF filter and is not a known sniffer (tcpdump/Wireshark/Zeek/dhclient); correlate with a later inbound trigger and spawned shell/child.
- **FP reduction:** allowlist legitimate `knockd`/`fwknop` deployments, vulnerability scanners (they also hit many closed ports — distinguish by the *activation* step), and known sniffers. The firewall-change / new-listener step is what separates a true knock from ordinary scan noise.

## Response / mitigation
- Containment: isolate the host, capture the firewall rule that was added and the newly-opened listener, identify and kill the signaling/backdoor process, revert unauthorized firewall rules. Hardening: application control over `netsh`/PowerShell firewall cmdlets; alert on all runtime firewall-rule changes; restrict raw-socket / `CAP_NET_RAW` capability on Linux; host-based firewall with change monitoring; network IPS (M1031) and egress/ingress allowlisting so an opened port is still unreachable from untrusted networks.

## Real tools
Zeek, Suricata, NetFlow collectors, Sysmon, Windows Firewall event logging, auditd, osquery (`listening_ports`, `process_open_sockets`), Falco/eBPF, Sigma (correlation rules). Legitimate signaling daemons to baseline/allowlist: `knockd`, `fwknop`, `ipt_pkd`. (no invented endpoints.)

## Draft frontmatter mappings
- mitre_attack: [T1205, T1205.001, T1205.002]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, PR.PS-01, RS.MI-01]
- d3fend (optional): D3-NTA (Network Traffic Analysis), D3-OTF/D3-ITF (Outbound/Inbound Traffic Filtering), D3-PA (Process Analysis) — verify current D3FEND IDs
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): detecting-multi-stage-c2-channels

## Draft description (<=1024 chars)
Detects traffic signaling backdoors — port-knock sequences and single-packet triggers that silently open a firewall hole or start a listener, and socket filters (raw socket/BPF) that sniff for a magic packet to wake a backdoor — by correlating a burst of failed connections to closed ports with a following firewall-rule change or new listening socket and a successful connection (MITRE DET0524/AN1448). Uses Zeek, NetFlow/firewall logs, Sysmon EID 1/3, Windows Firewall events 2004/2005/2006, and auditd. Use when hunting for dormant/on-demand backdoors activated by a knock. Keywords: traffic signaling, port knocking, magic packet, SPA, socket filter, BPF, knockd, fwknop, T1205. Do not use for staged loader-to-second-stage C2 - use detecting-multi-stage-c2-channels.

## Key references
- https://attack.mitre.org/techniques/T1205/ , /001/ , /002/
- https://attack.mitre.org/detectionstrategies/DET0524 (AN1448) — verify against v19.2
- "Don't Knock Bro" — SANS GIAC GCIH paper on Zeek-based port-knock detection (https://www.giac.org/paper/gcih/20059/knock-bro/116990)
- fwknop / ipt_pkd single-packet-authorization documentation (legitimate baseline)

## Open questions / scope boundaries
- Needs stateful cross-source/host correlation, not a single Sigma match; author must set the window, the minimum distinct-closed-ports threshold, and the scanner-vs-knock discriminator (the activation step). No public Sigma rule confirmed — **verify / may need to author one**.
- Confirm T1205's canonical tactic set for v19.2 (C2 vs persistence/defense-evasion) and the DET0524 analytic IDs — **verify**.
- Strictly defensive: observe the signal and its activation only; no instructions for building or sending a knock. Must NOT cover multi-stage C2 handoff (sibling) or generic beaconing.
