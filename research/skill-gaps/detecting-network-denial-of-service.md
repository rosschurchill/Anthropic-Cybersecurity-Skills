# Detecting Network Denial of Service — research notes

- **Proposed slug:** detecting-network-denial-of-service
- **ATT&CK:** T1498 Network Denial of Service (tactic: impact) — sub-techniques T1498.001 Direct Network Flood and T1498.002 Reflection Amplification
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to network-layer DoS/DDoS that exhausts bandwidth or network
infrastructure to deny availability — volumetric direct floods (SYN/UDP/ICMP,
HTTP floods) and reflection/amplification abuse (DNS, NTP, memcached, SSDP,
CLDAP, CharGen). The skill detects both inbound floods against assets the org
defends and, importantly, outbound participation (a compromised host acting as
a flood source or reflector), and drives the mitigation/scrubbing response.

## Data sources / telemetry
- **Flow records** — NetFlow / IPFIX / sFlow from border routers and firewalls:
  packets-per-second (pps), bits-per-second (bps), flows-per-second, source-IP
  cardinality, dst-port concentration, SYN-without-ACK ratios.
- **Network traffic content/flow (DS0029)** — IDS (Suricata/Snort), Zeek
  `conn.log`/`weird.log`, firewall drop/deny logs, load-balancer and reverse-
  proxy metrics (connection rate, 503/connection-timeout rates).
- **Reflection-specific** — spikes in responses from amplification services
  (UDP/53 DNS ANY, UDP/123 NTP monlist, UDP/11211 memcached, UDP/1900 SSDP,
  UDP/389 CLDAP) toward a single spoofed victim; source-port = amplifier port.
- **Host/process (outbound source detection)** — Sysmon EID 3 (network connect)
  / process creation showing a tool (`hping3`, `nping`, `hperf`, `t50`,
  LOIC/HOIC-style) generating high packet volume to many dsts.
- **ISP/CDN/DDoS-provider telemetry** — AWS Shield/CloudWatch DDoS metrics,
  Cloudflare/Akamai attack analytics, Azure DDoS Protection metrics.

## Detection logic / approach
MITRE detection strategy DET0518: AN1434 flags an executable/script generating
large outbound traffic toward remote hosts or known amplification ports;
AN1435 flags flooding tools (`hping3`, `nping`) sending high packet volume
across many ports/IPs (Sysmon network-connection + process-creation, tunable
thresholds for connections/sec and destination diversity).

Volumetric (flow-based) detection — baseline + threshold/anomaly:
```
# pseudo-SPL over NetFlow index
| stats sum(packets) as pps sum(bytes) as bps dc(src_ip) as src_card by dest_ip, _time span=10s
| where pps > baseline_pps*5 OR src_card > N   # many sources -> one victim = DDoS
```
Reflection/amplification signature (Zeek/Suricata spirit): high ratio of large
UDP responses from port 53/123/11211/1900/389 to one internal dst with no prior
matching request (spoofed-source reflection), or your own servers emitting
amplified responses (you are the reflector). SYN flood: SYN >> SYN-ACK
completion. Alert tiers: (a) inbound flood on defended asset, (b) outbound flood
from internal host (compromise), (c) org assets abused as amplifier.

## Response / mitigation
Engage upstream scrubbing / ISP blackhole/RTBH, enable cloud DDoS protection
(AWS Shield Advanced, Azure DDoS, Cloudflare/Akamai) and rate limiting /
SYN cookies / connection limits (M1037 Filter Network Traffic). Block spoofed
traffic with BCP38/uRPF ingress filtering; disable/limit amplification services
(NTP monlist, open DNS resolvers, exposed memcached). Scale/anycast critical
services. For outbound-source case, isolate the compromised host.

## Real tools
NetFlow/IPFIX collectors (nfdump/nfsen, Elastiflow, ntopng), Zeek, Suricata,
FastNetMon (DDoS detection), AWS Shield + CloudWatch, Azure DDoS Protection,
Cloudflare/Akamai, Arbor/NETSCOUT, Splunk/Elastic over flow data, Sysmon.

## Draft frontmatter mappings
- mitre_attack: [T1498, T1498.001, T1498.002]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, RS.MI-01, PR.IR-04]
- d3fend (optional): D3-NTA (Network Traffic Analysis), D3-ITF (Inbound Traffic Filtering), D3-OTF (Outbound Traffic Filtering)
- suggested subdomain: soc-operations
- nearest existing sibling (for the negative trigger): detecting-endpoint-denial-of-service

## Draft description (<=1024 chars)
Detects network denial-of-service — volumetric direct floods (SYN/UDP/ICMP/HTTP)
and reflection/amplification abuse (DNS, NTP, memcached, SSDP, CLDAP) — using
NetFlow/IPFIX/sFlow baselines, Zeek/Suricata, firewall drop logs, and cloud
DDoS metrics (AWS Shield, Azure DDoS, Cloudflare). Flags inbound floods on
defended assets, outbound floods from compromised internal hosts, and org
services abused as amplifiers (ATT&CK T1498). Drives scrubbing/rate-limiting
response. Use when investigating availability loss, traffic spikes, or DDoS
alerts, or when building volumetric detection. Keywords: DDoS, network denial
of service, SYN flood, reflection amplification, NetFlow, amplification, UDP
flood, T1498. Do not use for host/service resource-exhaustion or crash-based
DoS against a single endpoint — use detecting-endpoint-denial-of-service.

## Key references
- MITRE ATT&CK T1498 + DET0518: https://attack.mitre.org/techniques/T1498/
- CISA DDoS guidance: https://www.cisa.gov/
- AWS Shield / DDoS best practices whitepaper: https://docs.aws.amazon.com/
- Azure DDoS Protection: https://learn.microsoft.com/
- FastNetMon / NetFlow DDoS detection docs: https://fastnetmon.com/

## Open questions / scope boundaries
- Threshold/baseline strategy is environment-specific — ship a method
  (stddev/percentile over flow) rather than hard numbers; note as "tune".
- Decide how much cloud-managed-DDoS (where the provider detects) vs
  self-detected on-prem flow analysis to cover.
- Must NOT include flood-generation procedures beyond the tool *names* needed
  to recognize outbound/source activity. Keep clearly separate from T1499.
