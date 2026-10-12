---
name: detecting-network-denial-of-service
description: 'Detects network denial-of-service (MITRE T1498) - volumetric direct floods (SYN/UDP/ICMP/HTTP) and reflection/amplification abuse (DNS, NTP, memcached, SSDP, CLDAP) - using NetFlow/IPFIX/sFlow baselines, Zeek/Suricata, firewall drop logs, and cloud DDoS metrics (AWS Shield, Azure DDoS, Cloudflare). Flags inbound floods on defended assets, outbound floods from compromised internal hosts, and org services abused as amplifiers, and drives the scrubbing/rate-limiting response. Use when investigating availability loss, bandwidth-saturating traffic spikes, or DDoS alerts, or when building volumetric detection. Keywords: DDoS, network denial of service, SYN flood, reflection amplification, NetFlow, UDP flood, amplifier, AWS Shield, T1498. Do not use for host/service resource-exhaustion or crash-based DoS against a single endpoint - use detecting-endpoint-denial-of-service.'
domain: cybersecurity
subdomain: soc-operations
tags:
- soc-operations
- threat-detection
- ddos
- denial-of-service
- netflow
- reflection-amplification
- network-security
- syn-flood
- t1498
- availability
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- RS.MI-01
- PR.IR-04
mitre_attack:
- T1498
- T1498.001
- T1498.002
---

# Detecting Network Denial of Service

## When to Use

Use this skill to detect and respond to **network-layer DoS/DDoS** that exhausts
bandwidth or network infrastructure to deny availability (ATT&CK T1498):
volumetric direct floods (SYN/UDP/ICMP, HTTP floods) and
reflection/amplification abuse (DNS, NTP, memcached, SSDP, CLDAP, CharGen).
Reach for it when:

- Availability drops or border links saturate without a clear cause.
- A DDoS alert fires from a firewall, flow collector, or cloud provider.
- You need to tell apart three cases: an **inbound flood** on a defended asset,
  an **outbound flood from a compromised internal host**, and **your own
  services abused as an amplifier**.

For single-host resource-exhaustion / crash DoS (slow-loris against one app,
OOM), use `detecting-endpoint-denial-of-service`.

## Prerequisites

- **Flow telemetry**: NetFlow / IPFIX / sFlow from border routers and firewalls,
  into a collector (nfdump/nfsen, Elastiflow, ntopng) or SIEM.
- IDS (Suricata/Snort) and/or Zeek `conn.log`/`weird.log`; firewall drop logs;
  load-balancer / reverse-proxy connection and 503 metrics.
- For outbound-source detection: Sysmon Event ID 3 (network connect) + process
  creation on hosts.
- Cloud DDoS metrics where applicable (AWS Shield/CloudWatch, Azure DDoS,
  Cloudflare/Akamai analytics).
- A **traffic baseline** (pps/bps/flows, per asset, by time-of-day).

## Workflow

1. **Baseline normal volume** per defended asset (pps, bps, flows/sec, source-IP
   cardinality) using percentiles/stddev — ship a method, not hard numbers.
2. **Volumetric detection.** Alert when pps/bps to a destination exceed the
   baseline by a tuned factor, or when source-IP cardinality to one victim spikes
   (many sources → one target = DDoS). SYN flood: SYN ≫ SYN-ACK completions.
3. **Reflection/amplification detection.** Flag large UDP responses from
   amplifier ports (53/123/11211/1900/389) to one internal destination **with no
   prior matching request** (spoofed-source reflection) — or your own servers
   emitting amplified responses (you are the reflector).
4. **Outbound-source detection.** On hosts, flag flooding tools (`hping3`,
   `nping`, `t50`) or any process generating high packet volume to many
   destinations (Sysmon EID 3 + process creation).
5. **Classify the tier** — (a) inbound on defended asset, (b) outbound from
   internal host (compromise), (c) assets abused as amplifier — and respond
   accordingly (see *Response*).

## Key Concepts

- **Direct flood (T1498.001)** overwhelms with sheer volume; **reflection/
  amplification (T1498.002)** bounces small spoofed requests off third parties
  for a large response aimed at the victim.
- **Flow over packets:** at DDoS scale, flow records (pps/bps/cardinality) are
  the practical signal; full packet capture does not scale to line-rate floods.
- **Amplifier hygiene matters both ways:** detect being a victim *and* being
  abused as a reflector (open resolver, NTP monlist, exposed memcached).
- **Thresholds are environment-specific** — always tune against the asset's
  baseline; a static number alerts constantly or never.

## Tools & Systems

NetFlow/IPFIX collectors (nfdump/nfsen, Elastiflow, ntopng), Zeek, Suricata,
FastNetMon, AWS Shield + CloudWatch, Azure DDoS Protection, Cloudflare/Akamai,
Arbor/NETSCOUT, Splunk/Elastic over flow data, Sysmon.

## Detection Queries

### Splunk -- volumetric flood over NetFlow (baseline-relative)

```spl
`netflow`
| bin _time span=10s
| stats sum(packets) as pps sum(bytes)*8 as bps dc(src_ip) as src_card by dest_ip, _time
| join dest_ip [| inputlookup asset_baselines]   `# baseline_pps, baseline_bps per asset`
| where pps > (baseline_pps*5) OR src_card > 500
| eval verdict=if(src_card>500,"distributed flood (DDoS)","volume spike")
| table _time, dest_ip, pps, bps, src_card, verdict
```

### Zeek / Suricata -- reflection amplification (concept)

```
# Zeek: large UDP responses from amplifier source ports to one dst with no prior request
event connection_state_remove(c: connection) {
  if (c$id$orig_p in set(53/udp,123/udp,11211/udp,1900/udp,389/udp) &&
      c$resp$size > 10*c$orig$size)
    NOTICE([$note=AmplificationSuspect, $conn=c]);
}
```

### Sigma -- host generating flood traffic (outbound source; tune)

```yaml
title: Network Flooding Tool Execution
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: ['\hping3.exe','\nping.exe','\t50']
  condition: selection
falsepositives: [authorized load/stress testing]
level: high
```

## Common Scenarios

- **Inbound SYN flood** on a public service: pps spikes, SYN≫SYN-ACK, thousands
  of source IPs → engage scrubbing / SYN cookies.
- **DNS/NTP reflection** at a customer IP: large UDP/53 ANY responses with no
  request → upstream filter + BCP38.
- **Compromised host as bot:** internal host runs `hping3` to many dsts →
  isolate host, hunt the compromise.
- **You are the amplifier:** open resolver emits large responses to a spoofed
  victim → lock down the service.

## Output Format

```
NETWORK DOS DETECTION
  Verdict:         <confirmed | suspected>
  Tier:            <inbound-on-asset | outbound-from-host | abused-as-amplifier>
  Victim/target:   <dest ip/asset>
  Vector:          <SYN flood | UDP flood | DNS/NTP/memcached reflection | HTTP flood>
  Peak:            <pps> pps / <bps> bps, source cardinality <n>
  ATT&CK:          T1498(.001/.002)
  Actions taken:   <scrubbing engaged | RTBH | rate-limit | host isolated>
```

## Response

- Engage **upstream scrubbing / ISP RTBH blackhole** and enable cloud DDoS
  protection (AWS Shield Advanced, Azure DDoS, Cloudflare/Akamai).
- Apply **rate limiting, SYN cookies, connection limits** (ATT&CK M1037).
- Deploy **BCP38 / uRPF** ingress filtering against spoofed traffic; disable or
  restrict amplification services (NTP monlist, open resolvers, exposed
  memcached).
- Scale / anycast critical services (NIST CSF PR.IR-04). For the outbound-source
  case, **isolate the compromised host** and investigate.
