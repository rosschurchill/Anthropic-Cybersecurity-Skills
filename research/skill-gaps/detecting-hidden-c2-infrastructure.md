# Detecting Hidden C2 Infrastructure — research notes

- **Proposed slug:** detecting-hidden-c2-infrastructure
- **ATT&CK:** T1665 Hide Infrastructure (tactic: command-and-control) — no sub-techniques in ATT&CK (verify against v19.2); closely related: T1090 Proxy, T1568 Dynamic Resolution (incl. T1568.001 Fast Flux DNS), T1102 Web Service, T1572 Protocol Tunneling
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversary efforts to hide C2 infrastructure from scanners, researchers and defenders — manipulating DNS and network traffic, fronting C2 behind trusted hosting/CDN/URL-shortener services, filtering out known-scanner IPs, and serving benign content to non-victims while redirecting real targets. The skill focuses on what a *defender observes* from the victim network: anomalous DNS behaviour (short TTLs, suspicious/young WHOIS, fast-flux rotation), responses that differ for scanners vs clients, and egress to trusted-but-unusual fronting hosts. Because the hosting is often legitimate and defenders see only one side, detection leans on DNS/flow anomaly correlation and infrastructure enrichment, not reputation blocklists alone.

## Data sources / telemetry
- **DNS / passive DNS:** Zeek `dns.log`, resolver logs, passive-DNS feeds — short TTLs, a single FQDN resolving to many rotating IPs across diverse ASNs/geographies (single-flux), rotating NS records (double-flux), newly-registered / young-WHOIS domains, high query volume to one domain.
- **Network flow / NSM:** Zeek `conn.log`/`ssl.log`/`http.log`, NetFlow, proxy logs — egress to CDN/cloud/URL-shortener edges carrying C2 (domain fronting: SNI/Host mismatch — TLS SNI says a benign CDN domain while the HTTP Host header or decrypted path differs), unusual JA3/JA3S, SNI that does not match the served certificate.
- **Scanner-evasion signal:** C2 that returns benign/200 content to research scanners but real tasking to victims — observable as response-metadata differences and as the adversary filtering known responder IPs (iptables/nftables/proxy deny or redirect rules on a captured node).
- **Host (when a C2 node or proxy is on a managed host):** auditd execve (DC0032) for `iptables`/`nftables`/proxy config, macOS proxy/DNS setting changes; Windows Security 5156/5157 (filtering-platform connection) for network-connection creation.
- MITRE detection strategy **DET0411** (v1.0, 21 Oct 2025) for T1665 — analytics **AN1148–AN1152**: AN1148 DNS/proxy/user-agent anomalies (short-lived domains, odd WHOIS, filtering of responder IPs — sources Network Connection Creation DC0082 / Win 5156, Domain Registration DC0101 / DNS query logs); AN1149 iptables/nftables/proxy rules denying or redirecting scanners (Process Creation DC0032 / auditd execve, Response Metadata DC0106 / NSM flow); AN1150 macOS proxy/DNS/filter setting changes (Process Creation DC0032 / Unified Logs). AN1151/AN1152 not confirmed. **Verify all IDs against v19.2.**

## Detection logic / approach
- **Fast-flux DNS (T1568.001 overlap, strong hidden-infra signal):** per-domain, count distinct A-record IPs over a window and measure ASN/geo spread and TTL; flag one FQDN resolving to many IPs across unrelated ASNs with very short TTL and/or rotating NS records. (Passive-DNS data-mining approaches report high recall at low FP.) Example posture:
  ```
  # over 24h per queried domain:
  distinct_A_IPs >= K  AND  distinct_ASNs >= M  AND  min_TTL <= 300s
  AND domain_age < 30d  -> candidate hidden/fast-flux C2
  ```
- **Domain fronting / trusted-host abuse (T1090/T1102 overlap):** flag TLS where SNI (a benign CDN/front domain) and the inner HTTP Host / decrypted request differ, or where a high-reputation CDN edge carries beaconing-cadence traffic; enrich with JA3/JA3S rarity. Watch C2 hidden behind URL shorteners / marketing domains that redirect.
- **Scanner-vs-victim divergence (DET0411 AN1149):** on an owned/sinkhole node or via NSM, detect responses that differ by source (benign to scanners, tasking to victims) and firewall/proxy rules that deny or redirect known scanner ranges.
- **Beaconing corroboration:** run periodicity analysis (RITA/Zeek) on candidate destinations — hidden infra still beacons; combine with the DNS/fronting anomaly for confidence.
- **FP reduction:** legitimate CDNs, load balancers and global-traffic-managers also use short TTLs and many IPs — require corroboration (young WHOIS, beaconing cadence, rare JA3, SNI/Host mismatch) before alerting; allowlist known CDN SNIs used by sanctioned apps.

## Response / mitigation
- Containment: block the confirmed infrastructure (domains, IPs, JA3) — but because the adversary rotates/fronts deliberately, pivot on DNS/cert/registration pivots (passive DNS, certificate transparency) to enumerate the full set, and sinkhole the domain where possible. Hardening: egress TLS inspection and proxy allowlisting (M1031); block newly-registered domains and known fronting patterns; monitor and restrict DNS to approved resolvers. Report fronting abuse to the hosting/CDN provider — registrars and providers are often best positioned to disrupt hidden infra.

## Real tools
Zeek, Suricata, RITA (beaconing), passive-DNS providers, WHOIS / newly-registered-domain feeds, certificate-transparency monitoring, JA3/JA3S fingerprinting, proxy/NSM logs, Splunk/Microsoft Sentinel (KQL), Sigma, threat-intel enrichment. (no invented endpoints.)

## Draft frontmatter mappings
- mitre_attack: [T1665, T1568.001, T1090, T1102, T1572]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, RS.MI-01]
- d3fend (optional): D3-NTA (Network Traffic Analysis), D3-DNSTA (DNS Traffic Analysis), D3-OTF (Outbound Traffic Filtering) — verify current D3FEND IDs
- suggested subdomain: network-security
- nearest existing sibling (for the negative trigger): tracking-threat-actor-infrastructure

## Draft description (<=1024 chars)
Detects adversary efforts to hide C2 infrastructure from scanners and defenders — fast-flux DNS, domain fronting, abuse of trusted CDN/URL-shortener hosting, and filtering/redirecting known-scanner IPs — by correlating DNS anomalies (short TTLs, young WHOIS, many IPs across diverse ASNs, rotating NS) with network-flow and TLS signals (SNI/Host mismatch, rare JA3, beaconing) from the victim side. Uses Zeek dns/ssl/conn logs, passive DNS, certificate transparency, NetFlow, and MITRE DET0411 analytics. Use when hunting for C2 deliberately concealed behind fronting or flux infrastructure. Keywords: hide infrastructure, fast flux, domain fronting, SNI Host mismatch, passive DNS, short TTL, young domain, JA3, T1665, T1568.001. Do not use for proactively building/tracking an actor infrastructure graph for CTI - use tracking-threat-actor-infrastructure.

## Key references
- https://attack.mitre.org/techniques/T1665 — confirm sub-technique status (none expected) and detection text for v19.2
- https://attack.mitre.org/detectionstrategies/DET0411 (AN1148–AN1152) — verify against v19.2
- https://attack.mitre.org/techniques/T1568/001/ (Fast Flux DNS, overlap) and T1090 (Proxy)
- Lombardo et al., "Fast Flux detection via data mining on passive DNS traffic" (arXiv:1804.06316)

## Open questions / scope boundaries
- Confirm T1665 has no sub-techniques in v19.2 and that fast flux / domain fronting are mapped to T1568.001 / T1090 respectively — **verify**, do not over-claim mappings. Confirm AN1151/AN1152 content and the DC data-component IDs (DC0082/DC0101/DC0032/DC0106).
- Fast-flux/short-TTL overlaps heavily with legitimate CDN behaviour; author must ship realistic thresholds and a CDN allowlist, and center detection on corroboration.
- Boundary: this skill is *detection from the victim/defender vantage*. It must NOT become proactive CTI infrastructure-graphing (that is tracking-threat-actor-infrastructure) and must NOT teach building fronted/flux C2.
