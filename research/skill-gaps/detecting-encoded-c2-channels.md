# Detecting Encoded C2 Channels — research notes

- **Proposed slug:** detecting-encoded-c2-channels
- **ATT&CK:** T1132 Data Encoding (tactic: command-and-control) — sub-techniques T1132.001 (Standard Encoding), T1132.002 (Non-Standard Encoding); related: T1071 (Application Layer Protocol), T1001 (Data Obfuscation)
- **Status:** research (not yet a skill)

## Defensive goal
Detect command-and-control traffic where the adversary encodes the data stream (Base64, hex/ASCII, Unicode, MIME, gzip, or custom/modified schemes) to blend with or hide inside otherwise normal-looking protocol traffic. The skill focuses on what a *defender observes* — encoder-process activity paired with anomalous egress, and encoded payload structure in HTTP/DNS content — not on building the channel. Because encodings are legitimate, detection leans on correlation with C2 context rather than string-matching alone.

## Data sources / telemetry
- **Network content:** Zeek `http.log` (uri, user_agent, request/response body size), `files.log`, `dns.log` (long/high-entropy labels), `ssl.log` (JA3/SNI); proxy logs; Suricata payload inspection. Captured HTTP bodies for Base64/MIME block detection.
- **Flow:** conn.log / NetFlow bytes_out:bytes_in ratio, request periodicity.
- **Host:** Windows process creation Security Event ID 4688 / Sysmon 1 — `certutil -encode`/`-decode`, `powershell -enc`/`-EncodedCommand`, `base64`; Sysmon Event ID 3 (network) and 22 (DNS); PowerShell Script Block Logging (Event ID 4104, and module 4103).
- MITRE detection strategy DET0124 (T1132.001): pairs encoder-process activity (`powershell -enc`, `certutil -encode`) with outbound traffic having a high bytes_out:bytes_in ratio or Base64/MIME blocks in HTTP content; telemetry = process creation (4688), Sysmon 3/22, PowerShell logging (4103–4106). (verify IDs on live attack.mitre.org.)

## Detection logic / approach
- **Encoder-process → egress correlation:** alert when a host runs `powershell -enc`/`certutil -encode`/`base64` and, within a short window, opens an outbound connection with a high upload:download ratio to a new/rare destination. Sigma-style:
  ```
  selection_proc: CommandLine|contains: ['-enc ','-encodedcommand','certutil -encode','base64 ']
  # correlate with Sysmon EventID 3 to a non-allowlisted dest shortly after
  ```
- **Encoded content in HTTP/DNS (Zeek/Suricata):** flag HTTP URIs/bodies that are long, high-entropy, and decode cleanly as Base64/hex, or that carry MIME blocks in unusual fields; flag DNS queries with long base32/base64-looking labels and high Shannon entropy. Example posture: compute per-request entropy and Base64-charset ratio; alert above threshold combined with beaconing cadence.
- **Non-standard encoding (T1132.002):** harder — look for payloads that are near-Base64 but fail strict decode (custom alphabet), or fixed-length high-entropy fields in otherwise plaintext protocols; rely on protocol-anomaly + beaconing context rather than decode success.
- **Reduce FPs:** encodings are everywhere (JWTs, cookies, images). Require corroborating C2 signals — beaconing periodicity (RITA/Zeek), rare destination, suspicious JA3/user-agent, process lineage — before alerting. Entropy/decode alone is insufficient.

## Response / mitigation
- Network IPS/TLS inspection at egress (M1031); proxy allowlisting; block/alert on rare-destination high-entropy egress. On detection: decode captured payloads in a sandbox to confirm C2, identify the implant process via Sysmon lineage, isolate host, block infrastructure, and pivot on JA3/SNI/domain IOCs.

## Real tools
Zeek, Suricata, RITA (beacon context), Arkime, Sysmon, CyberChef (analyst decoding), Splunk/KQL, Sigma, Malcolm. (no invented endpoints.)

## Draft frontmatter mappings
- mitre_attack: [T1132, T1132.001, T1132.002, T1071.001, T1001]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, DE.CM-09, RS.MI-01]
- d3fend (optional): D3-NTA (Network Traffic Analysis), D3-OTF (Outbound Traffic Filtering), D3-PMAD (Protocol Metadata Anomaly Detection) — verify current D3FEND IDs
- suggested subdomain: network-security
- nearest existing sibling (for the negative trigger): analyzing-network-covert-channels-in-malware

## Draft description (<=1024 chars)
Detects encoded command-and-control channels — Base64/hex/MIME/gzip and custom-alphabet encodings used to hide C2 in HTTP/DNS traffic — by correlating encoder-process activity (powershell -enc, certutil -encode) with anomalous egress (high bytes-out:bytes-in, high-entropy Base64/MIME content, long DNS labels) and beaconing context, using Zeek, Suricata, Sysmon, and PowerShell script-block logs. Use when hunting for or alerting on C2 that encodes its data stream to evade content inspection. Keywords: data encoding, Base64 C2, certutil -encode, powershell -enc, high entropy egress, MIME C2, T1132. Do not use for reverse-engineering a malware sample's covert channel - use analyzing-network-covert-channels-in-malware; for DNS-tunnel exfil use detecting-dns-exfiltration-with-dns-query-analysis.

## Key references
- https://attack.mitre.org/techniques/T1132/ , /001/ , /002/
- https://attack.mitre.org/detectionstrategies/DET0124 (verify)
- https://redteam.y-security.de/MITRE/techniques/T1132 (mirror)

## Open questions / scope boundaries
- Entropy/Base64 detection is noisy; the skill must center on correlation with C2 context and ship realistic thresholds + allowlist guidance. Non-standard encoding (T1132.002) may only be detectable via anomaly, not decode — set expectations.
- Strictly defensive: observe/decode-to-triage only; no channel construction. Confirm DET0124 data-component/event IDs and whether any public Sigma rule exists (search found none — verify).
