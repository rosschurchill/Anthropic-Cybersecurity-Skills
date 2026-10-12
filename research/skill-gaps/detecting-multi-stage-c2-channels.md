# Detecting Multi-Stage C2 Channels — research notes

- **Proposed slug:** detecting-multi-stage-c2-channels
- **ATT&CK:** T1104 Multi-Stage Channels (tactic: command-and-control) — related: T1105 (Ingress Tool Transfer), T1071 (Application Layer Protocol), T1568 (Dynamic Resolution), T1008 (Fallback Channels)
- **Status:** research (not yet a skill)

## Defensive goal
Detect command-and-control implemented in multiple stages hosted on separate, non-overlapping infrastructure — a first-stage callback that collects host info / updates tooling / downloads a second stage, followed by a more capable later-stage channel to a different destination. The skill catches the *stage transition*: the process-lineage and cross-destination pivot that distinguishes staged C2 from a single beacon, since the staging is precisely what makes each stage individually quieter.

## Data sources / telemetry
- **Host:** Sysmon Event ID 1 (process creation + parent lineage), Event ID 3 (network connection) and 22 (DNS) — to tie a process's first-stage callback to a child/injected process's connection to a different host; Event ID 7/8/10 (image load / CreateRemoteThread / process access) for injection-based stage handoff; Security 4688.
- **Network:** Zeek `conn.log`/`http.log`/`dns.log`/`ssl.log`; proxy logs; NetFlow — to observe two distinct destinations contacted in sequence by one host/implant, and an ingress download (T1105) between them.
- **Correlation keys:** process GUID → connection mapping (Sysmon ties EID 1/3/22 by ProcessGuid), time ordering, destination ASN/domain diversity.
- MITRE detection strategy DET0228: analytic looks for a first process connecting to a first-stage C2 then spawning or injecting into a second process that connects to an **unrelated destination**; relies on Sysmon EID 1 and 3/22; tunable correlation window ~1–5 min, exclude known updaters/CDNs/corporate domains. Mitigation M1031 (Network Intrusion Prevention). (verify IDs on live attack.mitre.org.)

## Detection logic / approach
- **Stage-handoff via process lineage + cross-destination (core DET0228 logic):**
  ```
  1) Process A (Sysmon EID 1) makes outbound conn/DNS (EID 3/22) to Dest1
  2) A spawns child B OR injects (EID 8/10) into B
  3) B makes outbound conn/DNS (EID 3/22) to Dest2, where Dest2 != Dest1
     and Dest2/Dest1 share no infrastructure (different domain/ASN)
  within a 1–5 min window -> alert
  ```
  Implement as a SIEM correlation (Splunk transaction/KQL join on ProcessGuid and host) rather than a single-event rule.
- **Ingress between stages:** a download (T1105 — `certutil`/`bitsadmin`/`curl`/PowerShell `DownloadFile`) landing a new executable/DLL that then beacons to a second destination.
- **Infrastructure-diversity signal:** one host contacting two newly-seen, unrelated rare destinations in sequence (no overlapping IP/cert/domain) is a strong staged-C2 indicator; enrich with threat intel / newly-registered-domain / JA3.
- **Supporting beaconing:** each stage may still beacon — run periodicity analysis (RITA/Zeek) per destination to confirm C2 nature, but the *distinguishing* feature here is the staged pivot, not the beacon.
- Tune out legitimate multi-host chains: software updaters, CDNs, OS telemetry — allowlist by domain/signed-binary.

## Response / mitigation
- Egress IPS/allowlisting (M1031); block newly-registered/rare destinations; restrict LOLBins used for ingress (certutil/bitsadmin). On detection: isolate host, capture both-stage infrastructure as IOCs, identify first- and later-stage implant binaries via Sysmon lineage, sweep environment for the same stage-1 indicator, and block all discovered infrastructure (it is intentionally non-overlapping, so enumerate fully).

## Real tools
Sysmon, Zeek, RITA, Suricata/Arkime, Splunk/Microsoft Sentinel (KQL correlation), Sigma (correlation rules), threat-intel enrichment (newly-registered-domain feeds). (no invented endpoints.)

## Draft frontmatter mappings
- mitre_attack: [T1104, T1105, T1071.001, T1568, T1008]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, DE.CM-09, RS.MI-01]
- d3fend (optional): D3-NTA (Network Traffic Analysis), D3-PSA (Process Spawn Analysis), D3-OTF (Outbound Traffic Filtering) — verify current D3FEND IDs
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): hunting-for-command-and-control-beaconing

## Draft description (<=1024 chars)
Detects multi-stage command-and-control — a first-stage callback that downloads/launches a later stage on separate, non-overlapping infrastructure — by correlating process lineage with cross-destination network activity: Process A beacons to Dest1, spawns or injects into Process B, which beacons to an unrelated Dest2 within a short window, often with a T1105 ingress download between them. Uses Sysmon EID 1/3/22/8/10 and Zeek, as a SIEM correlation keyed on ProcessGuid. Use when hunting for staged C2 where a loader hands off to a more capable second-stage channel. Keywords: multi-stage channels, first-stage C2, stager, second stage, ingress tool transfer, DET0228, T1104. Do not use for single-channel beacon periodicity hunts - use hunting-for-command-and-control-beaconing; for encoded C2 content use detecting-encoded-c2-channels.

## Key references
- https://attack.mitre.org/techniques/T1104/
- https://attack.mitre.org/detectionstrategies/DET0228
- https://redteam.y-security.de/MITRE/techniques/T1104 (mirror)
- https://mitre.ptsecurity.com/en-US/T1104

## Open questions / scope boundaries
- Needs stateful cross-event correlation (not a single Sigma match); author must decide the correlation window and the "unrelated infrastructure" test (domain vs. ASN vs. cert). FP sources: updaters, CDNs, OS telemetry chains.
- Must NOT teach building staged C2. Decide overlap handling with beaconing and encoded-C2 siblings so this skill owns the *staging/handoff* angle. Confirm DET0228 analytic IDs and parameters on the live page.
