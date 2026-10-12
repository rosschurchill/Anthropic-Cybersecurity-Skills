# Detecting Automated Data Exfiltration — research notes

- **Proposed slug:** detecting-automated-data-exfiltration
- **ATT&CK:** T1020 Automated Exfiltration (tactic: exfiltration) — sub-technique T1020.001 (Traffic Duplication); related: T1029 (Scheduled Transfer), T1041 (Exfil over C2 Channel), T1567 (Exfil over Web Service)
- **Status:** research (not yet a skill)

## Defensive goal
Detect data leaving the environment via automated, programmatic processes (scripts, scheduled tasks, cron jobs, daemons, or network-device traffic duplication) rather than interactive user action. The skill flags repeated, periodic outbound transfers of collected/staged data to the same external destination, and the scheduled-task/cron mechanisms that drive them, distinguishing automation from one-off human uploads.

## Data sources / telemetry
- **Network:** Zeek `conn.log` (bytes_orig/duration/periodicity), `http.log`, `dns.log`, `ssl.log`; NetFlow/IPFIX outbound byte volume per dest; firewall/proxy egress logs; Sysmon Event ID 3 (network connection) and 22 (DNS).
- **Host – scheduling mechanisms:** Windows scheduled task creation (Event ID 4698, Sysmon 1 for `schtasks.exe`), Security 4688 command lines; Linux cron/`/etc/cron.*`, systemd timers, auditd EXECVE for `curl`/`scp`/`rclone`/`python` run by non-interactive parents.
- **File access:** Event ID 4663 / Sysmon 11 on staging directories read immediately before transfer.
- **Cloud:** CloudTrail (`GetObject`, `CreateSnapshot`, bulk S3 reads), GCP/Azure storage access logs, data-transfer/egress metrics.
- MITRE detection strategy DET0397 (analytics AN1113 Windows / AN1114 Linux / AN1115) maps to Network Connection Creation (DC0082 → Sysmon 3), with tunable repeat-window and trusted-destination filters; data sources DS0029 (Network Traffic Content), DS0022 (File Access), DS0017 (Command Execution). (verify IDs on live attack.mitre.org.)

## Detection logic / approach
- **Periodic outbound transfer to a fixed destination:** statistical analysis of conn.log — group by `id.resp_h`, measure inter-arrival regularity (low jitter / fixed interval) and cumulative bytes-out; flag automated cadence. (Mirrors the beaconing approach but keyed on upload volume.) ZAT/Pandas sketch:
  ```
  df.groupby('dest_ip').agg(n=('ts','count'), bytes=('orig_bytes','sum'),
     jitter=('iat','std')); flag where n>threshold and jitter<eps and bytes>vol
  ```
- **Scheduled/automation source:** correlate the transfer process with a scheduled-task (4698) / cron / systemd-timer owner and a non-interactive session — automation, not a logged-on user at the keyboard.
- **Staging-read → egress chain:** file read of a known staging/archive path followed within minutes by outbound transfer of similar byte volume.
- **Traffic duplication (T1020.001):** detect network-device config changes enabling SPAN/port-mirroring/GRE taps — monitor router/switch config-change logs for mirror-session or `monitor session` commands, and unexpected encapsulated egress.
- **Cloud:** alert on bulk/scripted object reads or snapshot exports from a role/service account to an external or new destination, outside business hours.
- Baseline normal egress destinations (backup, SaaS, updates); alert on new high-volume automated destinations.

## Response / mitigation
- DLP egress policy + proxy allowlisting; cap and alert on outbound volume per host/account; block unapproved cloud-sync tools (rclone/mega). Protect network-device configs and alert on mirror-session changes. On detection: identify and kill the scheduled task/cron/daemon, block the destination, scope what data was staged/read, rotate exposed credentials, and preserve flow records.

## Real tools
Zeek, ZAT, RITA (beacon/exfil analysis), Suricata/Arkime, NetFlow/nfdump, Sysmon, Splunk, Sigma, AWS CloudTrail/GuardDuty (exfiltration findings), DLP platforms (Microsoft Purview, Forcepoint). (verify vendor-specific rule names.)

## Draft frontmatter mappings
- mitre_attack: [T1020, T1020.001, T1029, T1041, T1567]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, PR.DS-05, RS.MI-01]
- d3fend (optional): D3-OTF (Outbound Traffic Filtering), D3-NTA (Network Traffic Analysis), D3-RTSD — verify current D3FEND IDs
- suggested subdomain: network-security
- nearest existing sibling (for the negative trigger): hunting-for-data-exfiltration-indicators

## Draft description (<=1024 chars)
Detects automated data exfiltration — scripted, scheduled-task, cron, daemon, or traffic-duplication transfers of staged data to external destinations — by correlating periodic low-jitter high-volume egress (Zeek conn.log / NetFlow), the scheduling mechanism (Event ID 4698, cron, systemd timers), staging-directory reads, and network-device mirror-session changes. Use when hunting for or alerting on recurring programmatic uploads that signal exfiltration automation rather than a one-off human upload. Keywords: automated exfiltration, scheduled transfer, traffic duplication, port mirroring, rclone, periodic upload, T1020. Do not use for general manual/DLP exfiltration hunting across all channels - use hunting-for-data-exfiltration-indicators; for DNS-tunneled exfil use detecting-dns-exfiltration-with-dns-query-analysis.

## Key references
- https://attack.mitre.org/techniques/T1020/
- https://attack.mitre.org/detectionstrategies/DET0397
- https://mitre.ptsecurity.com/en-US/T1020
- https://attack.mitre.org/techniques/T1020/001/ (Traffic Duplication — verify)

## Open questions / scope boundaries
- Overlaps with existing exfil/DNS/S3 siblings; author must sharpen the negative trigger so this skill owns the *automation/periodicity + scheduling-mechanism* angle, not generic exfil.
- Must NOT cover building exfil tooling. Decide whether cloud bulk-export detection stays here or defers to detecting-s3-data-exfiltration-attempts. Confirm DET0397 analytic/data-component IDs on the live page.
