---
name: detecting-automated-data-exfiltration
description: 'Detects automated data exfiltration (MITRE T1020) - scripted, scheduled-task, cron, daemon, or traffic-duplication transfers of staged data to external destinations - by correlating periodic low-jitter high-volume egress (Zeek conn.log / NetFlow), the scheduling mechanism (Windows Event ID 4698, cron, systemd timers), staging-directory reads, and network-device mirror-session changes. Use when hunting or alerting on recurring programmatic uploads that signal exfiltration automation rather than a one-off human upload. Keywords: automated exfiltration, scheduled transfer, traffic duplication, port mirroring, rclone, periodic upload, T1020. Do not use for general manual DLP exfiltration hunting across all channels - use hunting-for-data-exfiltration-indicators.'
domain: cybersecurity
subdomain: network-security
tags:
- network-security
- threat-detection
- exfiltration
- automated-exfiltration
- scheduled-transfer
- zeek
- netflow
- traffic-duplication
- t1020
- dlp
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- PR.DS-02
- RS.MI-01
mitre_attack:
- T1020
- T1020.001
- T1029
- T1041
- T1567
---

# Detecting Automated Data Exfiltration

## When to Use

Use this skill to detect data leaving the environment via **automated,
programmatic processes** — scripts, scheduled tasks, cron jobs, daemons, or
network-device traffic duplication — rather than interactive user action (ATT&CK
T1020). It flags repeated, periodic outbound transfers of collected/staged data
to the same external destination, and the scheduling mechanisms that drive them,
distinguishing automation from one-off human uploads. Reach for it when:

- Recurring high-volume uploads go to a fixed external destination.
- A scheduled task / cron job / systemd timer is transferring data.
- A network device shows an unexpected SPAN/mirror session.

This skill owns the **automation + periodicity + scheduling-mechanism** angle.
For general exfiltration hunting across all channels use
`hunting-for-data-exfiltration-indicators`; for DNS-tunnelled exfil use
`detecting-dns-exfiltration-with-dns-query-analysis`.

## Prerequisites

- **Network**: Zeek `conn.log`/`http.log`/`ssl.log`, NetFlow/IPFIX outbound byte
  volume per destination, firewall/proxy egress logs, Sysmon Event ID 3/22.
- **Host scheduling**: Windows scheduled-task creation (Event ID 4698, `schtasks`
  on Sysmon 1/4688); Linux cron (`/etc/cron.*`), systemd timers, `auditd` EXECVE
  for `curl`/`scp`/`rclone`/`python` with non-interactive parents.
- **File access**: Event ID 4663 / Sysmon 11 on staging directories.
- **Cloud**: CloudTrail bulk `GetObject`/snapshot export, GCP/Azure storage
  access logs and egress metrics.
- A **baseline of normal egress destinations** (backup, SaaS, updates).

## Workflow

1. **Baseline normal automated egress** (backup targets, SaaS sync, update
   servers) and the scheduled jobs that produce it.
2. **Periodic transfer to a fixed destination.** Over `conn.log`/NetFlow, group by
   destination and measure inter-arrival regularity (low jitter / fixed interval)
   and cumulative bytes-out; flag an automated cadence with significant upload
   volume (the beaconing method keyed on upload size).
3. **Tie to a scheduling mechanism.** Correlate the transfer process with a
   scheduled-task (4698) / cron / systemd-timer owner and a **non-interactive**
   session — automation, not a user at the keyboard.
4. **Staging-read → egress chain.** A read of a known staging/archive path
   followed within minutes by an outbound transfer of similar byte volume.
5. **Traffic duplication (T1020.001).** Watch network-device config logs for
   SPAN/`monitor session`/port-mirror/GRE-tap changes and unexpected encapsulated
   egress.
6. **Cloud.** Alert on bulk/scripted object reads or snapshot exports by a
   role/service account to a new/external destination, off-hours.
7. **Respond** (see *Response*).

## Key Concepts

- **Periodicity + volume is the signature:** automated exfil looks like beaconing
  but with large bytes-out — fixed cadence to one destination over time.
- **The scheduler is the corroborator:** a 4698 task or cron entry owning the
  transferring process confirms automation over a human upload.
- **Traffic duplication is silent:** a mirror session copies data at the network
  device with no host process — only device config logs reveal it.
- **Baseline beats blocklists:** legitimate backup/SaaS sync is periodic and
  high-volume too; a known-destination baseline keeps the signal clean.

## Tools & Systems

Zeek, ZAT, RITA (beacon/exfil analysis), Suricata/Arkime, NetFlow/nfdump, Sysmon,
Splunk, Sigma, AWS CloudTrail/GuardDuty, DLP platforms (Microsoft Purview,
Forcepoint).

## Detection Queries

### Python/ZAT -- periodic high-volume upload over conn.log

```python
import pandas as pd
# df: Zeek conn.log with ts, id.resp_h, orig_bytes
df = df.sort_values(["id.resp_h","ts"])
df["iat"] = df.groupby("id.resp_h")["ts"].diff()
agg = df.groupby("id.resp_h").agg(n=("ts","count"),
        bytes=("orig_bytes","sum"), jitter=("iat","std"))
suspect = agg[(agg.n > 20) & (agg.jitter < 5) & (agg.bytes > 50_000_000)]
print(suspect)   # low-jitter, high-volume, repeated = automated exfil
```

### Splunk -- scheduled task creating an egress process

```spl
`wineventlog_security` EventCode=4698
| rex field=Task_Content "<Command>(?<taskCmd>[^<]+)</Command>"
| where match(taskCmd, "(?i)(curl|rclone|scp|powershell|bitsadmin|Invoke-WebRequest)")
| table _time, Computer, Subject_User_Name, taskCmd
```

### Network-device -- mirror-session change (traffic duplication)

```spl
`network_syslog` (message="*monitor session*" OR message="*port-mirror*" OR message="*interface Tunnel*")
| stats values(message) as changes by host, user
| `comment("new SPAN/mirror/GRE session on a boundary device = possible T1020.001")`
```

## Common Scenarios

- **rclone cron:** a cron job runs `rclone copy /staging remote:` nightly to an
  attacker cloud — periodic egress + cron owner.
- **Scheduled curl upload:** a 4698 task POSTs an archive hourly to a C2.
- **Port mirror:** a compromised switch mirrors a sensitive VLAN to an
  attacker-collection host.
- **False positive:** the corporate backup agent's nightly offsite sync —
  allowlisted destination.

## Output Format

```
AUTOMATED EXFIL DETECTION
  Host/flow:       <host> -> <dest ip/domain>
  Verdict:         <confirmed | suspected | approved-backup/SaaS>
  Pattern:         <periodic upload | scheduled task | cron/systemd | traffic duplication | cloud bulk read>
  Cadence/volume:  interval ~<n>, jitter <x>, bytes-out <total>
  Mechanism:       <4698 task | cron entry | systemd timer | mirror session> owned by <account>
  ATT&CK:          T1020(.001)[, T1029, T1041, T1567]
  Actions taken:   <task/cron killed | destination blocked | staged data scoped | creds rotated>
```

## Response

- **DLP egress policy + proxy allowlisting**; cap and alert on outbound volume
  per host/account; block unapproved cloud-sync tools (rclone/mega) (NIST CSF
  PR.DS-02).
- **Protect network-device configs** and alert on mirror-session changes.
- **On detection:** identify and kill the scheduled task/cron/daemon, block the
  destination, scope what data was staged/read, rotate exposed credentials, and
  preserve flow records.
