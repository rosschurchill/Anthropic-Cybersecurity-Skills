# Detecting Adversary Log Enumeration — research notes

- **Proposed slug:** detecting-adversary-log-enumeration
- **ATT&CK:** T1654 Log Enumeration (tactic: discovery) — related: T1070.001 (Clear Windows Event Logs, the common follow-on), T1082 (System Information Discovery)
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries enumerating event and audit logs to find security-tooling coverage, admin activity, credentials in logs, or evidence to later clear. The skill flags abnormal use of native log-reading utilities and APIs — especially against Security/System channels by non-admin or non-SOC accounts — and correlates enumeration with subsequent export or log clearing. Enumeration often immediately precedes defense evasion (log clearing) or targeted lateral movement.

## Data sources / telemetry
- **Windows process creation:** Security Event ID 4688 (and Sysmon Event ID 1) with full command line — `wevtutil.exe`, `wevtutil el`/`qe`, `wmic nteventlog`, `Get-WinEvent`, `Get-EventLog`.
- **PowerShell:** Script Block Logging (Event ID 4104) and Module Logging (4103) for `Get-WinEvent`/`Get-EventLog`/WMI `Win32_NTLogEvent` queries.
- **Windows object/file access:** Event ID 4663 (object access), 4656 (handle request), 4670 (permissions change) on `.evtx` files under `C:\Windows\System32\winevt\Logs\`; file read access to those paths.
- **Linux:** auditd EXECVE / process telemetry for `cat`/`grep`/`tail`/`journalctl`/`ausearch`/`last`/`zgrep` against `/var/log/*` (`auth.log`, `secure`, `syslog`, `wtmp`, audit logs); file-access audit rules on `/var/log`.
- MITRE detection strategy DET0255 names process creation (4688) and file access (4663/4670/4656) as log sources. (verify against live attack.mitre.org.)

## Detection logic / approach
- **Native log-tool invocation with sensitive targets:** Sigma-style process_creation rule:
  ```
  selection_img: Image|endswith: ['\wevtutil.exe','\wmic.exe']
  selection_cli: CommandLine|contains: ['qe','query-events','el','enum-logs','nteventlog','get Security']
  selection_ps:  CommandLine|contains: ['Get-WinEvent','Get-EventLog','Win32_NTLogEvent']
  condition: selection_img or selection_cli or selection_ps
  ```
  (The public Splunk analytic covers wevtutil.exe/wmic/PowerShell/WMI against Security or PowerShell logs; tune out SOC/backup service accounts.)
- **Actor-baseline correlation:** alert when the invoking account is not in the SOC/admin/backup allowlist, or when the enumerating process has an unusual parent (Office, browser, script interpreter).
- **Enumeration → export/transfer chain:** correlate a `wevtutil epl` / `Get-WinEvent | Export-Clixml` / log copy to a staging dir, followed by archive or network transfer within a short window.
- **Enumeration → clearing chain:** T1654 read of Security channel shortly before Event ID 1102 (audit log cleared) or `wevtutil cl` — high-confidence malicious sequence.
- Linux KQL/osquery: watch for processes reading `/var/log/wtmp`, `auth.log`, or `journalctl -u` enumeration by non-root interactive sessions.

## Response / mitigation
- Forward logs off-host in real time (WEF/Winlogbeat, rsyslog/syslog-ng to a SIEM) so local enumeration/clearing does not destroy evidence. Restrict read access to Security channel; enable tamper-resistant/immutable log storage. On detection: snapshot the host, preserve `.evtx`/`/var/log`, hunt for follow-on clearing (1102) and credential-in-log exposure, and treat as discovery preceding further intrusion.

## Real tools
wevtutil, Get-WinEvent, Get-EventLog, wmic, auditd/ausearch, journalctl, Sysmon, Splunk (research.splunk.com analytic dc167f8b), Sigma, osquery, Windows Event Forwarding. (verify Splunk analytic ID.)

## Draft frontmatter mappings
- mitre_attack: [T1654, T1070.001, T1082]
- nist_csf: [DE.CM-01, DE.CM-03, DE.AE-02, PR.PS-04, PR.DS-01]
- d3fend (optional): D3-PSA (Process Spawn Analysis), D3-FA (File Analysis) — verify current D3FEND IDs
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): detecting-evasion-techniques-in-endpoint-logs

## Draft description (<=1024 chars)
Detects adversary log enumeration — abnormal use of wevtutil, Get-WinEvent/Get-EventLog, wmic/WMI Win32_NTLogEvent, and Linux reads of /var/log — by correlating native log-reading tools, sensitive channel targets (Security/System), non-SOC accounts, and follow-on log export or clearing, using Windows 4688/4104/4663 and auditd telemetry. Use when hunting for discovery activity where an attacker inspects event/audit logs to find monitoring coverage or evidence before clearing it. Keywords: log enumeration, wevtutil qe, Get-WinEvent, Win32_NTLogEvent, journalctl, auth.log discovery, T1654. Do not use for detecting the actual clearing/tampering of logs after enumeration - use detecting-evasion-techniques-in-endpoint-logs (or a dedicated log-clearing skill for Event ID 1102).

## Key references
- https://attack.mitre.org/techniques/T1654/
- https://attack.mitre.org/detectionstrategies/DET0255
- https://research.splunk.com/endpoint/dc167f8b-3f9d-4460-9c98-8b6e703fd628/
- https://mitre.ptsecurity.com/en-US/T1654

## Open questions / scope boundaries
- High false-positive risk: SOC tooling, backup agents, and admins legitimately read logs — the skill must ship a strong allowlist/baseline approach. Decide Windows-only vs. cross-platform.
- Must NOT cover log clearing/tampering itself (T1070.001) beyond using it as a correlation signal; that is a separate defense-evasion skill. Confirm the KQL community rule's "enum-logs" naming vs. actual wevtutil verbs.
