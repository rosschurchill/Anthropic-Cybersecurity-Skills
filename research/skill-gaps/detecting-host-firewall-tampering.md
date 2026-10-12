# Detecting Host Firewall Tampering — research notes

- **Proposed slug:** detecting-host-firewall-tampering
- **ATT&CK:** T1686 Disable or Modify System Firewall (tactic: defense-evasion / in ATT&CK v19 promoted to top-level under Defense Impairment TA0112) — successor to **T1562.004**. Sub-technique: **T1686.003 Windows Host Firewall** (verify full sub-technique list in v19). Related: T1562 Impair Defenses, T1489 Service Stop.
- **Status:** research (not yet a skill)

## Defensive goal
Detect when an adversary disables or weakens a host-based firewall to enable C2, lateral movement, or ingress tool transfer — turning the Windows Defender Firewall off, adding/deleting allow rules, stopping the firewall service, or flushing iptables/ufw/firewalld on Linux. The skill alerts on both the command-line method and the resulting audited policy-change events, and distinguishes routine admin changes from evasive ones via context.

## Data sources / telemetry
- **Windows Security log (MPSSVC Rule-Level Policy Change subcategory):**
  - **4946** — a rule was ADDED to the Windows Firewall exception list.
  - **4947** — a rule was MODIFIED.
  - **4948** — a rule was DELETED.
  - **4950** — a Windows Firewall setting changed.
  - **5025** — the Windows Firewall service was stopped (verify; 5024=started, 5034 generally service stopped — confirm against Microsoft docs).
  - Useful fields: `RuleName`, `RuleId`, `ProfileChanged`, `Computer`, `SubjectUserName`.
- **Process creation** (Sysmon EID 1 / Security 4688): `netsh.exe`, `powershell.exe` (Set-NetFirewallProfile / New-NetFirewallRule / Remove-NetFirewallRule), `reg.exe` writes to firewall policy keys.
- **Registry** (Sysmon 12/13/14): `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\*` (EnableFirewall, DisableNotifications).
- **Linux:** auditd `execve` records and Sysmon-for-Linux process creation for `iptables`/`nft`/`ufw`/`firewall-cmd`/`systemctl`; auditd watches on `/etc/sysconfig/iptables`, `/etc/ufw/`, firewalld config; systemd journal for `firewalld`/`ufw` service state changes.

## Detection logic / approach
Windows — command-line (SigmaHQ `proc_creation_win_netsh_fw_disable`, id 57c4bf16-227f-4394-8ec7-1b745ee061c3):
```
image|endswith: '\netsh.exe'
command line contains all of: ('firewall','set','opmode','disable')  OR  ('advfirewall','set',' state','off')
```
Also detect `netsh advfirewall firewall add rule ... action=allow` and `delete rule`. Elastic has the equivalent EQL rule mapped to T1686.

Windows — audited events (Splunk `research.splunk.com` "Windows Firewall Rule Added" for 4946; Sigma rules exist for 4947/4948 under defense_evasion). Alert on 4947/4948 (modify/delete) and 4950 (setting change), especially:
- rule changes opening inbound ports or allowing a suspicious binary,
- deletion of multiple rules in a short window (observed in Medusa / ShrinkLocker ransomware),
- firewall-service stop (5025) followed by new inbound flows.

Linux — process-creation (Sigma/osquery/auditd): alert on `iptables -F` / `iptables -P INPUT ACCEPT`, `nft flush ruleset`, `ufw disable`, `systemctl stop firewalld`/`systemctl disable firewalld`, `firewall-cmd --set-default-zone=trusted`.

Correlation to cut false positives: tie the change to an unexpected user/parent process, to off-hours, or to subsequent network ingress — because legitimate admin/GPO activity also fires these events (the Sigma rule's own FP note says so).

## Response / mitigation
- Re-enable and re-baseline firewall policy (prefer central GPO/Intune/Ansible so local changes are reverted automatically).
- Restrict who can modify firewall config (least privilege; UAC; `netsh`/`firewall-cmd` audited).
- Enable the MPSSVC Rule-Level Policy Change audit subcategory and forward 4946-4950/5025 to the SIEM.
- Containment: isolate host, review new/deleted rules and any flows that used them.

## Real tools
Sysmon / Sysmon-for-Linux, Windows Event Log (Security, MPSSVC subcategory), auditd, osquery, SigmaHQ, Splunk Enterprise Security, Elastic Security, Microsoft Sentinel (KQL), GPO/Intune, Ansible, `netsh`, `Get/Set-NetFirewall*` PowerShell cmdlets, `iptables`/`nft`/`ufw`/`firewall-cmd`.

## Draft frontmatter mappings
- mitre_attack: [T1686, T1686.003, T1562, T1562.004, T1489]
- nist_csf: [DE.CM-09, DE.CM-01, PR.IR-01, PR.PS-01, DE.AE-03]
- d3fend (optional): D3-SDM (System Daemon Monitoring), D3-PSMD (Process Spawn/command analysis) — verify exact ids
- suggested subdomain: soc-operations
- nearest existing sibling (for the negative trigger): detecting-evasion-techniques-in-endpoint-logs

## Draft description (<=1024 chars)
Detects tampering with host-based firewalls used to evade defenses and enable C2 or lateral movement — Windows Defender Firewall being disabled or rules added/modified/deleted (Security events 4946/4947/4948/4950, firewall-service stop), netsh/PowerShell command lines, and Linux iptables flushes, ufw disable, or firewalld being stopped. Correlates the method with the audited policy-change events and with resulting network ingress, and tunes out routine admin/GPO changes. Use when hunting defense-evasion via firewall tampering or triaging firewall policy-change alerts. Keywords: firewall tampering, netsh advfirewall disable, event 4946 4947 4948 4950, iptables -F, ufw disable, firewalld stop, T1686, T1562.004. Do not use for network perimeter/router ACL changes - use detecting-network-boundary-bridging; for broad endpoint evasion triage use detecting-evasion-techniques-in-endpoint-logs.

## Key references
- https://attack.mitre.org/techniques/T1686/
- https://research.splunk.com/endpoint/efc25501-4e75-4075-8cc5-ac80f2847d80/ (Windows Firewall Rule Added)
- https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_netsh_fw_disable/
- https://www.elastic.co/guide/en/security/8.x/disable-windows-firewall-rules-via-netsh.html
- https://docs.logrhythm.com/devices/docs/evid-4946-4948-firewall-rule-add-mod-del-xml-secur
- https://www.manageengine.com/log-management/detection-rules/firewall-disabled-via-netsh-exe.html

## Open questions / scope boundaries
- Confirm 5025 vs 5034 as the "Windows Firewall service stopped" event, and the exact v19 sub-technique list for T1686, against Microsoft/MITRE docs.
- Verify Linux auditd/osquery coverage of `nft`/`firewall-cmd` on the target distro before shipping those rules.
- Must NOT cover perimeter/network-device firewall or ACL changes (that is T1599 / a network-security skill) — this skill is host firewalls only.
