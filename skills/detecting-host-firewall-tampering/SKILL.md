---
name: detecting-host-firewall-tampering
description: 'Detects tampering with host-based firewalls (MITRE T1686) used to evade defenses and enable C2 or lateral movement - Windows Defender Firewall being disabled or rules added/modified/deleted (Security events 4946/4947/4948/4950 and firewall-service stop), netsh and PowerShell command lines (Set-NetFirewallProfile, netsh advfirewall set opmode disable), and Linux iptables flushes, ufw disable, or firewalld being stopped. Correlates the method with the audited policy-change events and resulting network ingress, and tunes out routine admin/GPO changes. Use when hunting defense-evasion via firewall tampering or triaging firewall policy-change alerts. Keywords: firewall tampering, netsh advfirewall disable, event 4946 4947 4948 4950, iptables -F, ufw disable, firewalld stop, T1686. Do not use for broad endpoint defense-evasion triage - use detecting-evasion-techniques-in-endpoint-logs.'
domain: cybersecurity
subdomain: soc-operations
tags:
- soc-operations
- threat-detection
- firewall-tampering
- defense-evasion
- netsh
- windows-events
- iptables
- firewalld
- t1686
- endpoint-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-03
- PR.IR-01
- PR.PS-01
mitre_attack:
- T1686
- T1686.003
- T1489
---

# Detecting Host Firewall Tampering

## When to Use

Use this skill to detect when an adversary **disables or weakens a host-based
firewall** to enable C2, lateral movement, or ingress tool transfer (ATT&CK
T1686) — turning the Windows Defender Firewall off, adding/deleting allow rules,
stopping the firewall service, or flushing iptables/ufw/firewalld on Linux.
Reach for it when:

- A firewall policy-change alert fires (rule added/modified/deleted).
- The host firewall service stops unexpectedly.
- You are hunting defense-evasion that precedes inbound C2 or lateral movement.

This skill is **host firewalls only**. For perimeter/router ACL and
network-boundary changes use a network-boundary skill; for broad endpoint
evasion triage use `detecting-evasion-techniques-in-endpoint-logs`.

## Prerequisites

- **Windows Security log — MPSSVC Rule-Level Policy Change subcategory enabled**:
  **4946** (rule added), **4947** (rule modified), **4948** (rule deleted),
  **4950** (firewall setting changed), plus the firewall-service stop event
  (confirm the exact ID in your build). Useful fields: `RuleName`, `RuleId`,
  `ProfileChanged`, `SubjectUserName`.
- **Process creation**: Sysmon Event ID 1 / Security 4688 (command line).
- **Registry** (Sysmon 12/13/14): `HKLM\SYSTEM\CurrentControlSet\Services\
  SharedAccess\Parameters\FirewallPolicy\*` (`EnableFirewall`).
- **Linux**: `auditd` execve / Sysmon-for-Linux for `iptables`/`nft`/`ufw`/
  `firewall-cmd`/`systemctl`, plus watches on firewall config files and systemd
  service-state changes.
- A **baseline firewall policy** (ideally central GPO/Intune/Ansible).

## Workflow

1. **Record the legitimate change path** — the GPO/Intune/Ansible principal and
   admins allowed to change firewall config, and the change windows.
2. **Windows command-line method.** Alert on `netsh advfirewall set opmode
   disable` / `set ... state off`, `netsh advfirewall firewall add/delete rule`,
   and PowerShell `Set-NetFirewallProfile -Enabled False` /
   `New-/Remove-NetFirewallRule`.
3. **Windows audited events.** Alert on 4947/4948 (modify/delete) and 4950
   (setting change), especially: rules opening inbound ports or allowing a
   suspicious binary, **deletion of multiple rules in a short window** (seen in
   Medusa/ShrinkLocker), and firewall-service stop followed by new inbound flows.
4. **Linux method.** Alert on `iptables -F` / `iptables -P INPUT ACCEPT`,
   `nft flush ruleset`, `ufw disable`, `systemctl stop/disable firewalld`,
   `firewall-cmd --set-default-zone=trusted`.
5. **Correlate to cut false positives.** Tie the change to an unexpected
   user/parent process, off-hours, or **subsequent network ingress** — routine
   admin/GPO activity fires the same events.
6. **Respond** (see *Response*) — re-baseline policy and hunt the flows the
   change enabled.

## Key Concepts

- **Method + effect both logged:** the command line (how) and the audited
  policy-change event (what changed) corroborate each other; neither alone is
  conclusive.
- **Rule deletion bursts** are a strong ransomware/evasion signal — legitimate
  admins rarely delete many rules at once.
- **The payoff is ingress:** firewall tampering is a means to an end; correlating
  with new inbound flows confirms malicious intent.
- **Central policy is the control:** GPO/Intune that reverts local changes both
  mitigates and generates a clean baseline to diff against.

## Tools & Systems

Sysmon / Sysmon-for-Linux, Windows Event Log (Security, MPSSVC subcategory),
`auditd`, osquery, SigmaHQ, Splunk Enterprise Security, Elastic Security,
Microsoft Sentinel (KQL), GPO/Intune, Ansible, `netsh`, `Get/Set-NetFirewall*`,
`iptables`/`nft`/`ufw`/`firewall-cmd`.

## Detection Queries

### Sigma -- Windows firewall disabled via netsh

```yaml
title: Windows Firewall Disabled via netsh
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith: '\netsh.exe'
  selection_disable:
    CommandLine|contains|all: ['firewall','set','opmode','disable']
  selection_adv:
    CommandLine|contains|all: ['advfirewall','set','state','off']
  condition: selection_img and (selection_disable or selection_adv)
falsepositives:
  - Legitimate administrator or GPO firewall changes
level: high
```

### Splunk -- firewall rule delete/modify burst (4947/4948)

```spl
`wineventlog_security` EventCode IN (4947,4948,4950)
| bin _time span=5m
| stats count as changes values(Rule_Name) as rules by Computer, Subject_User_Name, _time
| where changes >= 5
| `comment("many rule changes in 5 min by one user = likely evasion")`
```

### Linux -- auditd for firewall flush/disable

```
-w /usr/sbin/iptables -p x -k fw_tamper
-w /usr/sbin/nft -p x -k fw_tamper
-w /usr/sbin/ufw -p x -k fw_tamper
-w /usr/bin/firewall-cmd -p x -k fw_tamper
```

### KQL -- firewall setting change then inbound flow (correlation)

```kql
let fwOff = SecurityEvent
| where EventID in (4950) or (EventID == 4688 and CommandLine has "advfirewall" and CommandLine has "disable")
| project offTime = TimeGenerated, Computer, Account;
fwOff
| join kind=inner (CommonSecurityLog | where DeviceAction == "allow" and Direction == "Inbound")
    on Computer
| where TimeGenerated between (offTime .. offTime + 1h)
| project Computer, Account, offTime, SourceIP, DestinationPort
```

## Common Scenarios

- **Ransomware prep:** `netsh advfirewall set allprofiles state off` then SMB
  lateral movement — command line + 4950 + new inbound flows.
- **Rule-delete burst:** many 4948 events clear protective rules before C2.
- **Linux pivot:** `iptables -F; iptables -P INPUT ACCEPT` opens the host.
- **False positive:** scheduled GPO firewall update by the management account in
  a change window — suppressed by principal/window context.

## Output Format

```
FIREWALL TAMPERING DETECTION
  Host:            <computer>
  Verdict:         <confirmed | suspected | approved-admin/GPO>
  Method:          <netsh disable | rule add/delete | service stop | iptables -F | ufw disable | firewalld stop>
  Audited event:   <4946/4947/4948/4950 | n/a>
  Actor:           <user/parent> (expected admin: <y/n>)
  Follow-on:       <new inbound flow on port N | none>
  ATT&CK:          T1686(.003)[, T1489]
  Actions taken:   <policy re-baselined via GPO | host isolated | flows reviewed>
```

## Response

- **Re-enable and re-baseline** firewall policy, preferably via central
  GPO/Intune/Ansible so local changes revert automatically.
- **Restrict who can modify firewall config** (least privilege, UAC; audit
  `netsh`/`firewall-cmd`) — NIST CSF PR.PS-01.
- **Enable the MPSSVC Rule-Level Policy Change audit subcategory** and forward
  4946-4950 + service-stop events to the SIEM.
- **Contain and review:** isolate the host and review new/deleted rules and any
  flows that used them.
