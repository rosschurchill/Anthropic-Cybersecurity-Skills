---
name: detecting-esxi-administration-abuse
description: 'Detects adversary abuse of VMware ESXi administration interfaces after a hypervisor compromise (MITRE T1675): use of the Guest Operations API (StartProgramInGuest, InitiateFileTransferFromGuest) to execute in and move files into guest VMs (UNC3886-style), and hands-on-host esxcli/vim-cmd and SSH used to enable SSH, change the firewall, stop syslog, add accounts, and mass power-off or encrypt VMs ahead of ransomware. Correlates hostd Guest-Ops calls, shell.log command history, and auth.log SSH logins against an admin baseline by identity, frequency, and change window. Use when hunting ESXi/vSphere intrusion or triaging suspicious hypervisor activity. Keywords: T1675, ESXi, hostd.log, shell.log, esxcli, vim-cmd, Guest Operations, vmtoolsd, lockdown mode, ESXi ransomware. Do not use for cloud IaaS compute-plane tampering - use detecting-cloud-compute-infrastructure-tampering.'
domain: cybersecurity
subdomain: endpoint-security
tags:
- endpoint-security
- threat-detection
- esxi
- vmware
- hypervisor
- guest-operations
- esxi-ransomware
- vim-cmd
- t1675
- virtualization-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.AE-02
- DE.AE-03
- PR.AA-05
- PR.IR-01
mitre_attack:
- T1675
- T1059.012
- T1021.004
---

# Detecting ESXi Administration Abuse

## When to Use

Use this skill to detect an adversary who, having compromised a VMware **ESXi
host or vCenter**, uses the hypervisor's own administration interfaces to reach
into guest VMs and reconfigure the host (ATT&CK T1675). T1675 specifically
covers the **Guest Operations API** path — running programs and moving files
into guests from the hypervisor (e.g. UNC3886 driving `vmtoolsd`), which bypasses
in-guest network monitoring entirely. The skill also catches the adjacent
hands-on-host activity ransomware crews rely on: SSH/shell logins and
`esxcli`/`vim-cmd` to enable SSH, change the firewall, stop logging, add
accounts, and mass power-off or encrypt VMs. Reach for it when:

- Hunting ESXi/vSphere intrusion or triaging suspicious hypervisor activity.
- A host shows SSH enabled, syslog stopped, or mass VM power-off.

For cloud IaaS compute-plane tampering use
`detecting-cloud-compute-infrastructure-tampering`; for in-guest OS logs use
`analyzing-linux-audit-logs-for-intrusion`.

## Prerequisites

- **ESXi logs forwarded to a remote, immutable syslog/SIEM** (host root can wipe
  local logs): `/var/log/hostd.log` (Guest Ops + auth + config), `/var/log/
  shell.log` (every ESXi Shell/SSH command — Broadcom KB 321910),
  `/var/log/auth.log` (SSH logins), `/var/log/vmkernel.log`.
- vCenter VPXD events for `GuestOperations`.
- A **baseline** of legitimate admin accounts, Guest-Ops usage, and change
  windows.

## Workflow

1. **Baseline legitimate hypervisor admin** (accounts, Guest-Ops frequency,
   backup/automation tooling, change windows).
2. **Guest Operations misuse (T1675).** In `hostd.log`, alert on spikes in
   `StartProgramInGuest` / `ListProcessesInGuest` / `InitiateFileTransferFromGuest`
   / `...ToGuest`, invocation by an unexpected account, or calls outside change
   windows. Execution into many guests from one host = fan-out.
3. **Host hardening tamper (T1059.012).** In `shell.log`, high-signal:
   `esxcli network firewall set --enabled false`, enabling SSH/ESXi Shell,
   stopping/redirecting syslog, `esxcli system account add` / permission grants.
4. **SSH + shell correlation.** A new `auth.log` SSH login from an unusual IP
   immediately followed by `esxcli`/`vim-cmd` in `shell.log` (correlate by
   world/process ID per Broadcom KB).
5. **Impact chain.** `vim-cmd vmsvc/power.off` across many VMs or mass `.vmdk`
   modification in a short window → ransomware staging.
6. **Respond** (see *Response*).

## Key Concepts

- **Guest Ops bypasses the network:** executing into a guest from the hypervisor
  leaves no guest network trace — `hostd.log` is the only place it shows.
- **shell.log is the command tape:** it records every ESXi Shell/SSH command;
  correlating it with `auth.log` attributes a command to a user and client IP.
- **Logs must be off-host:** an attacker with host root erases local logs —
  remote syslog forwarding is the difference between visibility and a blind spot.
- **Power-off/encrypt fan-out = ransomware:** mass `vmsvc/power.off` then `.vmdk`
  changes is the ESXi-ransomware signature (seize VMs offline, then encrypt).

## Tools & Systems

VMware ESXi / vCenter (hostd, vpxd, syslog), PowerCLI and `govc` (baseline),
Splunk (ESXi ransomware detections), Microsoft Sentinel / Elastic for syslog,
vSphere lockdown mode, `execInstalledOnly`, EDR with ESXi support.

## Detection Queries

### Splunk -- host hardening / impact via shell.log

```spl
index=esxi (source="*shell.log" OR sourcetype="esxi:shell")
  ("esxcli system account add" OR "network firewall set --enabled false"
   OR "system syslog" OR "vim-cmd vmsvc/power.off"
   OR "system settings advanced set*Shell*" OR "vim-cmd hostsvc/enable_ssh")
| stats values(_raw) as cmds count by host, user
| where count > 0
```

### Splunk -- Guest Operations misuse via hostd.log

```spl
index=esxi source="*hostd.log"
  ("StartProgramInGuest" OR "InitiateFileTransferFromGuest" OR "InitiateFileTransferToGuest" OR "ListProcessesInGuest")
| rex "user=(?<user>\S+)"
| stats count dc(host) as hosts values(host) as vms by user, bin(_time, 10m)
| where count > 10 OR hosts > 3     // fan-out or burst
```

### Correlate SSH login -> shell command

```spl
index=esxi source="*auth.log" "SSH" ("session opened" OR "Accepted")
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| join host [ search index=esxi source="*shell.log" ("esxcli" OR "vim-cmd") | eval shellTime=_time ]
| where shellTime>=_time AND (shellTime-_time) < 300
| table _time, host, user, src, _raw
```

## Common Scenarios

- **UNC3886 Guest Ops:** attacker runs programs into guests via `vmtoolsd` —
  hostd Guest-Ops spike with no guest network trace.
- **ESXi ransomware prep:** SSH enabled, firewall off, syslog stopped, account
  added — all in shell.log minutes apart.
- **Mass power-off:** `vim-cmd vmsvc/power.off` across the inventory before
  encryption.
- **False positive:** backup software using Guest Ops on a schedule — baselined
  by account.

## Output Format

```
ESXI ADMIN ABUSE DETECTION
  Host(s):         <esxi host / cluster>
  Verdict:         <confirmed | suspected | approved-admin/backup>
  Vector:          <Guest Ops (T1675) | esxcli/vim-cmd (T1059.012) | SSH (T1021.004)>
  Evidence:        <hostd Guest-Ops calls | shell.log hardening/impact cmds | auth.log SSH from <ip>>
  Account:         <user> (expected: <y/n>) ; scope: <n guests/VMs>
  Impact signal:   <SSH enabled | firewall off | syslog stopped | mass power-off | .vmdk writes>
  ATT&CK:          T1675[, T1059.012, T1021.004]
  Actions taken:   <host isolated | logs preserved off-host | vCenter/ESXi creds revoked | other hosts hunted>
```

## Response

- **Restrict Guest Operations permissions** on ESXi-hosted VMs to accounts that
  need them (ATT&CK mitigation for T1675); enforce vCenter roles / least
  privilege (NIST CSF PR.AA-05).
- Keep ESXi in **lockdown mode**, SSH/ESXi Shell disabled by default, firewall
  restricted to the management network; enable `execInstalledOnly` / secure boot;
  enforce MFA on management.
- **Forward all ESXi logs to immutable remote syslog/SIEM** so host-root cannot
  erase the trail.
- **Respond:** isolate the host from management/storage networks, preserve
  hostd/shell/auth logs, revoke compromised vCenter/ESXi credentials, hunt other
  hosts via the same account, and check for added accounts/backdoors and altered
  startup scripts.
