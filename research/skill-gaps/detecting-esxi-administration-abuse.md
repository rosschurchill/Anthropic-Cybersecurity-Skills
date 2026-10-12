# Detecting ESXi Administration Abuse — research notes

- **Proposed slug:** detecting-esxi-administration-abuse
- **ATT&CK:** T1675 ESXi Administration Command (tactic: execution) — closely related: **T1059.012 Hypervisor CLI** (esxcli/vim-cmd; detection strategy DET0558), and T1021 Remote Services (SSH to the host). T1675 detection strategy: **DET0232** (analytic AN0646). (Verify ids against v19.2.)
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary who, having compromised a VMware ESXi host (or vCenter), uses the hypervisor's own administration interfaces to reach into guest VMs and to reconfigure the host. T1675 specifically covers the **Guest Operations API** path — running programs and moving files into guests from the hypervisor (e.g., UNC3886 driving `vmtoolsd` to execute in guests) — which bypasses in-guest network monitoring entirely. The skill also catches the adjacent hands-on-host activity ransomware crews rely on: SSH/shell logins and `esxcli`/`vim-cmd` used to enable SSH, change the firewall, stop logging, add accounts, and mass power-off or encrypt VMs.

## Data sources / telemetry
- **Guest Operations API (T1675 / DET0232):** `esxi:hostd` log (`/var/log/hostd.log`). Anomalous use of Guest Operations methods: **StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, InitiateFileTransferFromGuest/ToGuest**. vCenter VPXD events for `GuestOperations` likewise. (DC-mapping: Command Execution.)
- **Shell/CLI command history (T1059.012 / DET0558):** `/var/log/shell.log` records every ESXi Shell command whether run at the console or over SSH (Broadcom KB 321910). `esxcli` / `vim-cmd` invocations surface here.
- **Authentication:** `/var/log/auth.log` — SSH session/login events; correlate to shell.log entries by process/world ID (per Broadcom KB) to attribute a command to a user and client IP. `/var/log/hostd.log` also logs user auth and config changes.
- **Host state changes:** vmkernel (`/var/log/vmkernel.log`), firewall/syslog config changes, `Shell.SSH`/ESXi Shell service enablement, new local accounts, unusual `.vmdk` writes (encryption/impact).
- **Forwarding:** ESXi can syslog-forward all of the above to a SIEM — essential, since an attacker with host root can wipe local logs.

## Detection logic / approach
Per DET0232 (Guest Ops) and DET0558 (CLI abuse), baseline legitimate admin behaviour, then alert on deviation by frequency, identity, and timing:
- **Guest Operations misuse:** spikes in `StartProgramInGuest`/`InitiateFileTransfer*` in hostd.log, invocation by an unexpected service/management account, or guest-ops calls outside business hours / change windows. Program execution into many guests from one host = fan-out.
- **Host hardening tamper:** `esxcli network firewall set --enabled false`, enabling SSH/ESXi Shell, stopping/redirecting syslog, `esxcli system account add` / permission grants — all high-signal in shell.log.
- **SSH + shell correlation:** new `auth.log` SSH login from an unusual IP immediately followed by shell.log `esxcli`/`vim-cmd` from an interactive session.
- **Impact chain:** `vim-cmd vmsvc/power.off` across many VMs, or mass `.vmdk` modification, in a short window → ransomware staging.

Example Splunk (ESXi syslog) for shell/CLI abuse (per Splunk's ESXi-ransomware guidance):
```
index=esxi (source="*shell.log" OR sourcetype="esxi:shell")
  ("esxcli system account add" OR "network firewall set --enabled false"
   OR "system syslog" OR "vim-cmd vmsvc/power.off" OR "system settings advanced set*Shell*")
| stats values(_raw) count by host user
```
Guest-ops KQL/SPL: over `esxi:hostd`, match the Guest Operations method names above, summarize by host and initiating account, alert on rare account or out-of-hours calls. (ATT&CK ships no formal query for DET0232/DET0558 — baseline locally.)

## Response / mitigation
- Restrict Guest Operations permissions on ESXi-hosted VMs to accounts that need them (the ATT&CK-listed mitigation for T1675); use vCenter roles/least privilege.
- Keep ESXi in **lockdown mode**, SSH/ESXi Shell disabled by default, firewall restricted to management network; enable **execInstalledOnly** / secure boot; join to vCenter and enforce MFA on management.
- Forward all ESXi logs to immutable remote syslog/SIEM so host-root cannot erase the trail.
- Response: isolate the host from the management/storage network, preserve hostd/shell/auth logs, revoke compromised vCenter/ESXi creds, hunt other hosts via the same account, check for added accounts/backdoors and altered startup scripts.

## Real tools
VMware ESXi / vCenter (hostd, vpxd, syslog), PowerCLI and `govc` (admin tooling to baseline), Broadcom/VMware logging docs; Splunk (ESXi ransomware detections), Microsoft Sentinel/Elastic for syslog; vSphere lockdown mode, execInstalledOnly; EDR with ESXi support (e.g., CrowdStrike, Trellix) where available.

## Draft frontmatter mappings
- mitre_attack: [T1675, T1059.012, T1021.004]
- nist_csf: [DE.CM-09, DE.AE-02, DE.AE-03, PR.AA-05, PR.PS-01, PR.IR-01]
- suggested subdomain: endpoint-security
- nearest existing sibling (for the negative trigger): detecting-cloud-compute-infrastructure-tampering

## Draft description (<=1024 chars)
Detects adversary abuse of VMware ESXi administration interfaces after a hypervisor compromise: use of the Guest Operations API (StartProgramInGuest, InitiateFileTransferFromGuest) to execute in and move files into guest VMs (UNC3886-style), and hands-on-host esxcli/vim-cmd and SSH used to enable SSH, change the firewall, stop syslog, add accounts, and mass power-off/encrypt VMs ahead of ransomware. Correlates hostd Guest-Ops calls, shell.log command history, and auth.log SSH logins against an admin baseline by identity, frequency, and change window. Use when hunting ESXi/vSphere intrusion or triaging suspicious hypervisor activity. Keywords: T1675, ESXi, hostd.log, shell.log, auth.log, esxcli, vim-cmd, Guest Operations, vmtoolsd, lockdown mode, ESXi ransomware. Do not use for cloud IaaS compute-plane tampering (use detecting-cloud-compute-infrastructure-tampering) or generic Linux host intrusion logs (use analyzing-linux-audit-logs-for-intrusion).

## Key references
- https://attack.mitre.org/techniques/T1675/
- https://attack.mitre.org/detectionstrategies/DET0232 (verify id against v19.2)
- https://attack.mitre.org/detectionstrategies/DET0558 (T1059.012 Hypervisor CLI — verify)
- https://knowledge.broadcom.com/external/article/321910/auditing-esxi-shell-logins-and-commands.html
- https://www.splunk.com/en_us/blog/security/detecting-esxi-ransomware-activity-splunk

## Open questions / scope boundaries
- Verify DET0232/DET0558/AN0646 ids and the exact hostd event strings for Guest Operations and for "SSH enabled" against a current ESXi build (Broadcom sample logs are old).
- Decide whether to split T1675 (Guest Operations) from T1059.012 (esxcli/vim-cmd CLI) or cover both as one "ESXi administration abuse" skill — they share log sources and response, so one skill is defensible.
- Must NOT cover cloud IaaS snapshot/instance tampering (separate cloud skill) or in-guest OS log analysis; scope is the hypervisor host and its management plane.
