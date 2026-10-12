# Detecting Command History Tampering — research notes

- **Proposed slug:** detecting-command-history-tampering
- **ATT&CK:** T1690 Prevent Command History Logging (tactic: defense-evasion / in ATT&CK v19 under Defense Impairment TA0112) — successor to **T1562.003 Impair Command History Logging**. Related: T1070 Indicator Removal, T1070.003 Clear Command History, T1562 Impair Defenses.
- **Status:** research (not yet a skill)

> ID note: the catalogue should map to both T1690 (v19 name "Prevent Command History Logging") and its predecessor T1562.003 ("Impair Command History Logging"). Verify the exact v19 ID/name against the official April-2026 release notes, since third-party sources still use T1562.003. Published MITRE detection strategy for the predecessor is **DET0563** (analytics AN1555–AN1559, dated 2025-10-21).

## Defensive goal
Detect when an adversary disables or neutralizes shell command-history logging to hide the commands they run — unsetting/redirecting `HISTFILE`, zeroing `HISTFILESIZE`/`HISTSIZE`, abusing `HISTCONTROL=ignorespace`, disabling the shell `history` builtin, or truncating/clearing history files. The skill catches the *tampering action itself* and the downstream *absence of expected history writes* during an active session.

## Data sources / telemetry
- **auditd** `SYSCALL`/`EXECVE` records for commands that modify history variables: `unset HISTFILE`, `export HISTFILE=/dev/null`, `export HISTFILESIZE=0`, `export HISTCONTROL=ignorespace`/`ignoreboth`, `set +o history`, `shopt -uo history`, `history -c`, `truncate -s0 ~/.bash_history`, `ln -sf /dev/null ~/.bash_history`, `rm ~/.bash_history`.
- **auditd file watches** on `~/.bash_history`, `/etc/profile`, `/etc/bash.bashrc`, per-user `~/.bashrc`/`~/.bash_profile`/`~/.zshrc` (persistence of the tampering).
- **osquery** — `process_events` (needs audit framework) capturing `cmdline` and, where configured, environment; `shell_history` table (collects recent history) and `file` table on history paths; `process_envs` (Linux, verify availability) for HISTFILE/HISTCONTROL/HISTFILESIZE values.
- **EDR process telemetry** — Elastic Defend / Endgame command-line events (Elastic prebuilt "Tampering of Shell Command-Line History", Linux + macOS).
- Environment-variable capture is the hard part: osquery/auditd must be configured to record env (`HISTSIZE/HISTFILESIZE/HISTCONTROL/HISTFILE`) for the strongest signal.

## Detection logic / approach
SigmaHQ `lnx_shell_clear_cmd_history` (Linux Command History Tampering, high severity) matches command lines including:
```
' shopt -uo history'
'truncate -s0 *sh_history'   # covers ~/.bash_history, ~/.zsh_history
'rm *bash_history', 'rm *zsh_history'
'ln -sf /dev/null *bash_history'
'export HISTFILE=/dev/null' / 'unset HISTFILE'  # NOTE: unset HISTFILE is COMMENTED OUT upstream (too noisy)
```
Practical build (per MITRE DET0563/AN1555 + Crafted Signal brief):
1. **Action detection** — auditd/osquery process events matching the patterns above, PLUS `set +o history`, `export HISTFILESIZE=0`, `export HISTSIZE=0`, `HISTCONTROL=ignorespace`.
2. **State/anomaly detection** — correlate a zeroed/redirected history variable with an *active interactive shell session* that subsequently writes **no** history entries. AN1555's core logic: "correlate unset or zeroed history variables with active shell sessions" and watch for "absence of expected bash history writes."
3. **Tune** `unset HISTFILE` and lone `history -c` with context (parent process, user, session) — admins and automation legitimately do these, so pair with env-var capture rather than alerting on the bare string.

Example Sigma-style skeleton:
```
logsource: product: linux, category: process_creation
detection:
  sel_clear: CommandLine|contains: ['history -c','set +o history','shopt -uo history']
  sel_var:   CommandLine|contains: ['HISTFILE=/dev/null','HISTFILESIZE=0','HISTSIZE=0','HISTCONTROL=ignorespace','unset HISTFILE']
  sel_file:  CommandLine|contains: ['truncate -s0','.bash_history','.zsh_history']
  condition: sel_clear or sel_var or (sel_file and CommandLine|contains: ['rm ','truncate','ln -sf /dev/null'])
```

## Response / mitigation
- **M1039 Environment Variable Permissions / M1028 Operating System Configuration:** set and lock `HISTCONTROL=ignoredups` (avoid `ignorespace`/`ignoreboth`), set `readonly HISTFILE HISTSIZE HISTFILESIZE HISTCONTROL` and `HISTTIMEFORMAT` system-wide in `/etc/profile.d/`, make `~/.bash_history` append-only (`chattr +a`).
- Ship authoritative command logging that the user cannot edit: auditd `execve`, `pam_tty_audit`, Sysmon-for-Linux, or a session recorder (`tlog`, `auditd` + SIEM) so history-file tampering does not create a blind spot.
- Response: on a hit, pivot to auditd/EDR (not the history file) for ground truth; review the session's full process tree.

## Real tools
auditd (`auditctl`, `ausearch`), osquery, Sysmon for Linux, Elastic Security (Defend/Endgame), SigmaHQ, Splunk, Microsoft Sentinel, `pam_tty_audit`, `tlog`, `chattr`.

## Draft frontmatter mappings
- mitre_attack: [T1690, T1562.003, T1070.003, T1070, T1562]
- nist_csf: [DE.CM-09, DE.AE-02, PR.PS-01, PR.PS-04, DE.CM-01]
- d3fend (optional): D3-UGLPA (User Geolocation/Logon Pattern) n/a; better: D3-PSA (Process Spawn Analysis), D3-SFA — verify exact ids
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): analyzing-linux-audit-logs-for-intrusion

## Draft description (<=1024 chars)
Detects adversaries disabling or neutralizing shell command-history logging to hide their activity — unsetting or redirecting HISTFILE, zeroing HISTFILESIZE/HISTSIZE, HISTCONTROL=ignorespace, set +o history, or truncating/symlinking ~/.bash_history to /dev/null. Combines process/command-line detection (auditd execve, osquery, EDR) with anomaly logic that flags active shells writing no expected history, and recommends tamper-resistant logging as the ground truth. Use when hunting Linux/macOS defense-evasion via history suppression or triaging history-tampering alerts. Keywords: command history tampering, HISTFILE, HISTCONTROL, HISTFILESIZE, set +o history, bash_history, /dev/null, auditd, T1690, T1562.003. Do not use for Windows PowerShell/console history (use a Windows evasion skill); for general Linux audit-log intrusion analysis use analyzing-linux-audit-logs-for-intrusion.

## Key references
- https://attack.mitre.org/techniques/T1562/003 (predecessor; check v19 for T1690)
- https://attack.mitre.org/detectionstrategies/DET0563
- https://detection.fyi/sigmahq/sigma/linux/builtin/lnx_shell_clear_cmd_history
- https://www.elastic.co/guide/en/security/current/tampering-of-shell-command-line-history.html
- https://www.picussecurity.com/resource/blog/t1562-impair-command-history-logging
- https://feed.craftedsignal.io/briefs/2024-01-linux-shell-history-clearing/

## Open questions / scope boundaries
- Confirm the exact v19 technique ID/name (T1690 vs T1562.003) from the official release notes.
- Verify osquery `process_envs` availability and the auditd config needed to capture environment variables on the target distro (without it, the "state" detection degrades to command-line only).
- Decide whether macOS zsh and Windows console/PowerShell history belong here or in sibling skills — recommend keeping this Linux/macOS shell-focused.
- Must NOT cover clearing Windows event logs or general indicator removal (T1070.001) — that is a separate skill.
