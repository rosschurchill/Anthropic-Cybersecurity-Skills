---
name: detecting-command-history-tampering
description: 'Detects adversaries disabling or neutralizing shell command-history logging to hide their activity (MITRE T1690) - unsetting or redirecting HISTFILE, zeroing HISTFILESIZE/HISTSIZE, HISTCONTROL=ignorespace, set +o history, or truncating/symlinking ~/.bash_history to /dev/null. Combines process/command-line detection (auditd execve, osquery, EDR) with anomaly logic that flags active interactive shells writing no expected history, and recommends tamper-resistant logging (auditd, pam_tty_audit) as the ground truth. Use when hunting Linux/macOS defense-evasion via history suppression or triaging history-tampering alerts. Keywords: command history tampering, HISTFILE, HISTCONTROL, HISTFILESIZE, set +o history, bash_history, /dev/null, chattr, auditd, T1690. Do not use for general Linux audit-log intrusion analysis - use analyzing-linux-audit-logs-for-intrusion.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- command-history
- defense-evasion
- linux
- auditd
- bash-history
- osquery
- t1690
- endpoint-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.PS-01
- PR.PS-04
mitre_attack:
- T1690
- T1070.003
- T1070
---

# Detecting Command History Tampering

## When to Use

Use this skill to detect when an adversary **disables or neutralizes shell
command-history logging** to hide the commands they run (ATT&CK T1690) —
unsetting/redirecting `HISTFILE`, zeroing `HISTFILESIZE`/`HISTSIZE`, abusing
`HISTCONTROL=ignorespace`, disabling the `history` builtin, or
truncating/clearing/symlinking history files. The skill catches both the
**tampering action itself** and the downstream **absence of expected history
writes** during an active session. Reach for it when:

- Hunting Linux/macOS defense-evasion.
- A history-tampering alert fires.
- An interactive session shows activity (auditd) but an empty/unchanged history.

This skill is Linux/macOS shell-focused. For general Linux audit-log intrusion
analysis use `analyzing-linux-audit-logs-for-intrusion`.

## Prerequisites

- **auditd** `SYSCALL`/`EXECVE` records, plus file watches on `~/.bash_history`,
  `~/.zsh_history`, `/etc/profile`, `/etc/bash.bashrc`, per-user `~/.bashrc`/
  `~/.zshrc`.
- **osquery** `process_events` (audit framework), `shell_history` and `file`
  tables on history paths; `process_envs` where available for
  `HISTFILE`/`HISTCONTROL`/`HISTFILESIZE` values.
- **EDR** command-line telemetry (Elastic Defend / Endgame).
- Ideally, **environment-variable capture** configured in auditd/osquery — the
  strongest signal depends on seeing the history variables.

## Workflow

1. **Action detection.** Alert on process/command lines that modify history:
   `unset HISTFILE`, `export HISTFILE=/dev/null`, `export HISTFILESIZE=0`,
   `export HISTSIZE=0`, `export HISTCONTROL=ignorespace|ignoreboth`,
   `set +o history`, `shopt -uo history`, `history -c`,
   `truncate -s0 ~/.bash_history`, `ln -sf /dev/null ~/.bash_history`,
   `rm ~/.bash_history`.
2. **Persistence watch.** Alert when the tampering is written into a profile/rc
   file (`~/.bashrc`, `/etc/profile`) so it recurs every session.
3. **State/anomaly detection (strongest).** Correlate a zeroed/redirected history
   variable with an **active interactive shell that subsequently writes no
   history entries** — activity in auditd/EDR but a silent history file.
4. **Tune the noisy strings.** `unset HISTFILE` and lone `history -c` are also
   used by admins/automation; pair them with env-var capture, parent process,
   user, and session context rather than alerting on the bare string.
5. **Respond** (see *Response*) — pivot to tamper-resistant logs for ground truth
   and review the full session process tree.

## Key Concepts

- **The history file is attacker-editable**, so it is never ground truth once
  tampering is suspected — auditd/`pam_tty_audit`/EDR are.
- **Two detection layers:** the action (a command that suppresses history) and
  the state (a session that should be writing history but isn't).
- **`ignorespace` abuse:** with `HISTCONTROL=ignorespace`, any command prefixed
  with a space is never recorded — subtle and worth flagging.
- **Prevention is strong here:** `readonly` history variables set system-wide and
  `chattr +a` on the history file remove most of the attack surface.

## Tools & Systems

auditd (`auditctl`, `ausearch`), osquery, Sysmon for Linux, Elastic Security
(Defend/Endgame), SigmaHQ, Splunk, Microsoft Sentinel, `pam_tty_audit`, `tlog`,
`chattr`.

## Detection Queries

### Sigma -- shell command-history tampering (Linux)

```yaml
title: Linux Command History Tampering
status: stable
logsource:
  product: linux
  category: process_creation
detection:
  sel_clear:
    CommandLine|contains:
      - 'history -c'
      - 'set +o history'
      - 'shopt -uo history'
  sel_var:
    CommandLine|contains:
      - 'HISTFILE=/dev/null'
      - 'HISTFILESIZE=0'
      - 'HISTSIZE=0'
      - 'HISTCONTROL=ignorespace'
      - 'unset HISTFILE'
  sel_file:
    CommandLine|contains: ['truncate -s0', '.bash_history', '.zsh_history']
  sel_fileact:
    CommandLine|contains: ['rm ', 'truncate', 'ln -sf /dev/null']
  condition: sel_clear or sel_var or (sel_file and sel_fileact)
falsepositives:
  - Administrators/automation clearing history intentionally
level: high
```

### osquery -- history variables and append-only flag

```sql
-- history-suppressing env values on running processes (where process_envs is available)
SELECT p.pid, p.name, e.key, e.value
FROM process_envs e JOIN processes p USING (pid)
WHERE e.key IN ('HISTFILE','HISTFILESIZE','HISTSIZE','HISTCONTROL')
  AND (e.value='/dev/null' OR e.value='0' OR e.value LIKE '%ignorespace%');
```

### auditd -- rules for history tampering

```
-w /root/.bash_history -p wa -k hist_tamper
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/truncate -k hist_tamper
-a always,exit -F arch=b64 -S execve -F exe=/bin/ln -k hist_tamper
-w /etc/profile -p wa -k hist_persist
```

## Common Scenarios

- **Session hiding:** attacker runs `export HISTFILE=/dev/null; set +o history`
  at the start of an interactive session — action detection + silent history.
- **Symlink trick:** `ln -sf /dev/null ~/.bash_history` makes all history vanish.
- **Persistent suppression:** `HISTSIZE=0` added to `~/.bashrc` suppresses history
  every login.
- **False positive:** an admin runs `history -c` to clear their own terminal —
  resolved by session/user/parent context.

## Output Format

```
HISTORY TAMPERING DETECTION
  Host/user:       <host> / <user>
  Verdict:         <confirmed | suspected | admin-benign>
  Method:          <HISTFILE=/dev/null | HISTSIZE=0 | set +o history | truncate/symlink | history -c>
  Persistence:     <written to ~/.bashrc or /etc/profile | session-only>
  State signal:    <active session, no history writes | n/a>
  Ground truth:    <commands recovered from auditd/pam_tty_audit>
  ATT&CK:          T1690[, T1070.003, T1070]
  Actions taken:   <history vars locked readonly | chattr +a | session tree reviewed>
```

## Response

- Lock history config (ATT&CK M1028): set `HISTCONTROL=ignoredups` (not
  `ignorespace`), `readonly HISTFILE HISTSIZE HISTFILESIZE HISTCONTROL` and
  `HISTTIMEFORMAT` system-wide in `/etc/profile.d/`, and make `~/.bash_history`
  append-only (`chattr +a`).
- Ship **authoritative command logging the user cannot edit** — auditd `execve`,
  `pam_tty_audit`, Sysmon-for-Linux, or a session recorder (`tlog`) forwarded to
  the SIEM (NIST CSF PR.PS-04) — so history tampering creates no blind spot.
- On a hit, **pivot to auditd/EDR, not the history file**, for ground truth and
  review the session's full process tree.
