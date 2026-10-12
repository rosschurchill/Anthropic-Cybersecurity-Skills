---
name: analyzing-persistence-mechanisms-in-linux
description: Scan Linux systems for persistence mechanisms including crontab/systemd
  entries, LD_PRELOAD injection, shell profile modifications (.bashrc, .profile),
  and SSH authorized_keys backdoors, then correlate findings with auditd logs into
  an installation timeline. Use during incident response or threat hunting to detect
  or confirm how an adversary maintained access to a compromised Linux host. Do not
  use for broad Linux system-artifact forensics - use analyzing-linux-system-artifacts.
domain: cybersecurity
subdomain: threat-hunting
tags:
- linux-persistence
- crontab
- systemd
- ld-preload
- auditd
- threat-hunting
- incident-response
mitre_attack:
- T1053.003
- T1543.002
- T1574.006
- T1546.004
- T1098.004
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Process Termination
- Content Format Conversion
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Analyzing Persistence Mechanisms in Linux

## Overview

Adversaries establish persistence on Linux systems through crontab jobs, systemd service/timer units, LD_PRELOAD library injection, shell profile modifications (.bashrc, .profile), SSH authorized_keys backdoors, and init script manipulation. This skill scans for all known persistence vectors, checks file timestamps and integrity, and correlates findings with auditd logs to build a timeline of persistence installation.


## When to Use

- Use during Linux incident response to enumerate persistence across crontabs, /etc/cron.d, systemd service/timer units, and init scripts on a live host or forensic image.
- Use when checking /etc/ld.so.preload and the LD_PRELOAD environment variable for injected shared libraries.
- Use when inspecting shell profiles (.bashrc, .bash_profile, .profile, /etc/profile.d/) for injected commands or reverse shells.
- Use when auditing SSH authorized_keys files for unauthorized public keys or backdoor command restrictions.
- Use when correlating persistence file modifications against auditd logs to build an installation timeline.

## Prerequisites

- Root or sudo access on target Linux system (or forensic image)
- auditd configured with file watch rules on persistence paths
- Python 3.8+ with standard library (os, subprocess, json)
- Optional: OSSEC/Wazuh agent for file integrity monitoring alerts

## Steps

1. **Scan Crontab Entries** — Enumerate all user crontabs, /etc/cron.d/, /etc/cron.daily/, and anacron jobs for suspicious commands
2. **Audit Systemd Units** — Check /etc/systemd/system/ and ~/.config/systemd/user/ for non-package-managed service and timer units
3. **Detect LD_PRELOAD Hijacking** — Check /etc/ld.so.preload and LD_PRELOAD environment variable for injected shared libraries
4. **Inspect Shell Profiles** — Scan .bashrc, .bash_profile, .profile, /etc/profile.d/ for injected commands or reverse shells
5. **Check SSH Authorized Keys** — Audit all authorized_keys files for unauthorized public keys with command restrictions
6. **Correlate Auditd Logs** — Search auditd logs for file modification events on persistence paths to build an installation timeline
7. **Generate Persistence Report** — Produce a risk-scored report of all discovered persistence mechanisms

## Expected Output

- JSON report of all persistence mechanisms found with risk scores
- Timeline of persistence installation from auditd correlation
- MITRE ATT&CK technique mapping (T1053, T1543, T1574, T1546)
- Remediation commands for each detected persistence mechanism

## Example

Sweep the primary Linux persistence vectors listed in the steps above and correlate with auditd:

```bash
#!/usr/bin/env bash
# Enumerate common Linux persistence mechanisms on a live host.
set -u

echo "=== [T1053.003] Cron jobs ==="
for u in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$u" 2>/dev/null | grep -v '^\s*#' | sed "s/^/  [$u] /"
done
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
cat /etc/crontab 2>/dev/null

echo "=== [T1543.002] Non-package systemd units ==="
for unit in /etc/systemd/system/*.service ~/.config/systemd/user/*.service; do
    [ -f "$unit" ] || continue
    echo "  $unit"
    grep -E '^ExecStart=' "$unit"
done

echo "=== [T1574.006] LD_PRELOAD hijacking ==="
cat /etc/ld.so.preload 2>/dev/null && echo "  (!) /etc/ld.so.preload is populated"
env | grep -i ld_preload

echo "=== [T1546.004] Shell profile injection ==="
grep -REn 'bash -i|/dev/tcp/|nc |curl |wget ' \
    /etc/profile /etc/profile.d/ /root/.bashrc /home/*/.bashrc /home/*/.profile 2>/dev/null

echo "=== [T1098.004] SSH authorized_keys ==="
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] && echo "  $f:" && cat "$f"
done

echo "=== auditd timeline (persistence paths) ==="
ausearch -f /etc/crontab -f /etc/ld.so.preload -f /etc/systemd/system 2>/dev/null \
    | grep -E 'type=PATH|type=SYSCALL' | tail -n 40
```
