---
name: hunting-for-startup-folder-persistence
description: Detects T1547.001 startup folder persistence by monitoring Windows startup directories
  for suspicious file creation, cross-referencing Autoruns entries, and running a Python watchdog
  script for real-time filesystem monitoring. Use when hunting for malware or implants that survive
  reboot via startup-folder placement, or when validating autoruns/EDR findings against known-good
  startup baselines. Do not use for Run/RunOnce registry autostart persistence - use hunting-for-registry-run-key-persistence.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- T1547.001
- startup-folder
- persistence
- autoruns
- watchdog
- filesystem-monitoring
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1547
---

# Hunting for Startup Folder Persistence

## Overview

Attackers use Windows startup folders for persistence (MITRE ATT&CK T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder). Files placed in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` execute automatically at user logon. This skill scans startup directories for suspicious files, monitors for real-time changes using Python watchdog, and analyzes file metadata to detect persistence implants.


## When to Use

- Use when hunting malware or implants that survive reboot via placement in the user or all-users Startup folder (T1547.001).
- Use when scanning `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` and the ProgramData equivalent for suspicious extensions (.bat, .vbs, .ps1, .lnk, .exe).
- Use when flagging recently created startup files (< 7 days) and unsigned binaries as candidate implants.
- Use when monitoring startup directories in real time with a Python watchdog handler during an active investigation.
- Use when validating Autoruns/EDR findings against a known-good startup baseline.

## Prerequisites

- Python 3.9+ with `watchdog`, `pefile` (optional for PE analysis)
- Access to Windows startup folders (user and all-users)
- Windows Event Logs for Event ID 4663 correlation (optional)

## Steps

1. Enumerate all files in user and system startup directories
2. Analyze file types, creation timestamps, and digital signatures
3. Flag suspicious file extensions (.bat, .vbs, .ps1, .lnk, .exe)
4. Check for recently created files (< 7 days) as potential implants
5. Monitor startup folders in real-time using watchdog FileSystemEventHandler
6. Correlate with known legitimate startup entries
7. Generate threat hunting report with T1547.001 MITRE mapping

## Example

Enumerate both startup folders and flag suspicious or recently created entries:

```python
import os
import time

STARTUP_DIRS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
]
SUSPICIOUS_EXT = {".bat", ".vbs", ".ps1", ".js", ".lnk", ".exe", ".scr", ".cmd"}
RECENT_DAYS = 7
now = time.time()

for d in STARTUP_DIRS:
    if not os.path.isdir(d):
        continue
    for entry in os.scandir(d):
        if not entry.is_file():
            continue
        ext = os.path.splitext(entry.name)[1].lower()
        age_days = (now - entry.stat().st_ctime) / 86400
        reasons = []
        if ext in SUSPICIOUS_EXT:
            reasons.append(f"ext={ext}")
        if age_days < RECENT_DAYS:
            reasons.append(f"created {age_days:.1f}d ago")
        if reasons:
            print(f"[SUSPECT] {entry.path}  ({', '.join(reasons)})")
```

For real-time detection, wrap the same checks in a `watchdog.events.FileSystemEventHandler`
and schedule an observer on each startup directory.

## Expected Output

- JSON report listing all startup folder contents with risk scores, file metadata, and suspicious indicators
- Real-time monitoring alerts for new file creation in startup directories
