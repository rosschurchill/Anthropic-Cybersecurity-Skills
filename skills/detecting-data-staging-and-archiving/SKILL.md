---
name: detecting-data-staging-and-archiving
description: 'Detects data staging and archiving before exfiltration (MITRE T1560) - execution of rar/7z/makecab/tar/zip/Compress-Archive (especially with encryption flags like -hp/-mhe), library-based archiving via loaded compression/crypto DLLs, and creation of large, encrypted, or magic-byte-masqueraded archives in temp/staging directories - by correlating archive-utility process creation (Event ID 4688/Sysmon 1) with file creation (Sysmon 11) in a short window. Use when hunting the collection stage where an attacker compresses/encrypts data prior to exfil, often the last cheap chance to intervene. Keywords: archive collected data, rar -hp, 7z, Compress-Archive, makecab, staging directory, encrypted archive, Sysmon Event ID 11, T1560. Do not use for detecting the outbound transfer itself - use detecting-automated-data-exfiltration.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- data-staging
- archive-collected-data
- collection
- rar
- 7zip
- sysmon
- t1560
- exfiltration
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- PR.DS-01
- RS.MI-01
mitre_attack:
- T1560
- T1560.001
- T1560.002
- T1560.003
- T1074.001
---

# Detecting Data Staging and Archiving

## When to Use

Use this skill to detect the **pre-exfiltration step** where an adversary
compresses and/or encrypts collected data into archives in staging locations
(ATT&CK T1560). It flags archive/compression utility execution (rar, 7z,
makecab, zip, tar, `Compress-Archive`), library-based archiving, and large or
encrypted file creation in temp/staging directories — catching the **collection
stage before data leaves**, which is often the last cheap chance to intervene.
Reach for it when:

- Archive tools run in an unexpected context or with encryption flags.
- Large `.rar`/`.7z`/`.zip` (or extensionless) files appear in `%TEMP%`,
  `C:\Users\Public`, `\PerfLogs`, or the recycle bin.

For the **outbound transfer** that follows, use
`detecting-automated-data-exfiltration`.

## Prerequisites

- **Windows process creation**: Security Event ID 4688 and Sysmon Event ID 1
  (command line).
- **File creation**: Sysmon Event ID 11 for `.rar`/`.7z`/`.zip`/`.cab`/`.tar`/
  `.gz` and renamed/extensionless archives in staging dirs; file-size growth.
- **Module load**: Sysmon Event ID 7 for compression/crypto DLLs (library-based
  archiving).
- **PowerShell** Script Block Logging (4104) for `Compress-Archive` /
  `System.IO.Compression`.
- **Linux/macOS**: `auditd` EXECVE for `zip`/`tar`/`gzip`/`7z`/`gpg`/
  `openssl enc`, macOS `ditto`/`hdiutil`.
- A **baseline**: backup jobs and dev build tooling legitimately compress —
  allowlist by path/account/parent.

## Workflow

1. **Baseline legitimate archiving** (backup agents, build pipelines) by path,
   account, and parent process.
2. **Archive-utility execution.** Alert on `rar`/`7z`/`makecab`/`tar`/
   `Compress-Archive`; **raise severity** with encryption flags (`-hp`, `-p`,
   `-mhe`, `gpg`, `openssl enc`).
3. **Utility + large-file correlation (the key rule).** Within a short window,
   pair archive-tool execution (4688/Sysmon 1) with a Sysmon 11 creation of a
   large compressed/encrypted file in `%TEMP%`/staging — alert on the **pair**,
   not the tool alone.
4. **Anomalous parent/location.** Archive tool spawned by Office/browser/service,
   or an archive written to Public/PerfLogs/recycle bin → high confidence.
5. **Masqueraded archives.** Detect files whose magic bytes are `Rar!`/`PK`/`7z`
   but with non-archive extensions (library/custom method, .002/.003) via
   osquery/YARA on staging dirs.
6. **Staging accumulation.** Many files copied into one directory just before an
   archive is produced (ties to T1074.001).
7. **Respond** (see *Response*) — archiving usually means exfil is next.

## Key Concepts

- **The pair is the signal:** an archive tool alone is noisy; archive tool **plus**
  a large encrypted file appearing in a staging dir is the collection stage.
- **Encryption flags raise confidence:** `rar -hp` / `7z -mhe` password-protect
  the archive to defeat DLP content inspection — a strong intent indicator.
- **Location tells intent:** Public, PerfLogs, and the recycle bin are classic
  staging dirs no business process writes archives to.
- **Last cheap intervention:** catching staging stops the breach before data
  egresses, when response is far cheaper.

## Tools & Systems

Sysmon, Splunk, Sigma, YARA (archive magic bytes), osquery, `auditd`, EDR
file-creation telemetry.

## Detection Queries

### Sigma -- archive utility with encryption in a staging path

```yaml
title: Data Archiving for Staging (possible pre-exfil)
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith: ['\rar.exe','\7z.exe','\7za.exe','\makecab.exe','\tar.exe']
  selection_ps:
    CommandLine|contains: 'Compress-Archive'
  selection_enc:
    CommandLine|contains: ['-hp','-mhe',' -p',' gpg ','openssl enc']
  condition: (selection_img or selection_ps)   # escalate when selection_enc also matches
falsepositives:
  - Backup and build tooling
level: medium
```

### Splunk -- utility + large archive in TEMP correlation (AN1458 logic)

```spl
`sysmon` EventCode=1 (Image="*\\rar.exe" OR Image="*\\7z.exe" OR CommandLine="*Compress-Archive*")
| eval toolTime=_time
| join Computer [ search `sysmon` EventCode=11 (TargetFilename="*\\Temp\\*" OR TargetFilename="*\\Public\\*")
                   (TargetFilename="*.rar" OR TargetFilename="*.7z" OR TargetFilename="*.zip")
                 | eval fileTime=_time, archive=TargetFilename ]
| where fileTime>=toolTime AND (fileTime-toolTime) < 300
| table _time, Computer, Image, CommandLine, archive
```

### YARA -- magic-byte archive with wrong extension (staging scan)

```
rule masqueraded_archive {
  strings:
    $rar = { 52 61 72 21 1A 07 }   // Rar!
    $zip = { 50 4B 03 04 }         // PK..
    $sz  = { 37 7A BC AF 27 1C }   // 7z
  condition:
    ($rar at 0 or $zip at 0 or $sz at 0)
      and not filename matches /\.(rar|zip|7z|cab|tar|gz)$/i
}
```

## Common Scenarios

- **Password-protected RAR:** `rar a -hp<pass> C:\Users\Public\x.rar <loot>` —
  tool + large file in Public fires.
- **Library archiving:** malware uses `System.IO.Compression` directly (no tool)
  — caught by Sysmon 7 DLL load + file create.
- **Masquerade:** archive saved as `update.dat` — YARA magic-byte scan catches it.
- **False positive:** nightly backup archiving to its own directory —
  allowlisted.

## Output Format

```
DATA STAGING / ARCHIVING DETECTION
  Host/user:       <host> / <account>
  Verdict:         <confirmed | suspected | approved-backup/build>
  Method:          <rar/7z/makecab/tar | Compress-Archive | library | masqueraded>
  Encryption:      <password/-hp/-mhe | none>
  Archive:         <path/size> in <staging dir>
  Parent:          <parent process> (expected: <y/n>)
  ATT&CK:          T1560(.001-.003)[, T1074.001]
  Actions taken:   <archive preserved/triaged | exfil channel blocked | host isolated>
```

## Response

- **Application control / allowlisting** for archive utilities on servers; DLP
  watch on large encrypted archives in staging paths; deploy **honeyfiles** in
  likely staging dirs (NIST CSF PR.DS-01).
- **On detection:** preserve and triage the archive (identify what was
  collected), block the imminent exfil channel, isolate the host, and escalate —
  archiving usually means exfil is next.
