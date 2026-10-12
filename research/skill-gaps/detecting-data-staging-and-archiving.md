# Detecting Data Staging and Archiving — research notes

- **Proposed slug:** detecting-data-staging-and-archiving
- **ATT&CK:** T1560 Archive Collected Data (tactic: collection) — sub-techniques T1560.001 (Archive via Utility), T1560.002 (Archive via Library), T1560.003 (Archive via Custom Method); related: T1074 (Data Staged), T1020/T1041 (exfil follow-on)
- **Status:** research (not yet a skill)

## Defensive goal
Detect the pre-exfiltration step where an adversary compresses and/or encrypts collected data into archives in staging locations. The skill flags archive/compression utility execution (rar, 7z, makecab, zip, tar, Compress-Archive), library-based archiving, and large/encrypted file creation in temp/staging directories — catching the collection stage before data leaves, which is often the last cheap chance to intervene.

## Data sources / telemetry
- **Windows process creation:** Security Event ID 4688 and Sysmon Event ID 1 with command line — `rar.exe`/`winrar`, `7z.exe`/`7za.exe`, `makecab.exe`, `tar.exe`, `Compress-Archive` (PowerShell), plus password/encryption flags (`-hp`, `-p`, `-mhe`).
- **File creation / write:** Sysmon Event ID 11 (file create) for `.rar`/`.7z`/`.zip`/`.cab`/`.tar`/`.gz` and renamed/extensionless archives in `%TEMP%`, `C:\Users\Public`, `\PerfLogs`, recycle bin, or other staging dirs; file size growth.
- **Module load:** Sysmon Event ID 7 for compression/crypto DLLs loaded by unexpected processes (library-based archiving, T1560.002).
- **PowerShell:** Script Block Logging (Event ID 4104) for `Compress-Archive`, `System.IO.Compression`, `[Convert]` + encryption.
- **Linux/macOS:** auditd EXECVE for `zip`/`tar`/`gzip`/`7z`/`gpg`/`openssl enc`; macOS `ditto`/`hdiutil`/`zip` — flag invocation by Office apps, browsers, or background daemons.
- MITRE detection strategy DET0526: analytic AN1458 (Windows) correlates compression/encryption utility execution with subsequent large archive creation in temp/staging — log sources Security 4688, Sysmon 11, Sysmon 7; AN1460 (macOS) flags zip/ditto/hdiutil by unexpected parents. (verify IDs on live attack.mitre.org.)

## Detection logic / approach
- **Archive utility execution (Sigma process_creation):**
  ```
  selection_img: Image|endswith: ['\rar.exe','\7z.exe','\7za.exe','\makecab.exe','\tar.exe']
  selection_ps:  CommandLine|contains: 'Compress-Archive'
  selection_enc: CommandLine|contains: ['-hp','-p','-mhe','gpg','openssl enc']
  condition: (selection_img or selection_ps) # raise severity with selection_enc
  ```
- **Utility + large-file creation correlation (AN1458 logic):** within a short window, pair 4688/Sysmon 1 archive-tool execution with a Sysmon 11 creation of a large compressed/encrypted file in `%TEMP%`/staging; alert on the pair, not the tool alone.
- **Anomalous parent/location:** archive tool spawned by Office/browser/service, or archive written to Public/PerfLogs/recycle bin → high confidence (Splunk publishes "Windows Archived Collected Data In TEMP Folder" mapped to T1560, and a PowerShell variant via 4104).
- **Masquerraded archives:** detect files whose magic bytes = Rar!/PK/7z but with non-archive extensions (library/custom method evasion) — osquery/YARA on staging dirs.
- **Staging accumulation:** many files copied into one directory shortly before an archive is produced (ties to T1074).
- Baseline: backup jobs and dev build tooling legitimately compress — allowlist by path/account/parent.

## Response / mitigation
- Application control / allowlisting for archive utilities on servers; DLP watch on large encrypted archives in staging paths; honeyfiles in likely staging dirs. On detection: preserve and triage the archive (identify what was collected), block the imminent exfil channel, isolate host, and escalate — archiving usually means exfil is next.

## Real tools
Sysmon, Splunk (research.splunk.com cb56a1ea / 74c5a3b0), Sigma, YARA (archive magic bytes), osquery, auditd, EDR file-creation telemetry. (verify Splunk detection IDs.)

## Draft frontmatter mappings
- mitre_attack: [T1560, T1560.001, T1560.002, T1560.003, T1074.001]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, PR.DS-05, RS.MI-01]
- d3fend (optional): D3-FA (File Analysis), D3-PSA (Process Spawn Analysis), D3-FCA (File Content Analysis) — verify current D3FEND IDs
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): hunting-for-data-staging-before-exfiltration

## Draft description (<=1024 chars)
Detects data staging and archiving before exfiltration — execution of rar/7z/makecab/tar/zip/Compress-Archive (especially with encryption flags), library-based archiving via loaded compression/crypto DLLs, and creation of large/encrypted or magic-byte-masqueraded archives in temp/staging directories — by correlating archive-utility process creation (4688/Sysmon 1) with file creation (Sysmon 11). Use when hunting for the collection stage where an attacker compresses/encrypts data prior to exfil. Keywords: archive collected data, rar -hp, 7z, Compress-Archive, makecab, staging directory, encrypted archive, T1560. Do not use for detecting the outbound transfer itself - use hunting-for-data-staging-before-exfiltration for broad staging hunts or detecting-automated-data-exfiltration for the egress step.

## Key references
- https://attack.mitre.org/techniques/T1560/
- https://attack.mitre.org/detectionstrategies/DET0526
- https://research.splunk.com/endpoint/cb56a1ea-e0b1-46d5-913f-e024cba40cbe/
- https://research.splunk.com/endpoint/74c5a3b0-27a7-463c-9d00-1a5bb12cb7b5/

## Open questions / scope boundaries
- Overlaps strongly with existing hunting-for-data-staging-before-exfiltration; author must decide if this becomes a distinct detection-engineering skill (rules/Sigma) vs. a hunt, and sharpen the negative trigger accordingly.
- Must NOT cover the exfil transfer or offensive archiving. Decide depth of library/custom-method (T1560.002/.003) coverage, which is harder to detect than utility use. Confirm Splunk detection IDs.
