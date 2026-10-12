# Detecting Disk Wipe and Destruction — research notes

- **Proposed slug:** detecting-disk-wipe-and-destruction
- **ATT&CK:** T1561 Disk Wipe (tactic: impact) — plus sub-techniques T1561.001 Disk Content Wipe and T1561.002 Disk Structure Wipe
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to destructive wiper activity that overwrites raw disks,
boot sectors, the MBR/GPT partition table, or the MFT to render systems
unbootable or data unrecoverable. The skill catches the moment a process opens
a raw physical device handle and writes to it, installs a raw-disk driver to
gain that access, or issues destructive OS commands — the behavior shared by
HermeticWiper, CaddyWiper, WhisperGate/BFG Agonizer, DEADWOOD, Shamoon-style
wipers, and NotPetya's bootlocker. Early detection buys time to isolate hosts
and protect backups before the wipe spreads via lateral movement.

## Data sources / telemetry
- **Sysmon Event ID 9 (RawAccessRead)** — process opening a raw handle to
  `\\.\PhysicalDrive0`, `\\.\HarddiskVolumeN`, `\Device\Harddisk*`. This is the
  single strongest primitive for wipers that bypass the filesystem.
- **Sysmon Event ID 1 / Windows Security 4688 (process creation + command line)**
  — look for `\\.\PhysicalDrive`, `\\.\HarddiskVolume`, and destructive
  LOLBins: `diskpart clean all`, `format`, `cipher /w`, `fsutil`, `wevtutil cl`,
  `vssadmin delete shadows`, `wmic shadowcopy delete`, `fdisk`, `dd of=/dev/sd*`,
  `shred`, `wipefs`, `blkdiscard`, `mkfs`.
- **Sysmon Event ID 6 (DriverLoad)** — third-party raw-disk drivers that give
  usermode raw write access (e.g. EaseUS/ElRawDisk `RawDisk`, used by Shamoon
  and HermeticWiper; `empntdrv.sys`). Correlate with new/unsigned or
  recently-dropped `.sys` files.
- **Windows Security 4673** — SeLoadDriverPrivilege / sensitive privilege use
  preceding a driver load.
- **Linux auditd** — `openat`/`write` to `/dev/sd*`, `/dev/nvme*`, `/dev/mapper/*`
  and execution of `dd`, `shred`, `wipefs`, `blkdiscard`; execve records.
- **EDR file/registry telemetry** — bulk file overwrites, VSS deletion,
  bootloader/BCD modification (`bcdedit /set`, `bootsectors`).

## Detection logic / approach
Primary analytic (MITRE DET0137 / DET0316 / DET0297 pattern): raw physical-drive
access + write to boot-sector sector range + new raw-disk driver load, from a
non-allowlisted process.

Splunk Security Content ships a published analytic ("Windows Raw Access to Disk
Volume Partition" / boot-sector read-write) mapped to T1561.002 keyed on Sysmon
EID 9, excluding `System32`/`SysWOW64` system processes. Sigma `process_creation`
rules match command lines containing `\\.\PhysicalDrive` or `\\.\HarddiskVolume`
with write/lock verbs.

Illustrative Sigma (spirit, tune before use):
```yaml
title: Raw Disk Access by Non-System Process (possible wiper)
logsource: {product: windows, category: raw_access_read}  # Sysmon EID 9
detection:
  sel:
    Device|contains: ['\Device\Harddisk', '\Device\HarddiskVolume']
  filter_sys:
    Image|startswith: ['C:\Windows\System32\', 'C:\Windows\SysWOW64\']
  condition: sel and not filter_sys
falsepositives: [disk imaging/backup tools, defrag, AV, EaseUS/Acronis]
level: high
```
Correlate EID 9 within a short window of a fresh EID 6 driver load and VSS
deletion. Allowlist known backup/imaging tools (Acronis, Veeam, EaseUS, dd for
forensic imaging) by signed-image path. HermeticWiper-specific: SOC Prime /
vendor Sigma keys on the RawDisk driver install rather than the raw I/O, so run
both as complementary coverage.

## Response / mitigation
Isolate the host from the network immediately (wipers propagate). Protect and
air-gap backups; verify immutable/offline backup copies exist (M1053 Data
Backup). Enforce least privilege so unprivileged users cannot load drivers or
open raw devices; application control (WDAC/AppLocker) to block unsigned
raw-disk drivers. Snapshot volatile memory before shutdown for IR. Do NOT
reboot a suspected-wiped host — boot-sector damage often manifests only on
reboot.

## Real tools
Sysmon, Splunk Security Content (research.splunk.com), Sigma / SigmaHQ,
Microsoft Defender for Endpoint, Velociraptor, auditd/auditbeat, osquery.
Forensic/recovery: TestDisk, PhotoRec, `dd`/`dcfldd` for imaging (defensive).

## Draft frontmatter mappings
- mitre_attack: [T1561, T1561.001, T1561.002, T1485, T1490]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, RS.MI-01, PR.DS-11]
- d3fend (optional): D3-FAPA (File Access Pattern Analysis), D3-PM (Process Monitoring), D3-DENCR adjacent backup integrity
- suggested subdomain: incident-response
- nearest existing sibling (for the negative trigger): detecting-ransomware-encryption-behavior

## Draft description (<=1024 chars)
Detects destructive disk-wipe activity — raw writes to physical drives, boot
sector/MBR/partition-table overwrites, MFT destruction, and raw-disk driver
installs — using Sysmon RawAccessRead (EID 9), process-creation command lines,
and driver-load events, correlated in Splunk/Sigma. Catches HermeticWiper,
CaddyWiper, WhisperGate, Shamoon-style and NotPetya bootlocker behavior before
a reboot makes hosts unbootable. Use when triaging a suspected destructive
attack, unexplained unbootable systems, or raw-disk-access alerts, or when
hardening against ATT&CK T1561. Keywords: disk wipe, wiper malware,
HermeticWiper, boot sector, MBR, partition table, RawAccessRead, PhysicalDrive,
T1561, destructive attack. Do not use for file-encrypting ransomware behavior —
use detecting-ransomware-encryption-behavior.

## Key references
- MITRE ATT&CK T1561 and detection strategies DET0137, DET0316, DET0297:
  https://attack.mitre.org/techniques/T1561/ , https://attack.mitre.org/techniques/T1561/002/
- Splunk Security Content (raw access to disk / boot sector): https://research.splunk.com/
- SigmaHQ rules: https://github.com/SigmaHQ/sigma
- CISA/FBI HermeticWiper & destructive-malware advisories (verify current URLs): https://www.cisa.gov/
- BlackBerry / SOC Prime HermeticWiper analyses (RawDisk driver indicator)

## Open questions / scope boundaries
- Verify Sysmon EID 9 captures the *writes* defenders care about vs. only reads
  in the target environment; some wipers use `DeviceIoControl` not plain write.
- Decide whether VSS/shadow-copy deletion and bootloader tampering belong here
  or in a ransomware/Inhibit System Recovery (T1490) skill — avoid overlap.
- Must NOT cover offensive wiping procedures or recovery of specific wiped
  samples beyond general IR triage. Confirm Linux coverage scope (auditd rules).
