---
name: detecting-disk-wipe-and-destruction
description: 'Detects destructive disk-wipe activity (MITRE T1561) - raw writes to physical drives, boot sector/MBR/partition-table overwrites, MFT destruction, and raw-disk driver installs - using Sysmon RawAccessRead (Event ID 9), process-creation command lines, and driver-load events correlated in Splunk, Sigma and KQL. Catches HermeticWiper, CaddyWiper, WhisperGate, Shamoon-style and NotPetya bootlocker behavior before a reboot makes hosts unbootable. Use when triaging a suspected destructive attack, investigating unexplained unbootable systems, responding to raw-disk-access alerts, or hardening against ATT&CK T1561. Keywords: disk wipe, wiper malware, HermeticWiper, CaddyWiper, boot sector, MBR, partition table, RawAccessRead, PhysicalDrive, Sysmon Event ID 9, T1561, destructive attack. Do not use for file-encrypting ransomware behavior - use detecting-ransomware-encryption-behavior.'
domain: cybersecurity
subdomain: incident-response
tags:
- incident-response
- threat-detection
- disk-wipe
- wiper-malware
- destructive-attack
- sysmon
- hermeticwiper
- mbr
- boot-sector
- t1561
- windows
- dfir
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- RS.MI-01
- PR.DS-11
mitre_attack:
- T1561
- T1561.001
- T1561.002
- T1485
- T1490
---

# Detecting Disk Wipe and Destruction

## When to Use

Use this skill to detect and respond to **destructive wiper activity** that
overwrites raw disks, boot sectors, the MBR/GPT partition table, or the MFT to
render systems unbootable and data unrecoverable. This is the behavior shared by
HermeticWiper, CaddyWiper, WhisperGate, DEADWOOD, Shamoon-style wipers, and
NotPetya's bootlocker. Reach for it when:

- An EDR or SIEM alert fires on raw physical-drive access.
- Hosts become unexplainedly unbootable, or users report mass data loss.
- You are threat-hunting during a suspected destructive intrusion and need to
  catch the wipe **before** it spreads via lateral movement.

Wipers do their damage in seconds and the result often only manifests on reboot,
so the detection value is in catching the raw write **as it happens**.

## Prerequisites

- Sysmon deployed with a config that logs **Event ID 9 (RawAccessRead)**,
  **Event ID 1 (ProcessCreate)** and **Event ID 6 (DriverLoad)**. The stock
  SwiftOnSecurity config logs 9 and 6; confirm RawAccessRead is not filtered out.
- Windows Security auditing for process creation (**Event ID 4688**) with
  command-line logging enabled, and sensitive-privilege use (**4673**).
- For Linux hosts: `auditd` with rules on `/dev/sd*`, `/dev/nvme*`, `/dev/mapper/*`
  and execve of destructive utilities.
- A SIEM (Splunk, Microsoft Sentinel, Elastic) ingesting the above.

## Workflow

1. **Baseline the legitimate raw-disk actors.** Backup/imaging and disk tools
   (Acronis, Veeam, EaseUS, `dd` for forensic imaging, defrag, AV) legitimately
   open raw handles. Build an allowlist keyed on **signed image path**, not
   filename, so a masquerading binary cannot inherit the exemption.
2. **Hunt the primary primitive — raw physical-drive access.** Query Sysmon
   Event ID 9 for writes/handles to `\\.\PhysicalDrive*`, `\\.\HarddiskVolume*`,
   `\Device\Harddisk*` from any process outside `System32`/`SysWOW64` and the
   allowlist. See the Splunk/KQL/Sigma queries below.
3. **Hunt destructive command lines.** Query Event ID 1 / 4688 for the
   destructive LOLBins and utilities listed under *Key Concepts*.
4. **Hunt raw-disk driver installs.** Query Event ID 6 for third-party raw-disk
   drivers (`RawDisk`/ElRawDisk, `empntdrv.sys`) — HermeticWiper and Shamoon
   install one to get usermode raw write access. Correlate with a recently
   dropped or unsigned `.sys` file.
5. **Correlate into a high-confidence signal.** The strongest detection is raw
   access (EID 9) **within a short window** of a fresh driver load (EID 6) and/or
   shadow-copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`).
   Any one alone is medium; together they are high.
6. **Respond immediately** (see *Response*). Treat a true positive as an active,
   spreading incident.

## Key Concepts

- **Raw device access** bypasses the filesystem. A process that opens
  `\\.\PhysicalDrive0` and writes to the first sectors is overwriting the MBR/GPT
  and boot code directly — there is almost no benign reason for a non-system,
  non-backup process to do this.
- **Destructive utilities / LOLBins to watch:** `diskpart clean all`, `format`,
  `cipher /w`, `fsutil`, `fdisk`, `bcdedit /set`, `wevtutil cl`,
  `vssadmin delete shadows`, `wmic shadowcopy delete`; on Linux `dd of=/dev/sd*`,
  `shred`, `wipefs`, `blkdiscard`, `mkfs`.
- **Driver-based wipers:** ElRawDisk/`RawDisk` (Shamoon, HermeticWiper) and
  similar signed-but-abused drivers provide the raw write path. The driver load
  is often a more reliable indicator than the I/O itself.
- **Sub-techniques:** T1561.001 (Disk Content Wipe) overwrites data;
  T1561.002 (Disk Structure Wipe) targets the boot sector / partition table.
  Wipers frequently pair with T1490 (Inhibit System Recovery) and T1485 (Data
  Destruction).

## Tools & Systems

Sysmon, Splunk Security Content (research.splunk.com), Sigma / SigmaHQ,
Microsoft Defender for Endpoint, Microsoft Sentinel, Elastic Security,
Velociraptor, `auditd`/`auditbeat`, osquery. For post-incident forensic imaging
and recovery (defensive): TestDisk, PhotoRec, `dd`/`dcfldd`.

## Detection Queries

### Splunk -- raw physical-drive access by a non-system process (Sysmon EID 9)

```spl
`sysmon` EventCode=9
Device IN ("\\Device\\Harddisk*", "\\Device\\HarddiskVolume*")
NOT (Image IN ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*"))
NOT (Image IN ("C:\\Program Files\\Acronis\\*", "C:\\Program Files\\Veeam\\*"))
| stats count min(_time) as firstTime max(_time) as lastTime
    by Computer, Image, ProcessGuid, Device
| `security_content_ctime(firstTime)`
```

### KQL -- Microsoft Sentinel / Defender: raw disk access + destructive command line

```kql
let rawAccess = Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 9
| extend d = parse_xml(EventData)
| where tostring(d.Device) has_any ("\\Device\\Harddisk", "HarddiskVolume")
| where tostring(d.Image) !startswith "C:\\Windows\\System32\\"
| project TimeGenerated, Computer, Image = tostring(d.Image), ProcessGuid = tostring(d.ProcessGuid);
let destructive = DeviceProcessEvents
| where ProcessCommandLine has_any
    ("\\\\.\\PhysicalDrive","diskpart","clean all","vssadmin delete shadows",
     "wmic shadowcopy delete","cipher /w","bcdedit /set");
rawAccess
| join kind=leftouter destructive on $left.Computer == $right.DeviceName
| project TimeGenerated, Computer, Image, ProcessGuid, ProcessCommandLine
```

### Sigma -- raw disk access by non-system process (tune before use)

```yaml
title: Raw Disk Access by Non-System Process (possible wiper)
status: experimental
logsource:
  product: windows
  category: raw_access_read   # Sysmon Event ID 9
detection:
  selection:
    Device|contains:
      - '\Device\Harddisk'
      - '\Device\HarddiskVolume'
  filter_system:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  filter_backup:
    Image|contains:
      - '\Acronis\'
      - '\Veeam\'
      - '\EaseUS\'
  condition: selection and not 1 of filter_*
falsepositives:
  - Disk imaging, backup and defrag tools
  - Antivirus deep scans
level: high
```

### Linux -- auditd rules for raw block-device writes

```
-a always,exit -F arch=b64 -S openat -F dir=/dev -F perm=w -k raw_disk_write
-w /usr/bin/dd -p x -k disk_destroy
-w /usr/sbin/wipefs -p x -k disk_destroy
-w /usr/sbin/blkdiscard -p x -k disk_destroy
```

## Common Scenarios

- **HermeticWiper:** drops and loads the ElRawDisk driver, then corrupts the MBR
  and partitions. Driver load (EID 6) + raw access (EID 9) fire together.
- **CaddyWiper / WhisperGate:** overwrite the MBR and files directly; catch via
  raw access and mass file overwrite plus boot-record modification.
- **Insider `diskpart clean all` / `cipher /w`:** destructive command line on
  EID 1 / 4688 from an interactive session off-hours.
- **False positive:** a backup agent doing a bare-metal image — resolved by the
  signed-path allowlist.

## Output Format

```
WIPER DETECTION
  Host:            <computer>
  Verdict:         <confirmed | suspected | false-positive>
  Primitive(s):    [raw-access EID9 | destructive-cmdline | driver-load EID6 | VSS-delete]
  Process:         <image> (ProcessGuid <guid>), parent <parent>
  Target device:   <\Device\HarddiskVolumeN>
  ATT&CK:          T1561(.001/.002)[, T1490, T1485]
  First seen:      <timestamp>
  Spread risk:     <isolated | lateral-movement observed>
  Actions taken:   <host isolated | backups verified | memory captured>
```

## Response

- **Isolate the host from the network immediately** — wipers propagate.
- **Protect and verify backups**: confirm immutable/offline copies exist before
  the wipe reaches them (NIST CSF PR.DS-11; ATT&CK mitigation M1053).
- **Do NOT reboot** a suspected-wiped host — boot-sector damage often only
  manifests on reboot; capture volatile memory first for IR.
- Enforce least privilege and application control (WDAC/AppLocker) so
  unprivileged users cannot load drivers or open raw devices.
