---
name: detecting-firmware-corruption-attacks
description: 'Detects firmware corruption attacks (MITRE T1495) - privileged flash-utility execution, raw writes to SPI/BIOS/UEFI, NIC and drive firmware, and pre/post-boot integrity drift - using process-creation and driver-load events, auditd writes to /dev/mem and /sys/firmware, TPM PCR/Measured Boot baselines, and CHIPSEC integrity checks. Catches attempts to brick or corrupt firmware for destructive impact. Use when triaging suspected firmware tampering, investigating unexplained bricked devices, responding to alerts on flashrom/chipsec/fpt execution, or building firmware-integrity monitoring. Keywords: firmware corruption, BIOS, UEFI, SPI flash, flashrom, CHIPSEC, bricking, TPM PCR, Measured Boot, RwDrv.sys, T1495. Do not use for routine UEFI configuration auditing and assessment - use auditing-uefi-firmware-with-chipsec.'
domain: cybersecurity
subdomain: incident-response
tags:
- incident-response
- threat-detection
- firmware-security
- uefi
- bios
- spi-flash
- chipsec
- destructive-attack
- tpm
- t1495
- measured-boot
- dfir
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- ID.AM-02
- PR.PS-02
- RS.MI-01
mitre_attack:
- T1495
- T1542.001
- T1601.001
- T1601.002
---

# Detecting Firmware Corruption Attacks

## When to Use

Use this skill to detect and respond to adversaries who **overwrite, corrupt, or
brick firmware** — system BIOS/UEFI (SPI flash), network-card firmware, drive/HBA
firmware, or embedded/router firmware — to deny availability or render devices
permanently inoperable (ATT&CK T1495). Reach for it when:

- An alert fires on execution of a firmware flashing utility (`flashrom`,
  `chipsec_util`, `fpt.exe`, `afuwin`) or a low-level flash driver load.
- Devices become unexplainedly bricked or fail Secure Boot / attestation.
- You are hardening a fleet with firmware-integrity monitoring and need the
  detection logic.

This is the **destructive / corruption** angle. For firmware *implant persistence*
investigation use a Pre-OS Boot skill; for routine configuration auditing use
`auditing-uefi-firmware-with-chipsec`.

## Prerequisites

- Process-creation logging: **Windows Security 4688** (with command line) or
  **Sysmon Event ID 1**, plus **Sysmon Event ID 6 (DriverLoad)**.
- Elevated-token / privilege context available on process events.
- Linux `auditd` with rules on `/dev/mem`, `/dev/port`, `/sys/firmware/*`,
  `/dev/mtd*` and execve of flash utilities.
- Firmware/boot integrity telemetry: TPM PCR reads, Windows Measured Boot log,
  Defender System Guard / firmware attestation, Secure Boot violation events,
  BMC/iDRAC/iLO logs for out-of-band flashing.
- A known-good firmware/PCR **baseline** to diff against.

## Workflow

1. **Establish the approved-update context.** Firmware is legitimately flashed
   during vendor BIOS updates and `fwupd` runs. Record approved maintenance
   windows and the signed vendor updater paths so routine updates do not alarm.
2. **Hunt privileged flash-utility execution.** Query process events for the
   firmware utilities listed under *Key Concepts*, where the token is elevated
   and the context is not an approved update window.
3. **Hunt low-level flash driver loads.** Query Sysmon EID 6 for `RwDrv.sys`
   (RWEverything), the CHIPSEC driver, and vendor SPI drivers — correlate with a
   recently dropped or unsigned `.sys`.
4. **Hunt raw firmware-path writes (Linux).** Query `auditd` for writes/opens to
   `/dev/mem`, `/sys/firmware/*`, `/dev/mtd*` and execve of `flashrom`,
   `mtd_debug`, `dd of=/dev/mtd*`.
5. **Detect integrity drift (strongest signal).** Compare scheduled CHIPSEC
   firmware dumps and TPM **PCR 0-7** / Measured Boot logs against the known-good
   baseline; alert on any change outside an approved update window. Monitor
   Secure Boot **dbx** changes and BMC audit logs for out-of-band flashes that
   never touch the OS.
6. **Respond** (see *Response*) — treat confirmed corruption as potentially
   unrecoverable and isolate the hardware.

## Key Concepts

- **Firmware-flash utilities to watch:** vendor flashers (`afuwin`, `afudos`,
  `fpt.exe`/Intel FPT, `winflash`, Dell/HP/Lenovo BIOS update exe), `flashrom`,
  `chipsec_util`, `ethtool -f` (NIC firmware), `nvme fw-download`/`fw-commit`,
  `fwupdmgr`/`fwupd`.
- **Low-level access drivers:** `RwDrv.sys` (RWEverything), the CHIPSEC driver,
  vendor SPI drivers — these grant the raw flash access an attacker needs.
- **Integrity anchors:** TPM PCRs 0-7 measure firmware and boot components;
  unexpected PCR changes outside a vendor update are a high-fidelity signal.
  SPI flash **write-protect** status and Intel BootGuard/BIOS Guard enforce
  hardware-level protection.
- **Related techniques:** T1542.001 (System Firmware, Pre-OS Boot — persistence)
  and T1601 (Modify System Image — network devices). This skill is scoped to
  **corruption for destructive impact**.

## Tools & Systems

CHIPSEC (`chipsec_util`, `chipsec_main`), `fwupd`/`fwupdmgr`, Microsoft Defender
System Guard & Device Health Attestation, UEFITool, `tpm2-tools` (PCR read),
vendor BMC/iLO/iDRAC consoles, Eclypsium, flashrom (defensive dump only).

## Detection Queries

### Splunk -- privileged firmware-flash utility execution

```spl
(`sysmon` EventCode=1) OR (`wineventlog_security` EventCode=4688)
| eval img=lower(coalesce(Image, New_Process_Name))
| where match(img, "(afuwin|afudos|fpt\.exe|winflash|flashrom|chipsec_util|nvme)")
    OR match(CommandLine, "(?i)(ethtool\s+-f|fw-download|fw-commit)")
| stats count min(_time) as firstTime by Computer, img, CommandLine, ParentImage, user
| `security_content_ctime(firstTime)`
```

### Sigma -- low-level flash driver load (tune before use)

```yaml
title: Low-Level Firmware Flash Driver Load
status: experimental
logsource:
  product: windows
  category: driver_load   # Sysmon Event ID 6
detection:
  selection:
    ImageLoaded|endswith:
      - '\RwDrv.sys'
      - '\chipsec_hlpr.sys'
  filter_signed_vendor:
    Signature|contains:
      - 'Dell'
      - 'Hewlett'
      - 'Lenovo'
  condition: selection and not filter_signed_vendor
falsepositives:
  - Legitimate vendor BIOS update utilities during maintenance
level: high
```

### Linux -- auditd rules for firmware-path writes

```
-a always,exit -F arch=b64 -S openat -F path=/dev/mem -F perm=w -k firmware_write
-w /sys/firmware -p wa -k firmware_write
-w /usr/sbin/flashrom -p x -k firmware_flash
-w /usr/sbin/mtd_debug -p x -k firmware_flash
```

### TPM / Measured Boot integrity drift (concept)

```
# Read PCR 0-7 and compare to golden baseline (tpm2-tools)
tpm2_pcrread sha256:0,1,2,3,4,5,6,7 > /var/lib/fwmon/pcr.current
diff /var/lib/fwmon/pcr.golden /var/lib/fwmon/pcr.current \
  && echo "PCR MATCH" || echo "ALERT: firmware/boot integrity drift"
```

## Common Scenarios

- **Destructive flash:** attacker runs `chipsec_util spi write` or `flashrom -w`
  with a corrupt image after loading `RwDrv.sys` — driver load + utility exec fire
  together outside any update window.
- **NIC/drive firmware corruption:** `ethtool -f` or `nvme fw-commit` with a bad
  image on a server — caught on process events.
- **Out-of-band flash:** BMC/iLO used to reflash with no OS process — caught only
  by BMC audit logs and PCR drift.
- **False positive:** scheduled vendor BIOS update — resolved by update-window
  and signed-path context.

## Output Format

```
FIRMWARE CORRUPTION DETECTION
  Host:            <computer>
  Verdict:         <confirmed | suspected | approved-update>
  Primitive(s):    [flash-utility-exec | flash-driver-load | /dev/mem write | PCR-drift | BMC-flash]
  Process/driver:  <image or .sys> (elevated: <y/n>), parent <parent>
  Firmware target: <SPI/BIOS | NIC | NVMe | BMC>
  Integrity:       <PCR match | drift on PCR n | Secure Boot dbx change>
  ATT&CK:          T1495[, T1542.001, T1601.x]
  Actions taken:   <hardware isolated | baseline captured | vendor engaged>
```

## Response

- **Isolate and remove affected hardware** from service; firmware corruption is
  often unrecoverable without hardware reflash or replacement. Engage the vendor.
- Enforce **SPI flash write-protect**, BIOS password, Secure Boot, Intel
  BootGuard/BIOS Guard, and vendor firmware signing (preventive).
- Restrict privileged accounts and **driver loading** (least privilege, WDAC) so
  flash utilities and low-level drivers cannot run unapproved.
- Keep firmware patched and maintain **out-of-band recovery images** and tight
  BMC access controls.
