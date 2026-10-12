# Detecting Firmware Corruption Attacks — research notes

- **Proposed slug:** detecting-firmware-corruption-attacks
- **ATT&CK:** T1495 Firmware Corruption (tactic: impact) — no sub-techniques; closely related to T1542 Pre-OS Boot (System Firmware T1542.001) and T1601 Modify System Image
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to adversaries who overwrite, corrupt, or brick firmware —
system BIOS/UEFI (SPI flash), network-card firmware, drive/HBA firmware, or
embedded/router/IoT firmware — to deny availability or render devices
permanently inoperable. The skill catches the privileged flash-utility
execution, the raw writes to firmware device paths, and the pre/post boot
integrity drift that mark a corruption attempt, so defenders can block or
quarantine before a device is bricked.

## Data sources / telemetry
- **Process creation — Windows Security 4688 / Sysmon EID 1** — execution of
  firmware flashing utilities with elevated privileges: vendor flashers
  (`afuwin`, `afudos`, `fpt.exe`/Intel Flash Programming Tool, `winflash`,
  `Dell/HP/Lenovo BIOS update exe`), `flashrom`, `chipsec_util`, `ethtool -f`
  (NIC firmware), `nvme` fw-download/commit, `fwupdmgr`/`fwupd`.
- **Sysmon EID 6 (DriverLoad)** — low-level flash access drivers (RWEverything
  `RwDrv.sys`, `chipsec` driver, vendor SPI drivers).
- **Linux auditd** — writes/opens to `/dev/mem`, `/dev/port`, `/sys/firmware/*`,
  `/sys/class/mtd/*`, `/dev/mtd*`, and execve of `flashrom`, `mtd_debug`,
  `dd of=/dev/mtd*`.
- **Firmware integrity / boot telemetry** — TPM PCR values (PCR 0–7 measure
  firmware/boot), Windows Measured Boot log, Device Health Attestation,
  Microsoft Defender System Guard / firmware attestation events, UEFI Secure
  Boot violation events, vendor BMC/iDRAC/iLO logs for out-of-band flash.
- **Baseline comparisons** — periodic CHIPSEC/`fwupd` dumps compared to a
  golden image; SPI flash region write-protect status.

## Detection logic / approach
MITRE detection strategy DET0167 (AN0474 Windows / AN0475 Linux): correlate a
firmware-flash utility run with elevated privileges + raw access to a firmware
device path or boot-configuration change.

Windows analytic (spirit):
```
EventCode IN (4688, 1)  AND
ImageFile|endswith IN (afuwin.exe, fpt.exe, flashrom.exe, chipsec_util.exe, winflash.exe, RwDrv*)
AND elevated_token = true
-> enrich with Sysmon EID 6 driver load of RwDrv.sys / chipsec within window
```
Linux analytic: `auditd` execve of `flashrom`/`mtd_debug` OR write syscall where
`path` matches `/dev/mem|/sys/firmware|/dev/mtd`, from a non-maintenance context.

Strongest signal is *integrity drift*: schedule CHIPSEC modules
(`chipsec_main -m common.bios_wp`, `-m common.spi_lock`, firmware dump + diff)
and compare TPM PCR0-7 / Measured Boot logs against a known-good baseline;
alert on unexpected change outside an approved vendor update window. Pair with
Secure Boot DBX/dbx-change monitoring and BMC audit logs for out-of-band
flashing that never touches the OS.

## Response / mitigation
Isolate and remove affected hardware from service; firmware corruption is often
unrecoverable without hardware reflash/replacement. Restrict privileged accounts
and driver loading (M1047 Audit, least privilege). Enable and enforce SPI flash
write-protect, BIOS password, Secure Boot, Intel BootGuard/BIOS Guard, and
vendor firmware signing. Keep firmware patched (M1051) and verify integrity of
existing firmware for modifiability. Maintain out-of-band recovery images and
BMC access controls.

## Real tools
CHIPSEC (chipsec_util / chipsec_main), fwupd/`fwupdmgr`, Microsoft Defender
System Guard & Device Health Attestation, UEFITool, flashrom (defensive dump),
`tpm2-tools` (PCR read), vendor BMC/iLO/iDRAC consoles, Eclypsium (firmware
security platform), binwalk (reference/sibling tooling).

## Draft frontmatter mappings
- mitre_attack: [T1495, T1542.001, T1601.001, T1601.002]
- nist_csf: [DE.CM-01, DE.CM-09, ID.AM-02, PR.PS-02, RS.MI-01]
- d3fend (optional): D3-FBA (Firmware Behavior Analysis), D3-FEMC (Firmware Embedded Monitoring Code), D3-SBV (System Boot Verification)
- suggested subdomain: incident-response
- nearest existing sibling (for the negative trigger): auditing-uefi-firmware-with-chipsec

## Draft description (<=1024 chars)
Detects firmware corruption attacks — privileged flash-utility execution, raw
writes to SPI/BIOS/UEFI, NIC and drive firmware, and pre/post-boot integrity
drift — using process-creation and driver-load events, auditd writes to
/dev/mem and /sys/firmware, TPM PCR/Measured Boot baselines, and CHIPSEC
integrity checks. Catches attempts to brick or corrupt firmware for destructive
impact (ATT&CK T1495). Use when triaging suspected firmware tampering,
unexplained bricked devices, or alerts on flashrom/chipsec/fpt execution, or
when building firmware-integrity monitoring. Keywords: firmware corruption,
BIOS, UEFI, SPI flash, flashrom, CHIPSEC, bricking, TPM PCR, Measured Boot,
T1495. Do not use for routine UEFI configuration auditing/assessment — use
auditing-uefi-firmware-with-chipsec.

## Key references
- MITRE ATT&CK T1495 + detection strategy DET0167: https://attack.mitre.org/techniques/T1495/ , https://attack.mitre.org/mitigations/T1495/
- CHIPSEC project: https://github.com/chipsec/chipsec
- fwupd / LVFS: https://github.com/fwupd/fwupd
- Microsoft Secured-core / System Guard firmware protection docs (verify current URL): https://learn.microsoft.com/
- CISA firmware security guidance (verify): https://www.cisa.gov/

## Open questions / scope boundaries
- ATT&CK v18 (Oct 2025) deprecated the old "Firmware: Firmware Modification"
  (DS0001) data source into data components — confirm current mapping before
  authoring.
- Clarify boundary vs T1542 Pre-OS Boot (persistence/implant) and T1601 Modify
  System Image (network devices) — this skill is the *destructive/corruption*
  angle, not implant persistence.
- Decide coverage of network-device (Cisco/Juniper) firmware vs host firmware;
  may warrant a reference file rather than inline. Must NOT include any
  offensive flashing procedures.
