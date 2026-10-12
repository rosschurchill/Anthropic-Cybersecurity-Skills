---
name: detecting-mercenary-mobile-spyware-with-mvt
description: 'Forensically detects targeted mercenary mobile spyware (Pegasus, Predator, Reign) delivered by exploitation for initial access (T1664), including zero-click client-execution exploits (T1658) and drive-by compromise (T1456), using the Mobile Verification Toolkit (MVT) against iOS backups and filesystem dumps or Android backups, matched to Amnesty and Citizen Lab STIX2 IOCs. MVT has no built-in sysdiagnose modules; Shutdown.log triage uses iShutdown. Parses DataUsage.sqlite, netusage.sqlite, Shutdown.log, Safari history, and iMessage artifacts, and applies the temporal-correlation attribution method. Victim-protective detection and response only. Use when triaging an at-risk device for state-grade spyware or responding to an Apple threat notification. Keywords: MVT, mvt-ios, Pegasus, Predator, STIX2 IOC, DataUsage.sqlite, Shutdown.log, sysdiagnose, Lockdown Mode, iOS, Android, T1664. Do not use for commercial full-device extraction and case forensics, use performing-mobile-device-forensics-with-cellebrite.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- ios
- android
- mercenary-spyware
- mvt
- forensics
- pegasus
- ioc
- t1664
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.AE-02
- DE.AE-03
- DE.CM-09
- PR.PS-02
mitre_attack:
- T1664
- T1658
- T1456
---

# Detecting Mercenary Mobile Spyware with MVT

## When to Use

Use this skill to **forensically detect targeted, exploit-delivered, state-grade
(mercenary) spyware** — Pegasus, Predator, Reign — on a specific device at risk,
using the **Mobile Verification Toolkit (MVT)** against device backups and dumps
with published IOCs. It covers ATT&CK T1664 Exploitation for Initial Access,
T1658 Exploitation for Client Execution (the zero-click case), and T1456
Drive-By Compromise. These chains are zero-click / one-click and leave few
on-device signals, so detection is **forensic triage of artifacts**, not
permission-grant or app-reputation analysis. Reach for it when:

- Triaging an at-risk person's device (journalist, activist, dissident) for
  state-grade spyware.
- Responding to an **Apple threat notification** or a credible targeting tip.

This skill is **victim-protective: detection and response only.** It never
describes how to build, deploy, configure, or operate spyware.

For fleet-scale permission-abusing stalkerware use
`detecting-mobile-surveillanceware`; for commercial evidentiary full-device
extraction and chain-of-custody imaging use
`performing-mobile-device-forensics-with-cellebrite`.

## Target safety (read first)

- **Preserve evidence before any change.** Take a full backup / sysdiagnose
  first; **do not wipe or reset first**, which destroys the artifacts MVT needs
  and the record a lab would review.
- Involve the device owner as the decision-maker and, for high-risk cases,
  engage expert help early (Citizen Lab, Amnesty International Security Lab,
  Access Now Digital Security Helpline).
- Absence of an IOC is **not proof of safety** — operators have modified
  implants to delete their own traces.

## Prerequisites

- **MVT (Mobile Verification Toolkit)**: `mvt-ios` and `mvt-android`.
- `libimobiledevice` (`idevicebackup2`, sysdiagnose retrieval) for iOS
  acquisition.
- A current STIX2 IOC bundle from the Amnesty International Security Lab / Citizen
  Lab feeds (for example Amnesty's `pegasus.stix2`). **IOC feeds change per
  campaign — always pull the live bundle from the maintained MVT IOC repo**
  rather than a cached copy.
- An isolated analysis workstation; store acquired backups as untrusted data in
  their own directory.
- Optional: Kaspersky `iShutdown` scripts for the `Shutdown.log` fast pass;
  iVerify for a complementary threat hunt.

## Workflow

1. **Acquire (evidence first).**
   - iOS: an **encrypted backup** (`idevicebackup2 backup --full`, encryption
     on), then `mvt-ios decrypt-backup`; a full-filesystem dump if lawfully
     available. These two are MVT's built-in IOC paths (`check-backup`,
     `check-fs`). A **sysdiagnose** archive is also worth retrieving, but MVT
     ships **no built-in sysdiagnose modules** — `mvt-ios check-sysdiagnose`
     only prepares the archive for custom modules, so sysdiagnose analysis means
     Kaspersky's `iShutdown` scripts (for `Shutdown.log`) or a custom MVT
     module, not MVT out of the box.
   - Android: `mvt-android check-backup` (an ADB backup) or
     `mvt-android check-adb`.
2. **Run MVT with the current IOC bundle.**
   ```bash
   mvt-ios check-backup --iocs pegasus.stix2 --output results/ <decrypted_backup>
   # filesystem dump:
   mvt-ios check-fs --iocs pegasus.stix2 --output results/ <fs_dump>
   ```
   MVT emits matched processes, domains, and files into the output directory.
3. **Fast first pass on `Shutdown.log`.** Triage the reboot-trace pattern
   (Kaspersky's 2024 method found Pegasus/Reign/Predator traces here, often
   referencing `/private/var/db/` process paths) as a quick check before a full
   backup scan.
4. **Review flagged domains** against the maintained Pegasus/Predator domain
   lists, and corroborate with the **temporal-correlation method** (Amnesty,
   Citizen Lab-reviewed): compare when an artifact first appears in the logs
   against when the device contacted a known spyware installation/C2 server.
5. **Weigh the artifacts.** Treat a single confirmed IOC on a plausible target
   as high-confidence and chase corroborating artifacts, rather than requiring
   many hits. Supporting indicators include anomalous process names in
   `DataUsage.sqlite` (iTunes backup) or `netusage.sqlite` (full filesystem),
   suspicious links/attachment metadata in SMS/iMessage, and repeated crashes in
   process names such as `com.apple.WebKit.WebContent`, `assertiond`, or
   `IMTransferAgent` —
   **verify these crash-process names against the originating public report
   before asserting them as indicators.**
6. **Respond** (see *Response*, and the safety note above).

## Key Concepts

- **Forensic, not behavioral.** The MTD / permission signal is weak for
  zero-click implants; the method is IOC matching against backups, not runtime
  permission analysis.
- **Temporal correlation is the attribution.** An artifact appearing right when
  the device contacted a known operator server is far stronger than the artifact
  alone.
- **Absence proves nothing.** Implants delete rows (NSO modified Pegasus around
  late-2019/early-2020 to incompletely remove `DataUsage.sqlite` rows) — a clean
  MVT run does not clear a credibly targeted device.
- **Single hit can be decisive.** On a plausible target, one solid IOC is high
  signal; corroborate rather than demand volume.

## Tools & Systems

MVT (`mvt-ios` / `mvt-android`); Amnesty International Security Lab and Citizen
Lab STIX2 IOC feeds; `libimobiledevice` (`idevicebackup2`, sysdiagnose
retrieval); Kaspersky `Shutdown.log` / `iShutdown` analysis scripts; iVerify;
Apple Lockdown Mode (preventive hardening).

## Detection Queries

Artifact names and paths change per campaign — treat them as current-as-of and
**verify** against the live reports/feeds.

### MVT — backup scan against the current IOC bundle

```bash
# Decrypt an encrypted iOS backup, then check it against Pegasus IOCs
# Supply the backup password with -p/--password (prompts if given no value),
# or export MVT_IOS_BACKUP_PASSWORD to keep it out of shell history.
# For a raw backup key use -k/--key-file instead (not combinable with -p).
MVT_IOS_BACKUP_PASSWORD='<backup password>' \
  mvt-ios decrypt-backup --destination decrypted/ <backup>
mvt-ios check-backup --iocs pegasus.stix2 --output results/ decrypted/
# Review results/ for matched processes, domains, and files.
```

### Shutdown.log fast pass (concept)

```text
# Inside the sysdiagnose archive. Look for a process that repeatedly delays
# shutdown and references suspicious paths (e.g. under /private/var/db/).
# Verify current trace patterns against the published method before relying on it.
```

### Temporal-correlation triage (concept)

```text
# For each flagged artifact: first-seen timestamp in device logs
#   vs. device network contact with a known spyware install/C2 host.
# A tight temporal overlap raises confidence from "IOC present" to "targeted".
```

## Common Scenarios

- **Apple threat notification:** the owner receives an Apple targeting alert; an
  encrypted backup is acquired and MVT matches a Pegasus domain plus a
  temporally correlated process.
- **Zero-click iMessage chain:** suspicious attachment metadata and repeated
  WebKit/IMTransferAgent crashes corroborate a confirmed IOC.
- **Android check:** `mvt-android check-adb` flags a known Predator package /
  domain.
- **Clean-but-not-clear:** MVT returns no hits on a credibly targeted device —
  recorded as inconclusive, not safe, and escalated to a specialist lab.

## Output Format

```text
MERCENARY SPYWARE FORENSIC TRIAGE
  Device:          <device id / owner>
  Platform:        <iOS | Android>
  Acquisition:     <encrypted backup | sysdiagnose | filesystem dump | ADB>
  Verdict:         <confirmed IOC match | suspicious | inconclusive (not cleared)>
  Family:          <Pegasus | Predator | Reign | unknown>
  Artifacts:       <matched domains / processes / files; Shutdown.log trace>
  Correlation:     <temporal overlap with known operator server? y/n>
  IOC bundle:      <source + date pulled>
  ATT&CK:          T1664, T1658, T1456
  Evidence:        <full backup/sysdiagnose preserved before any change>
  Actions taken:   <Lockdown Mode | OS update | device migration | expert referral>
```

## Response

- **Evidence first.** Preserve the full backup / sysdiagnose before any
  remediation; do not wipe first.
- **Harden the target.** Enable iOS **Lockdown Mode**, update to the latest OS
  (closes the exploited chain), and consider migrating the target to a new
  device and number.
- **Escalate.** Engage Citizen Lab, Amnesty International Security Lab, or the
  Access Now Digital Security Helpline for confirmation and support.
- **Preventive for high-risk users.** Lockdown Mode by default, aggressive
  patching, periodic reboots (disrupts non-persistent implants), and minimizing
  attack surface (iMessage/link hygiene).
