# Detecting Mercenary Mobile Spyware with MVT — research notes

- **Proposed slug:** detecting-mercenary-mobile-spyware-with-mvt
- **ATT&CK (Mobile):** T1664 Exploitation for Initial Access (tactic: initial-access) — plus T1658 Exploitation for Client Execution, T1456 Drive-By Compromise. Detection strategy: **DET0666**; mitigation **M1058** (detect/alert when a device is vulnerable to a known exploit). Example: Pegasus for iOS (**S0289**, NSO Group) delivered via zero-click iMessage exploits; related families Predator and Reign.
- **Status:** research (not yet a skill)

## Defensive goal
Forensically detect **targeted, exploit-delivered, state-grade (mercenary) spyware** — Pegasus, Predator, Reign — on a specific device at risk, using the Mobile Verification Toolkit (MVT) against device backups/dumps with published IOCs. These are zero-click / one-click exploit chains that leave few on-device signals, so detection is **forensic triage of artifacts**, not permission-grant or app-reputation analysis. This is the correct skill for a high-risk-individual device check, distinct from fleet surveillanceware detection.

## Data sources / telemetry
- **MVT (Mobile Verification Toolkit):** `mvt-ios` and `mvt-android`. Inputs: encrypted/decrypted iTunes/Finder iOS backup, iOS full filesystem dump, iOS sysdiagnose, or Android backup/ADB. Matches artifacts against Amnesty/Citizen Lab **STIX2 IOC** files (e.g. Amnesty's `pegasus.stix2`).
- **iOS artifacts MVT parses:** `DataUsage.sqlite` (present in an iTunes backup) and `netusage.sqlite` (full-filesystem only) for anomalous process names; Safari history/favicons; SMS/iMessage with suspicious links and attachment metadata; `Shutdown.log` (inside the sysdiagnose archive; Kaspersky's 2024 method found Pegasus/Reign/Predator traces here, often referencing `/private/var/db/` paths); configuration/webkit/datausage caches.
- **Attribution signal (Amnesty method, Citizen Lab–reviewed):** temporal correlation between an artifact's first appearance in logs and the device's communication with a known spyware installation/C2 server. Note: NSO modified Pegasus ~late-2019/early-2020 to (incompletely) delete `DataUsage.sqlite` rows — absence is not proof of safety.
- **Supporting:** iOS crash logs (repeated crashes in `com.apple.WebKit`, `assertiond`, IMTransferAgent as exploit indicators — *verify per published reports*), DataUsage network byte counts, iVerify-style threat hunts.

## Detection logic / approach
Per DET0666 / M1058 the on-device MTD signal is weak, so rely on forensic IOC matching:
1. Acquire: iOS → encrypted backup (`idevicebackup2`/Finder) then `mvt-ios decrypt-backup`, or sysdiagnose; Android → `mvt-android check-backup` / `check-adb`.
2. Run MVT with the current STIX2 IOC bundle: `mvt-ios check-backup --iocs pegasus.stix2 <backup>` (and `check-fs` for filesystem dumps). MVT emits matched processes, domains, and files.
3. Manually review flagged domains against the maintained Pegasus/Predator domain lists and corroborate with the temporal-correlation method (artifact appearance vs. known-server contact).
4. Triage `Shutdown.log` for the Kaspersky-documented reboot-trace pattern as a fast first pass before a full MVT backup scan.
5. Treat any single confirmed IOC on a plausible target as high-confidence; chase corroborating artifacts rather than requiring many hits.

## Response / mitigation
- Preserve evidence (full backup/sysdiagnose) before any change; do not wipe first.
- Enable iOS **Lockdown Mode**, update to the latest OS (closes the exploited chain), consider migrating the target to a new device/number.
- Engage expert help: Citizen Lab, Amnesty Security Lab, Access Now Digital Security Helpline.
- Preventive for high-risk users: Lockdown Mode by default, aggressive patching, periodic reboots (disrupts non-persistent implants), minimize attack surface (iMessage/link hygiene).

## Real tools
MVT (Mobile Verification Toolkit) `mvt-ios` / `mvt-android`; Amnesty International Security Lab & Citizen Lab STIX2 IOC feeds; `libimobiledevice` (`idevicebackup2`, sysdiagnose retrieval); Kaspersky `Shutdown.log` / `iShutdown` analysis scripts; iVerify; Apple Lockdown Mode (mitigation).

## Draft frontmatter mappings
- mitre_attack: [T1664, T1658, T1456]
- nist_csf: [DE.AE-02, DE.AE-03, DE.CM-09, PR.PS-02]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): performing-mobile-device-forensics-with-cellebrite

## Draft description (<=1024 chars)
Forensically detects targeted mercenary mobile spyware (Pegasus, Predator, Reign) delivered by exploitation for initial access (T1664), including zero-click client-execution exploits (T1658) and drive-by compromise (T1456), using the Mobile Verification Toolkit (MVT) against iOS backups, filesystem dumps, and sysdiagnose, or Android backups, matched to Amnesty and Citizen Lab STIX2 IOCs. Parses DataUsage.sqlite, netusage.sqlite, Shutdown.log, Safari history, and iMessage artifacts, and applies the temporal-correlation attribution method. Use when triaging a high-risk individual's phone for state-grade spyware or responding to an Apple threat-notification. Keywords: MVT, mvt-ios, Pegasus, Predator, STIX2 IOC, DataUsage.sqlite, Shutdown.log, sysdiagnose, Lockdown Mode, T1664, DET0666. Do not use for commercial full-device extraction and case forensics, use performing-mobile-device-forensics-with-cellebrite.

## Key references
- https://attack.mitre.org/techniques/T1664/
- https://attack.mitre.org/detectionstrategies/DET0666/
- https://attack.mitre.org/software/S0289/ (Pegasus for iOS)
- https://github.com/mvt-project/mvt (Mobile Verification Toolkit)
- https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/ (Amnesty forensic methodology; Citizen Lab peer review)

## Open questions / scope boundaries
- IOC feeds and `Shutdown.log` crash/process indicators change per campaign and are being actively evaded (anti-forensics, row deletion) — author must point at the live MVT IOC repo and treat named artifacts as current-as-of, flagged "verify".
- Verify the specific crash-process names (WebKit/assertiond/IMTransferAgent) against the originating public report before asserting them as indicators.
- Must NOT be reframed as permission/app-reputation analysis (that is detecting-mobile-surveillanceware) — the whole point is forensic, exploit-delivered detection.
- Distinct from commercial court-forensics extraction (performing-mobile-device-forensics-with-cellebrite); MVT here is a defensive IOC triage, not evidentiary chain-of-custody imaging.
