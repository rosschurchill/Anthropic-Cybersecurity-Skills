# Detecting Mobile Security-Control Tampering — research notes

- **Proposed slug:** detecting-mobile-security-control-tampering
- **ATT&CK (Mobile):** T1629 Impair Defenses (tactic: defense-evasion; incl. T1629.001 Prevent Application Removal, T1629.002 Device Lockout, T1629.003 Disable or Modify Tools) — plus folded/related: T1630 Indicator Removal on Host (incl. T1630.001 Uninstall Malicious Application, T1630.002 File Deletion, T1630.003 Disguise Root/Jailbreak Indicators), T1628 Hide Artifacts (incl. T1628.001 Suppress Application Icon, T1628.002 User Evasion)
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries disabling or evading mobile defences so other activity goes
unseen: turning off Google Play Protect, killing/uninstalling or blocking
uninstall of the MTD agent, abusing the device-administration API to resist
removal or lock the user out (T1629), clearing/altering artifacts and disguising
root/jailbreak status (T1630), and hiding the app — suppressing its launcher
icon or evading the user while active (T1628). The defensive premise: tamper and
agent-health signals are often the *last* reliable signal before telemetry goes
dark, so their absence/change must itself alert.

## Data sources / telemetry
- **MTD agent-health / tamper signals** (Lookout, Zimperium zIPS, Microsoft
  Defender for Endpoint mobile, Wandera): explicit uninstall-attempt and
  tamper/kill alerts, last-check-in heartbeat, and a *missing heartbeat* as a
  detection in its own right.
- **MDM/UEM compliance + device-admin state** (Intune, Jamf, Workspace ONE,
  Android Enterprise): device-admin/`DeviceAdminReceiver` grant and *revocation*
  events; device-owner/profile-owner status changes; Play Protect enable-state
  compliance signal (verify Android Enterprise API name); OS-integrity /
  root-jailbreak compliance verdict; MTD-connector health flipping a device to
  non-compliant.
- **Attestation** (Play Integrity API device/strong-integrity verdicts, Samsung
  Knox, iOS jailbreak detection): drop from pass to fail, or a sudden "clean"
  verdict on a device with other anomalies (possible T1630.003 spoofing).
- **App inventory / launcher state:** app present in MDM/app-vetting inventory
  but with no launcher activity visible to the user (icon suppressed — T1628.001);
  disappearance of a previously-inventoried app (self-uninstall — T1630.001).
- **App-vetting / dynamic analysis** (MobSF): manifest requests for device-admin
  policy, `setComponentEnabledSetting` to hide the launcher alias, code paths
  that call back-off/kill on the MTD or Play Protect packages, root-hiding
  framework indicators (Magisk DenyList / Zygisk-style — recognition only).
- **Forensics:** Android `bugreport` (`dumpsys device_policy`, `package`), logcat
  for admin-grant/revoke and package-removed broadcasts, iOS `sysdiagnose`.

## Detection logic / approach
1. **Agent/telemetry going dark:** correlate a missing MTD heartbeat or sudden
   app-uninstall of the security agent with the device still being online in MDM
   — the gap is the signal. Alert on MTD tamper/uninstall-attempt events
   directly.
2. **Play Protect disabled / OS defences weakened (T1629.003):** compliance
   policy asserting Play Protect must be on; alert on transition to off.
3. **Device-admin abuse (T1629.001/.002):** an untrusted app acquiring
   `DeviceAdminReceiver`/active-admin status (resists uninstall), or lockscreen
   credential changes/lockout from a non-sanctioned app — distinguish from the
   legitimate MDM agent, which is the expected admin.
4. **Indicator removal (T1630):** file-deletion/self-wipe and self-uninstall
   right after suspicious activity; **root/jailbreak spoofing (T1630.003)** —
   do NOT rely on static artifact names (a renamed `su` evades it); prefer
   attestation (Play Integrity / Knox) and behavioural root-hiding detection, and
   treat a device that *was* rooted then reports clean as suspicious.
5. **Hide artifacts (T1628):** reconcile authoritative app inventory (MDM /
   vetting) against what is visible on the launcher; a managed/known app with a
   suppressed icon is high-signal. Allowlist legitimate icon-hiding (some
   enterprise/parental apps) as FPs. Chameleon and GodFather are documented
   examples; Operation Triangulation for iOS indicator removal.

## Response / mitigation
Make MTD-agent presence/health and Play Protect state hard compliance gates —
non-compliance triggers Conditional Access block and selective wipe. Use
device-owner (fully-managed) enrolment so the MDM, not the malware, holds the
privileged admin role and sideloading is disabled. Revoke the malicious app's
device-admin (required before uninstall under T1629.001), then remove it. On
confirmed root-spoofing or integrity failure, quarantine and re-provision
(factory reset); artifact deletion means on-device forensics may be incomplete,
so pivot to network/identity logs.

## Real tools
Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Wandera;
Microsoft Intune, Jamf Pro/Protect, VMware Workspace ONE, Google Android
Enterprise + Play Protect + Play Integrity API, Samsung Knox; MobSF; Android
`bugreport`/`dumpsys device_policy`/logcat, iOS `sysdiagnose`. Malware/root-tool
names for recognition only: Chameleon, GodFather, Operation Triangulation,
Magisk.

## Draft frontmatter mappings
- mitre_attack: [T1629, T1630, T1628]
- nist_csf: [DE.CM-09, DE.CM-01, DE.AE-02, DE.AE-03, PR.PS-01, RS.MI-01, ID.AM-02]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): implementing-mobile-application-management

## Draft description (<=1024 chars)
Detects adversaries disabling or evading mobile defences so other activity goes
unseen: turning off Google Play Protect, killing or blocking uninstall of the
MTD agent, abusing the Android device-administration API to resist removal or
lock out the user (T1629), deleting files or self-uninstalling and disguising
root/jailbreak status (T1630), and hiding the app by suppressing its launcher
icon (T1628). Uses MTD agent-health and tamper/uninstall-attempt alerts, a
missing heartbeat as its own signal, MDM device-admin grant/revoke and Play
Protect compliance state, Play Integrity and Knox attestation verdicts, and
inventory-versus-launcher reconciliation. Use when a security agent goes silent,
Play Protect is disabled, device-admin is granted to an unknown app, or an app
hides its icon. Keywords: Play Protect disabled, MTD tamper, device admin,
root hiding, Play Integrity, hide app icon, T1629, T1630, T1628. Do not use for
deploying or configuring MAM/MDM controls - use
implementing-mobile-application-management.

## Key references
- MITRE ATT&CK Mobile T1629 Impair Defenses (+ .001/.002/.003): https://attack.mitre.org/techniques/T1629/
- MITRE ATT&CK Mobile T1630 Indicator Removal on Host + DET0651: https://attack.mitre.org/techniques/T1630/
- MITRE ATT&CK Mobile T1628 Hide Artifacts + DET0640 (AN1715): https://attack.mitre.org/techniques/T1628/
- Google Play Integrity API: https://developer.android.com/google/play/integrity
- Android device administration / DevicePolicyManager: https://developer.android.com/guide/topics/admin/device-admin
- Microsoft Intune mobile-threat-defense connector & compliance: https://learn.microsoft.com/mem/intune/protect/mobile-threat-defense
- Google Play Protect: https://developers.google.com/android/play-protect

## Open questions / scope boundaries
- Exact Android Enterprise / Intune API field names for "Play Protect enabled"
  and "MTD-agent health" compliance signals should be verified before use.
- Detecting an agent that has been *fully* uninstalled depends on MDM still
  seeing the device; a total wipe of all telemetry defeats on-device detection —
  the skill must lean on server-side heartbeat gaps and network/identity logs.
- Root/jailbreak spoofing is an arms race; keep the guidance attestation-first
  and explicitly warn against static `su`-name checks (T1630.003).
- Keep distinct from forensics (`performing-mobile-device-forensics-*`): this
  skill is live detection/response, not post-seizure extraction.
