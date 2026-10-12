# Detecting Mobile Device Rooting and Jailbreak — research notes

- **Proposed skill name:** Detecting Mobile Device Rooting and Jailbreak
- **Proposed slug:** detecting-mobile-device-rooting-and-jailbreak
- **ATT&CK (Mobile):** T1404 Exploitation for Privilege Escalation (platforms: Android, iOS)
- **Status:** research (not yet a skill)

## Defensive goal
Detect loss of device integrity: a device whose security model has been defeated
by rooting (Magisk, exploit-based root) or jailbreak (checkra1n, unc0ver, Dopamine),
whether user-initiated or achieved by an attacker exploiting an OS/privileged-app
vulnerability to escalate from app sandbox to root. A rooted/jailbroken device
can falsify what on-device tools see, so the detection leans on *server-side
attestation* and *MDM compliance* rather than trusting the device's own report.

## Data sources / telemetry
- **Attestation verdicts (primary, server-verified).**
  - **Google Play Integrity API** device verdicts: `MEETS_STRONG_INTEGRITY`
    (hardware-backed, recent security patch), `MEETS_DEVICE_INTEGRITY` (locked
    bootloader + certified OS image), down through `MEETS_BASIC_INTEGRITY` and
    `MEETS_VIRTUAL_INTEGRITY` (emulator). A drop below DEVICE/STRONG for a device
    that previously passed = integrity loss / likely root. (Legacy SafetyNet
    Attestation `ctsProfileMatch`/`basicIntegrity` — deprecated, verify.)
  - **Apple App Attest** (`DCAppAttestService`) and **DeviceCheck** (`DCDevice`):
    attest genuine, unmodified app on genuine hardware. Note Apple's caveat —
    App Attest is **not a standalone jailbreak detector** and may not hold on a
    jailbroken device, so treat it as one risk signal, not proof.
- **MDM/UEM compliance.** Intune "Jailbroken/rooted devices" compliance setting
  (enhanced jailbreak detection can require location services), Jamf Pro and
  Workspace ONE root/jailbreak compliance state, iOS supervised state.
- **MTD on-device checks.** Lookout, Zimperium zIPS, Defender for Endpoint
  (mobile) root/jailbreak detections feed Intune device-threat level; these see
  Magisk/Zygisk, su binaries, unexpected system partitions.
- **Forensics.** su/Magisk artifacts, writable `/system`, unexpected
  `/Applications/Cydia.app` or Sileo; Android `bugreport`/logcat SELinux-denial
  bursts then a UID/domain change (MITRE AN1758 observable); MVT for
  spyware-linked exploitation traces.

## Detection logic / approach
1. **Attestation gate (authoritative).** Require Play Integrity DEVICE/STRONG (or
   App Attest) at app sign-in / enrollment; server evaluates the signed verdict.
   Verdict below the required tier → treat device as compromised, independent of
   any on-device claim.
   ```
   if play_integrity.deviceRecognitionVerdict lacks "MEETS_DEVICE_INTEGRITY":
       deny_sensitive_access(); mark_noncompliant()
   ```
2. **MDM compliance + Conditional Access.** Intune compliance = non-compliant on
   rooted/jailbroken; Entra CA blocks corporate resource access.
3. **MTD threat-level correlation.** MTD root/jailbreak alert raises device threat
   level; policy blocks at or above a threshold.
4. **Exploitation (attacker-driven) hunt (AN1758).** SELinux denial burst
   followed by a permission/domain change, or a new root/system-UID process
   tracing back to an app sandbox path → exploit-based escalation, not a user
   rooting their own phone.

## Response / mitigation
Conditional Access blocks non-compliant/attested-fail devices from corporate apps
and data; selective-wipe the work profile; quarantine until re-attested on a
clean OS. Require OS security updates (MITRE M1001) — patching closes the
escalation path. Enforce attestation server-side for sensitive apps. For a device
with signs of *exploitation* (not voluntary root), treat as a possible targeted
compromise and run MVT/forensics for spyware.

## Real tools
Google Play Integrity API, SafetyNet (legacy), Apple App Attest / DeviceCheck,
Microsoft Intune compliance + Entra Conditional Access, Jamf Pro, VMware Workspace
ONE, Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), ADB/logcat,
`bugreport`, MVT. Root/jailbreak tool names for recognition only: Magisk,
checkra1n, unc0ver, Dopamine.

## Draft frontmatter mappings
- mitre_attack: [T1404]
- nist_csf: [PR.PS-01, DE.CM-09, DE.AE-02, ID.AM-02, PR.AA-05, DE.CM-01]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): implementing-mobile-application-management

## Draft description (<=1024 chars)
Detects loss of mobile device integrity: rooted Android (Magisk, exploit-based su)
and jailbroken iOS (checkra1n, unc0ver, Dopamine), whether user-initiated or from
an attacker exploiting an OS or privileged-app bug to escalate to root (T1404
Exploitation for Privilege Escalation). Leans on server-verified attestation
because a compromised device can lie about itself: Google Play Integrity device
verdicts (MEETS_DEVICE_INTEGRITY, MEETS_STRONG_INTEGRITY), Apple App Attest and
DeviceCheck, plus Intune jailbreak/root compliance, Jamf and Workspace ONE state,
and MTD threat level from Lookout, Zimperium and Defender for Endpoint. Use when
an attestation verdict drops, a device reports rooted or jailbroken, or SELinux
denials precede a UID change. Keywords: root detection, jailbreak, Magisk, Play
Integrity, attestation, MEETS_DEVICE_INTEGRITY, App Attest, DeviceCheck,
compliance, T1404. Do not use for app-specific Frida or Xposed hooking - use
detecting-mobile-runtime-hooking-and-instrumentation.

## Key references
- MITRE ATT&CK Mobile T1404 Exploitation for Privilege Escalation (+ DET0665, AN1758): https://attack.mitre.org/techniques/T1404/
- Google Play Integrity API overview + improved verdicts: https://developer.android.com/google/play/integrity/overview
- Apple App Attest / DeviceCheck (DCAppAttestService, DCDevice): https://developer.apple.com/documentation/devicecheck
- Microsoft Intune device compliance (jailbroken/rooted): https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started

## Open questions / scope boundaries
- Author must decide the attestation tier required per app, and how to treat the
  pre-Android-13 software-backed fallback for MEETS_DEVICE_INTEGRITY.
- Decide whether to separate *voluntary root* (policy/compliance problem) from
  *attacker exploitation* (incident) — AN1758 observables distinguish them.
- Verify current SafetyNet deprecation status and exact App Attest guarantees.
- MUST NOT cover runtime instrumentation of a single app (that is
  detecting-mobile-runtime-hooking-and-instrumentation); scope is whole-device
  integrity.
