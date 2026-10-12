---
name: detecting-mobile-device-rooting-and-jailbreak
description: 'Detects loss of whole-device integrity: rooted Android (Magisk, exploit-based su) and jailbroken iOS (checkra1n, unc0ver, Dopamine), whether user-initiated or from an attacker exploiting an OS or privileged-app bug to escalate to root (T1404 Exploitation for Privilege Escalation). Leans on server-verified attestation because a compromised device can lie about itself: Google Play Integrity device verdicts, Apple App Attest and DeviceCheck, plus Intune jailbreak-or-root compliance, Jamf and Workspace ONE state, and MTD threat level from Lookout, Zimperium and Defender for Endpoint. Use when an attestation verdict drops for a device that previously passed, a device reports rooted or jailbroken, or SELinux denials precede a UID change. Keywords: root detection, jailbreak, Magisk, Play Integrity, attestation, device integrity, App Attest, DeviceCheck, MDM compliance, Android, iOS, T1404. Do not use for app-specific Frida or Xposed hooking - use detecting-mobile-runtime-hooking-and-instrumentation.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile
- android
- ios
- root-detection
- jailbreak
- attestation
- device-integrity
- t1404
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- PR.PS-01
- DE.CM-09
- DE.AE-02
- ID.AM-02
- PR.AA-05
- DE.CM-01
mitre_attack:
- T1404
---

# Detecting Mobile Device Rooting and Jailbreak

## When to Use

Use this skill to detect **loss of whole-device integrity**: a device whose
security model has been defeated by rooting (Magisk, exploit-based `su`) on
Android or jailbreak (checkra1n, unc0ver, Dopamine) on iOS — whether the user did
it voluntarily or an attacker exploited an OS / privileged-app bug to escalate
from the app sandbox to root (ATT&CK T1404 Exploitation for Privilege Escalation).
A rooted/jailbroken device can **falsify what on-device tools see**, so detection
leans on *server-verified attestation* and *MDM compliance*, not the device's own
word. Reach for it when:

- An attestation verdict drops for a device that previously passed.
- MDM/MTD reports a device rooted or jailbroken.
- SELinux-denial bursts precede a UID / security-domain change (exploit-driven).

Scope is **whole-device** integrity. For runtime instrumentation of a *single app*
(Frida, Xposed/LSPosed, ptrace injection) use
`detecting-mobile-runtime-hooking-and-instrumentation` — the two are a deliberate
split: root is the device state, hooking is what rides on it inside one app.

## Prerequisites

- **Attestation (primary, server-verified).**
  - **Google Play Integrity API** device verdicts, evaluated server-side. A device
    that previously returned a strong/device-integrity verdict and now returns only
    a weaker one indicates integrity loss. The verdict labels are documented and
    current: `deviceIntegrity.deviceRecognitionVerdict` carries
    `MEETS_DEVICE_INTEGRITY`, `MEETS_STRONG_INTEGRITY` and
    `MEETS_BASIC_INTEGRITY`. Still alert on the **drop in tier**, not on the
    exact string — that is what survives a device changing state. Legacy
    SafetyNet Attestation was deprecated in 2022 and **fully shut down in
    January 2025**: `attest()` calls now always fail, so it is a migration
    reference only, never a fallback.
  - **Apple App Attest** (`DCAppAttestService`) and **DeviceCheck** (`DCDevice`) —
    attest a genuine, unmodified app on genuine hardware. Apple's own caveat: App
    Attest is **not a standalone jailbreak detector** and may not hold on a
    jailbroken device, so treat it as one risk signal, not proof.
- **MDM/UEM compliance.** Intune jailbroken/rooted compliance setting, Jamf Pro and
  Workspace ONE root/jailbreak state, iOS supervised state.
- **MTD on-device checks.** Lookout, Zimperium zIPS, Microsoft Defender for
  Endpoint (mobile) root/jailbreak detections feeding Intune device-threat level.
- **Forensics.** ADB/logcat and `bugreport`; MVT where spyware-linked exploitation
  is suspected.

## Workflow

1. **Attestation gate (authoritative).** Require a device-integrity (or stronger)
   attestation at app sign-in / enrollment; the **server** evaluates the signed
   verdict. A verdict below the required tier means treat the device as
   compromised, independent of any on-device claim.
2. **MDM compliance + Conditional Access.** Mark rooted/jailbroken devices
   non-compliant in Intune/Jamf/Workspace ONE; Entra Conditional Access blocks
   corporate resource access.
3. **MTD threat-level correlation.** An MTD root/jailbreak alert raises device
   threat level; policy blocks at or above a threshold.
4. **Exploitation (attacker-driven) hunt.** Distinguish *voluntary root* from
   *attacker exploitation*: a burst of SELinux denials followed by a
   permission/security-domain change, or a new root/system-UID process tracing back
   to an app-sandbox path, points to exploit-based escalation — handle as a
   possible targeted compromise, not a policy violation.

## Key Concepts

- **Do not trust the device to report on itself.** Root defeats on-device checks,
  so the authoritative signal is a **server-side** attestation verdict and the MDM
  compliance state derived from it.
- **The drop is the signal.** The verdict enum names are stable, but what matters
  is a device moving from a strong verdict to a weaker one. Frame rules on the
  *tier change*, not a hard-coded string.
- **Attestation is necessary, not sufficient on iOS.** App Attest does not promise
  jailbreak detection; combine it with MDM/MTD state.
- **Voluntary vs exploited.** A user rooting their own phone is a compliance
  problem; an app-sandbox escape to root is an incident. The SELinux-denial-burst
  then UID/domain-change pattern separates them.
- **Root is the platform for worse.** Once root is present, app hooking and spyware
  injection become possible — pivot to
  `detecting-mobile-runtime-hooking-and-instrumentation` and run MVT.

## Tools & Systems

Google Play Integrity API (SafetyNet Attestation is gone — shut down January
2025 — and appears here only as a migration note), Apple App
Attest / DeviceCheck, Microsoft Intune compliance + Entra Conditional Access, Jamf
Pro, VMware Workspace ONE, Lookout, Zimperium zIPS, Microsoft Defender for Endpoint
(mobile), ADB/logcat, `bugreport`, MVT. Root/jailbreak tool names for recognition
only: Magisk, checkra1n, unc0ver, Dopamine.

## Detection Queries

Treat table/column names and thresholds as **verify/tune** for your connectors.

### Play Integrity server-side gate (concept)

```
# Server decodes the signed Play Integrity token at sign-in/enrollment:
verdict = token.deviceIntegrity.deviceRecognitionVerdict
if required_tier not in verdict:                           # e.g. device-integrity tier absent
    deny_sensitive_access(); mark_noncompliant(device); alert("integrity drop")
```

### Microsoft Sentinel (KQL) -- rooted/jailbroken compliance or MTD alert

```kql
// Intune compliance in Log Analytics is IntuneDeviceComplianceOrg; it has no
// per-setting column, and the MTD-driven root/jailbreak signal is
// DeviceHealthThreatLevel. Verify column names for your connectors.
IntuneDeviceComplianceOrg
| where ComplianceState == "Noncompliant"
| project TimeGenerated, DeviceName, UPN, ComplianceState, DeviceHealthThreatLevel
| union (
    // Mobile threat events surface as ALERTS, not in a DeviceTvm* table: use
    // AlertInfo/AlertEvidence (Defender XDR advanced hunting, also available in
    // Sentinel via the XDR connector) or SecurityAlert (Sentinel-native).
    AlertInfo
    | where Title has_any ("root", "jailbreak", "Magisk", "su binary")  // verify/tune
    | join kind=inner (AlertEvidence | where isnotempty(DeviceId)
                       | project AlertId, DeviceId) on AlertId
    | project TimeGenerated, DeviceId, ThreatName = Title
  )
```

### Exploit-driven escalation (logcat/bugreport, concept)

```
# In a bugreport/logcat pulled for triage, look for the sequence:
#   burst of 'avc: denied' SELinux entries  ->  a process changing UID/security domain
#   or a new root/system-UID process whose path traces to an app sandbox dir
# This pattern = sandbox-escape exploitation, not a user rooting their own phone.
```

## Common Scenarios

- **Voluntary Magisk root:** device returns a weakened Play Integrity verdict; MDM
  marks non-compliant, Conditional Access blocks corporate apps.
- **Jailbroken iOS:** MTD flags jailbreak; App Attest treated as one signal
  alongside MDM state.
- **Exploit-based escalation:** SELinux-denial burst then a UID change — escalated
  as a possible targeted compromise; run MVT for spyware.
- **False positive:** a developer test device expected to be rooted — excluded from
  the fleet policy by an explicit exception group.

## Output Format

```
DEVICE INTEGRITY LOSS DETECTION
  Device:          <device id / user / platform>
  Verdict:         <confirmed-rooted | confirmed-jailbroken | suspected | exploit-driven>
  Attestation:     <Play Integrity tier now vs previously | App Attest/DeviceCheck signal>
  Compliance:      <Intune/Jamf/Workspace ONE root-jailbreak state>
  MTD:             <Lookout/Zimperium/Defender threat level>
  Origin:          <voluntary root | sandbox-escape exploitation (SELinux burst -> UID change)>
  ATT&CK:          T1404
  Actions taken:   <CA block | selective wipe | quarantine until re-attested | MVT forensics on exploit path>
```

## Response

- **Contain:** Conditional Access blocks non-compliant / attestation-failed devices
  from corporate apps and data; selective-wipe the work profile; quarantine until
  the device re-attests on a clean OS.
- **Enforce server-side attestation** for sensitive apps so a device cannot assert
  its own integrity.
- **Patch:** require OS security updates — patching closes the privilege-escalation
  path that exploit-driven root depends on.
- **For exploitation (not voluntary root):** treat as a possible targeted
  compromise and run MVT/forensics for spyware before restoring the device.
