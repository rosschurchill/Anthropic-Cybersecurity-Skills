---
name: detecting-mobile-security-control-tampering
description: 'Detects adversaries disabling or evading mobile defences on Android and iOS: turning off Google Play Protect, killing or blocking uninstall of the MTD agent, abusing the Android device-administration API to resist removal or lock out the user (T1629), self-uninstalling and disguising root or jailbreak status (T1630), and hiding the app by suppressing its launcher icon (T1628). Uses MTD agent-health and tamper or uninstall-attempt alerts, a missing heartbeat as its own signal, MDM device-admin grant and revoke events and Play Protect compliance state, Play Integrity and Knox attestation verdicts, and inventory-versus-launcher reconciliation. Use when a security agent goes silent, Play Protect is disabled, device-admin is granted to an unknown app, or an app hides its icon. Keywords: Play Protect disabled, MTD tamper, device admin, root hiding, Play Integrity, hide app icon, T1629, T1630, T1628. Do not use for deploying or configuring MAM and MDM controls - use implementing-mobile-application-management.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- android
- ios
- defense-evasion
- play-protect
- mtd-tamper
- device-admin
- play-integrity
- t1629
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.CM-01
- DE.AE-02
- DE.AE-03
- RS.MI-01
mitre_attack:
- T1629
- T1630
- T1628
---

# Detecting Mobile Security-Control Tampering

## When to Use

Use this skill to detect an adversary **disabling or evading mobile defences** so
other activity goes unseen on Android/iOS:

- **Impair defenses (T1629)** — turning off Google Play Protect, killing or
  blocking uninstall of the MTD agent, or abusing the Android device-administration
  API to resist removal or lock the user out.
- **Indicator removal (T1630)** — deleting files, self-uninstalling after
  activity, and disguising root/jailbreak status.
- **Hide artifacts (T1628)** — suppressing the launcher icon or otherwise evading
  the user while active.

The defensive premise: tamper and agent-health signals are often the **last
reliable signal before telemetry goes dark**, so their *absence or change must
itself alert*. Reach for it when a security agent goes silent, Play Protect is
disabled, device-admin is granted to an unknown app, or a known app loses its
launcher icon.

This is **live detection and response**, not post-seizure forensic extraction,
and not control deployment — to deploy or configure MAM/MDM controls, use
`implementing-mobile-application-management`.

## Prerequisites

Mobile detection has **no raw host agent with syscall telemetry** — and here the
very telemetry may be the target, so server-side signals carry the load:

- **MTD agent-health / tamper signals** (Lookout, Zimperium zIPS, Microsoft
  Defender for Endpoint on mobile, Wandera): explicit uninstall-attempt and
  tamper/kill alerts, last-check-in heartbeat, and a **missing heartbeat as a
  detection in its own right**.
- **MDM/UEM compliance + device-admin state** (Microsoft Intune, Jamf Pro, VMware
  Workspace ONE, Android Enterprise): device-admin grant and **revocation**
  events; device-owner / profile-owner status changes; Play Protect enable-state
  as a compliance signal (verify the exact Android Enterprise / Intune field name
  against current docs); OS-integrity / root-jailbreak compliance verdict;
  MTD-connector health flipping a device to non-compliant.
- **Attestation** (Google Play Integrity API device/strong-integrity verdicts,
  Samsung Knox, iOS jailbreak detection): a drop from pass to fail, or a sudden
  "clean" verdict on a device with other anomalies (possible root/jailbreak
  spoofing).
- **App inventory / launcher state**: an app present in authoritative inventory
  but with no user-visible launcher activity (icon suppressed); the disappearance
  of a previously inventoried app (self-uninstall).
- **App-vetting / dynamic analysis** (MobSF): manifest requests for
  device-admin policy, launcher-alias disable (`setComponentEnabledSetting` —
  verify constant), code paths that kill/back-off the MTD or Play Protect
  packages, root-hiding framework indicators (Magisk DenyList / Zygisk-style —
  recognition only).
- **Forensics**: Android `bugreport` (`dumpsys device_policy`, `package`), logcat
  for admin grant/revoke and package-removed broadcasts, iOS `sysdiagnose`.

## Workflow

1. **Treat the missing signal as the alert.** Correlate a missing MTD heartbeat or
   a sudden uninstall of the security agent with the device **still being online
   in MDM** — that gap is the detection. Alert on MTD tamper / uninstall-attempt
   events directly.
2. **Play Protect / OS defences off (T1629).** Assert Play Protect-on
   as a compliance policy; alert on the transition to off.
3. **Device-admin abuse (T1629).** An untrusted app acquiring active
   device-admin status (which resists uninstall), or a lockscreen credential
   change / lockout from a non-sanctioned app. Distinguish from the legitimate MDM
   agent, which is the *expected* admin holder.
4. **Indicator removal (T1630).** File self-wipe and self-uninstall right after
   suspicious activity. For **root/jailbreak spoofing**, do **not** rely on static
   artifact names — a renamed `su` evades it; prefer attestation (Play Integrity /
   Knox) and behavioural root-hiding detection, and treat a device that *was*
   rooted then reports clean as suspicious.
5. **Hide artifacts (T1628).** Reconcile authoritative app inventory against what
   is visible on the launcher; a managed/known app with a suppressed icon is
   high-signal. Allowlist legitimate icon-hiding (some enterprise/parental apps).
   Chameleon and GodFather are documented examples; Operation Triangulation is an
   iOS indicator-removal reference.
6. **Respond** (see *Response*).

## Key Concepts

- **Absence is evidence.** When defences succeed at going dark, the only signal
  left is the gap — a silent agent on a live device is itself the alert.
- **Attestation beats on-device checks.** Root/jailbreak spoofing is an arms race;
  keep guidance attestation-first and explicitly reject static `su`-name checks.
- **The MDM is the expected admin.** Device-admin is normal for the managed MDM
  and alarming for anything else — the discriminator is *which* app holds it.
- **Inventory versus launcher.** Server-side inventory is authoritative; a known
  app invisible on the launcher is hiding.
- **A clean verdict can be a lie.** A device previously rooted that suddenly
  attests clean, while other anomalies persist, suggests spoofing — not recovery.

## Tools & Systems

Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Wandera;
Microsoft Intune, Jamf Pro/Protect, VMware Workspace ONE, Google Android
Enterprise + Play Protect + Play Integrity API, Samsung Knox; MobSF; Android
`bugreport`/`dumpsys device_policy`/logcat, iOS `sysdiagnose`. Malware/root-tool
names for recognition only: Chameleon, GodFather, Operation Triangulation, Magisk.

## Detection Queries

Treat thresholds, field names and API constants as **verify/tune**.

### MTD heartbeat gap on a live device (concept)

```
Alert when (last MTD check-in age > threshold) AND (device last-seen in MDM is
recent) AND (no sanctioned uninstall/retire record). The agent is silent while
the device is online -> tamper/uninstall suspected. Tune the age threshold to the
agent check-in interval.
```

### Intune compliance — Play Protect + MTD-agent health gates (concept)

```
Compliance: Play Protect must be on; MTD-connector risk must be acceptable.
A transition Play-Protect-on -> off, or MTD health healthy -> unhealthy, flips
the device non-compliant -> Conditional Access block. Verify the exact setting
names against current Intune/Android Enterprise docs.
```

### KQL (Sentinel / Defender) — device-admin granted to an unknown app

```kql
// verify table/column names against your schema
DevicePolicyEvents
| where Action == "device-admin-activated"
| where PackageName !in (ApprovedAdminAllowlist)   // the MDM agent is expected
| join kind=leftouter (MobileThreatInfo) on AppId
| project DeviceId, PackageName, AppReputation, TimeGenerated
```

### Inventory-versus-launcher reconciliation (concept)

```
Diff authoritative MDM/vetting inventory against user-visible launcher entries.
A managed/known package with no launcher activity -> icon suppressed (T1628).
Allowlist sanctioned icon-hiding apps. Verify launcher-alias disable signals
(setComponentEnabledSetting) in MobSF before encoding.
```

## Common Scenarios

- **Agent goes dark:** MTD heartbeat stops while the device stays online in MDM —
  uninstall/tamper suspected, alert fires on the gap.
- **Device-admin lock-in:** a low-reputation app activates device-admin to resist
  uninstall and later changes the lockscreen credential.
- **Root spoofing:** a device that previously attested rooted now reports clean
  while other anomalies persist (root/jailbreak spoofing under T1630).
- **Icon hidden:** a managed-known package has no launcher entry after install.
- **False positive:** an enterprise/parental app that legitimately hides its icon
  and the MDM agent holding device-admin — both allowlisted.

## Output Format

```
MOBILE CONTROL-TAMPERING DETECTION
  Device:          <device id / user>
  App:             <package name / version, if identified>
  Verdict:         <confirmed | suspected | sanctioned-allowlisted>
  Evasion:         <Play Protect off | MTD tamper/uninstall | device-admin abuse | indicator removal | hidden icon | root spoof>
  Signal:          <missing heartbeat | compliance transition | admin grant/revoke | attestation drop | inventory-vs-launcher>
  ATT&CK:          <T1629 | T1630 | T1628>
  Actions taken:   <quarantined | marked non-compliant | admin revoked then app removed | re-provisioned>
```

## Response

- **Make health a hard gate:** MTD-agent presence/health and Play Protect state as
  compliance gates — non-compliance triggers Conditional Access block and
  selective wipe.
- **Hold the privileged role:** use device-owner (fully-managed) enrolment so the
  MDM, not the malware, holds the admin role and sideloading is disabled.
- **Remove in order:** revoke the malicious app's device-admin (required before
  uninstall when it resists removal), then remove it.
- **On root-spoofing / integrity failure:** quarantine and re-provision (factory
  reset). Because artifact deletion means on-device forensics may be incomplete,
  pivot to network and identity logs.
