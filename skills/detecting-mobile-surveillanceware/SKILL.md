---
name: detecting-mobile-surveillanceware
description: 'Detects mobile surveillanceware and stalkerware (T1429 Audio Capture) - an installed app abusing microphone, camera, screen capture (T1513), video (T1512), and location (T1430) permissions to covertly monitor a targeted person. Correlates sensor-permission grants with runtime use that persists while the app is backgrounded or the device is locked, then egress, using the Android Privacy Dashboard and AppOpsManager, iOS App Privacy Report and recording indicators, and MTD stalkerware classification. Flags the RECORD_AUDIO plus background-location permission cluster and screen-capture session abuse. Victim-protective detection and response only. Use when hunting stalkerware, consumer spyware, covert mic or camera recording, or hidden location tracking. Keywords: stalkerware, RECORD_AUDIO, MediaProjection, Privacy Dashboard, App Privacy Report, AppOps, background location, Android, iOS, T1429. Do not use for general mobile malware triage, use detecting-mobile-malware-behavior.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- android
- ios
- surveillanceware
- stalkerware
- sensor-abuse
- audio-capture
- location-tracking
- t1429
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- PR.AA-05
- DE.CM-09
- DE.AE-02
- DE.CM-01
mitre_attack:
- T1429
- T1512
- T1513
- T1430
---

# Detecting Mobile Surveillanceware

## When to Use

Use this skill to detect an **installed app abusing sensor permissions** —
microphone, camera, screen capture, and location — to covertly surveil a
person (stalkerware / consumer spyware). It covers ATT&CK T1429 Audio Capture,
T1512 Video Capture, T1513 Screen Capture, and T1430 Location Tracking. The
defining signal is a **grant-and-use pattern on sensitive sensors**, especially
while the app is backgrounded or the screen is locked, followed by data egress.
Reach for it when:

- Hunting stalkerware or consumer spyware on a device.
- An app holds the mic + background-location cluster with no user-facing reason.
- Privacy indicators or usage history show sensor use the owner cannot account
  for.

This skill is **victim-protective: detection and response only.** It never
describes how to deploy, install, configure, or operate surveillanceware.

For exploit-delivered, state-grade spyware (Pegasus/Predator) use
`detecting-mercenary-mobile-spyware-with-mvt`; for device-management trust abuse
use `detecting-malicious-mobile-configuration-profiles`; for general mobile
malware triage use `detecting-mobile-malware-behavior`.

## Target / survivor safety (read first)

In an intimate-partner-abuse context, **removal can tip off the abuser and
escalate risk to the survivor.** Before changing anything:

- **Preserve evidence first** (screenshots of the app, the permission-usage
  history, and the installed-app list) in case it is needed for a protective
  order or law-enforcement report.
- **Do not auto-remove.** Follow safety-planning guidance from the Coalition
  Against Stalkerware and a domestic-violence advocate (for example NNEDV)
  before uninstalling, since the person may need a safety plan in place first.
- Treat the device owner as the decision-maker on timing. Detection informs
  them; it does not act unilaterally.

## Prerequisites

- Access to the device's permission and privacy telemetry: Android 12+ **Privacy
  Dashboard** / permission-usage history; `AppOpsManager` records are **not**
  fleet telemetry — historical app-ops for other packages need privileged access
  (`GET_APP_OPS_STATS` is signature|privileged), so in practice that path means
  on-device user review or `adb shell dumpsys appops`. On iOS, the **App Privacy
  Report** (Settings, Privacy & Security) and the mic/camera recording
  indicators.
- An MTD with surveillanceware/stalkerware classification (Lookout, Zimperium
  zIPS, Microsoft Defender for Endpoint mobile) and/or Google Play Protect.
- MDM/UEM app inventory (Intune/Jamf/Workspace ONE) to catch known stalkerware
  package names and the sensitive-permission cluster across a fleet.
- A reputation / allowlist source — the Coalition Against Stalkerware indicator
  sets, and an allowlist of legitimate recorders, dictation, and nav apps.

## Workflow

1. **Permission-cluster screen.** Enumerate apps holding the sensitive cluster —
   `RECORD_AUDIO` + a location permission (illustrative:
   `ACCESS_FINE_LOCATION` / `ACCESS_BACKGROUND_LOCATION`) or `CAMERA`. Apps with
   no UI justification for the cluster are candidates. Screen capture is **not**
   enumerable this way: `MediaProjection` has no manifest permission and needs
   per-session user consent via
   `MediaProjectionManager.createScreenCaptureIntent()`, so the static signals
   are the declared `foregroundServiceType="mediaProjection"` and, on Android
   14+, `FOREGROUND_SERVICE_MEDIA_PROJECTION`. **Verify the exact permission and
   AppOps op constants against current Android docs** and prefer the behavioral
   framing (an unexpected, non-allowlisted app holding a powerful sensor
   grant).
2. **Runtime-use anomaly.** Read mic / camera / `MediaProjection` use timestamps
   from the Privacy Dashboard or App Privacy Report. Flag use that occurs while
   the user was not interacting — backgrounded or screen-locked capture is the
   discriminator, not the grant alone.
3. **Egress correlation.** Correlate sensor use with outbound connections
   shortly after, especially to low-reputation or newly registered hosts.
4. **Reputation.** Cross-reference the package against MTD stalkerware
   classifications and the Coalition Against Stalkerware indicators; subtract
   the legitimate-recorder/nav allowlist to cut false positives.
5. **Persistence check.** Verify whether the app abuses an Accessibility
   service or device-admin for persistence (stalkerware commonly does) —
   present a non-allowlisted app holding Accessibility as high-signal; **verify
   the exact service/op constant** rather than asserting it.
6. **Respond** (see *Response*, and the safety note above).

## Key Concepts

- **Grant alone is not abuse.** A recorder app holding `RECORD_AUDIO` is normal.
  The signal is **grant + runtime use while backgrounded/locked + egress.**
- **Privacy telemetry is the on-device sensor.** There is no host syscall log on
  a phone; the Privacy Dashboard / App Privacy Report *is* the usage record.
- **The cluster matters.** Mic + background location + background execution with
  no UI is the classic stalkerware fingerprint.
- **Accessibility abuse = persistence.** Stalkerware uses Accessibility both to
  hide and to survive — a non-allowlisted app holding it warrants scrutiny.

## Tools & Systems

Android Privacy Dashboard / permission-usage history and `AppOpsManager`; iOS
App Privacy Report and recording indicators; Lookout, Zimperium zIPS, Microsoft
Defender for Endpoint (mobile) stalkerware classification; Google Play Protect;
Coalition Against Stalkerware resources (indicators and survivor-safety
guidance); MDM app inventory (Intune / Jamf Pro / Workspace ONE).

## Detection Queries

Permission names, AppOps ops, and thresholds are illustrative — **verify and
tune** against current Android/Apple docs.

### Android — sensitive permission cluster (MDM / fleet)

```text
# From MDM app-permission inventory. Verify constant names; tune the allowlist.
CANDIDATE IF app holds RECORD_AUDIO
          AND app holds (ACCESS_BACKGROUND_LOCATION OR ACCESS_FINE_LOCATION)
          AND app NOT IN legitimate_recorder_nav_allowlist
# Raise priority if the app declares foregroundServiceType="mediaProjection"
# (Android 14+: FOREGROUND_SERVICE_MEDIA_PROJECTION) or an Accessibility service.
# MediaProjection itself is not a permission and cannot be inventoried.
```

### Android — runtime use while backgrounded (Privacy Dashboard concept)

```text
# From permission-usage history / AppOps op records. These sources carry per-access
# TIMESTAMPS, not an interaction state: derive backgrounded / screen-locked by
# correlating each access timestamp against a screen-on / device-usage timeline
# (the fields below stand in for that derived state — confirm what your source
# actually exposes before coding).
ALERT IF sensor_op IN (mic, camera, screen-capture session)
      AND (app_state == backgrounded OR screen == locked)
      AND app NOT IN allowlist
# AppOps op strings vary by Android version — verify before coding.
```

### iOS — App Privacy Report review (concept)

```text
# App Privacy Report logs per-app sensor + network access over ~7 days.
# Triage: an app logging microphone/camera access at times the owner did not
# use it, paired with a network contact to an unfamiliar domain.
```

### Egress correlation (SIEM concept)

```text
# Sensor-use event followed within a short window (verify/tune) by an outbound
# connection to a low-reputation / newly registered host from the same app.
```

## Common Scenarios

- **Hidden mic recorder:** an app with no recording UI uses the microphone while
  the screen is locked, then uploads to an unfamiliar host.
- **Covert location tracker:** background-location sampling at high frequency
  from an app with no map/nav function.
- **Screen mirror:** a `MediaProjection` session starts with no user-facing
  reason and streams out.
- **False positive:** a legitimate dictation or navigation app using mic or
  location with a clear UI reason — excluded by the allowlist and the
  interaction-state check.

## Output Format

```text
MOBILE SURVEILLANCEWARE DETECTION
  Device:          <device id / owner>
  Platform:        <Android | iOS>
  Verdict:         <confirmed stalkerware | suspected | benign-allowlisted>
  App:             <package / display name>
  Sensor abuse:    <mic | camera | screen (MediaProjection) | location>
  Runtime use:     <timestamps while backgrounded/locked>
  Egress:          <outbound host(s) after sensor use>
  Persistence:     <Accessibility / device-admin held? y/n>
  ATT&CK:          T1429, T1512, T1513, T1430
  Safety:          <evidence preserved; safety plan confirmed before removal>
  Actions taken:   <permissions revoked | app removed | referral made>
```

## Response

- **Safety first.** Confirm the survivor-safety steps above before any change;
  preserve evidence; in an intimate-partner context do not remove the app until
  a safety plan is in place.
- **Revoke, then remove.** Revoke the app's sensor permissions, then uninstall;
  verify no Accessibility-service or device-admin persistence remains.
- **Refer.** Point at-risk individuals to the Coalition Against Stalkerware /
  NNEDV resources.
- **Harden.** Permission-hygiene reviews; block side-loading on managed devices;
  MTD coverage; user education on the mic/camera privacy indicators.
