# Detecting Mobile Surveillanceware — research notes

- **Proposed slug:** detecting-mobile-surveillanceware
- **ATT&CK (Mobile):** T1429 Audio Capture (tactic: collection) — plus T1512 Video Capture, T1513 Screen Capture, T1430 Location Tracking. Detection strategy: **DET0673** (Android + iOS). Example family: DCHSpy (captures audio by controlling the microphone). Android audio needs `RECORD_AUDIO`; `CAPTURE_AUDIO_OUTPUT` is reserved for privileged/vendor apps unless privilege is escalated.
- **Status:** research (not yet a skill)

## Defensive goal
Detect an **installed app abusing sensor permissions** — microphone, camera, screen capture, and location — to covertly surveil the user (stalkerware / consumer spyware). The defining signal is a grant-and-use pattern on sensitive sensors, especially while the app is backgrounded or the screen is locked, followed by data egress. Keep distinct from mercenary zero-click spyware (forensic, exploit-delivered — see the MVT skill) and from generic malware behavior.

## Data sources / telemetry
- **Sensor-permission grants + runtime use:** Android `RECORD_AUDIO`, `CAMERA`, `ACCESS_FINE_LOCATION` / `ACCESS_BACKGROUND_LOCATION`, and `MediaProjection` (screen capture) grants; runtime use via the Android 12+ Privacy Dashboard / permission-usage history and `AppOpsManager` op records (*verify exact AppOps op names*). Mic/camera status-bar indicators (Android 12+).
- **iOS privacy telemetry:** the orange (mic) and green (camera) recording indicators, location arrow, and the **App Privacy Report** (Settings → Privacy & Security) logging per-app sensor and network access over 7 days.
- **MTD classification:** Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile) surveillanceware/stalkerware classification; Google Play Protect app classification.
- **Behavioral:** audio/video/screen capture started via OS APIs that continues while backgrounded/locked, paired with outbound traffic; MediaProjection session started without a user-facing reason; high-frequency background location sampling. Android `logcat` and mobile EDR telemetry (DET0673 data sources).
- **MDM/UEM:** app inventory to catch known stalkerware package names and apps requesting the sensitive-permission cluster.

## Detection logic / approach
Per DET0673: flag an app that **initiates sensor capture via OS APIs, sustains it while backgrounded or the device is locked, then transmits** outbound. Build the detection as a correlation, not a single permission check:
- Permission-cluster screen: apps holding `RECORD_AUDIO` + `ACCESS_FINE_LOCATION` + background execution, with no UI justification, are candidate stalkerware.
- Runtime-use anomaly: mic/camera/`MediaProjection` use timestamps (Privacy Dashboard / App Privacy Report) that occur when the user was not interacting → investigate.
- Egress correlation: sensor use followed shortly by outbound connections to low-reputation / newly registered hosts.
- Reputation: cross-reference package against MTD stalkerware classifications and the Coalition Against Stalkerware indicator sets.

## Response / mitigation
- Revoke the abusive app's sensor permissions, then uninstall; verify no device-admin / accessibility-service persistence remains (stalkerware commonly abuses Accessibility).
- **Safety-first for intimate-partner contexts:** removal can tip off an abuser — follow Coalition Against Stalkerware / NNEDV safety-planning guidance before acting; preserve evidence first.
- Preventive: permission hygiene reviews, block side-loading, MTD on managed devices, user education on the privacy indicators.

## Real tools
Android Privacy Dashboard / permission-usage history, `AppOpsManager`; iOS App Privacy Report and recording indicators; Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile) stalkerware classification; Google Play Protect; Coalition Against Stalkerware resources; MDM app inventory (Intune/Jamf/Workspace ONE).

## Draft frontmatter mappings
- mitre_attack: [T1429, T1512, T1513, T1430]
- nist_csf: [PR.AA-05, DE.CM-09, DE.AE-02, DE.CM-01]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-malware-behavior

## Draft description (<=1024 chars)
Detects mobile surveillanceware and stalkerware (T1429 Audio Capture) — an installed app abusing microphone, camera, screen capture (T1513), video (T1512), and location (T1430) permissions to covertly monitor the user. Correlates sensor-permission grants with runtime use that persists while the app is backgrounded or the device is locked, then egress, using the Android Privacy Dashboard and AppOpsManager, iOS App Privacy Report and recording indicators, and MTD stalkerware classification. Flags the RECORD_AUDIO plus background-location permission cluster and MediaProjection abuse. Use when hunting stalkerware, consumer spyware, covert mic or camera recording, or hidden location tracking. Keywords: stalkerware, RECORD_AUDIO, MediaProjection, Privacy Dashboard, App Privacy Report, AppOps, background location, T1429, DET0673. Do not use for general mobile malware triage, use detecting-mobile-malware-behavior.

## Key references
- https://attack.mitre.org/techniques/T1429/
- https://attack.mitre.org/detectionstrategies/DET0673/
- https://developer.android.com/training/permissions/explaining-access (permission usage / Privacy Dashboard)
- https://support.apple.com/guide/iphone/control-app-tracking-permissions (App Privacy Report, recording indicators)
- https://stopstalkerware.org/ (Coalition Against Stalkerware — indicators and survivor safety guidance)

## Open questions / scope boundaries
- Verify the exact `AppOpsManager` op strings and the programmatic path to read permission-usage history across Android versions before writing any query.
- The permission-cluster heuristic produces false positives (legitimate recorders, dictation, nav apps); author must document an allowlist / reputation step.
- Intimate-partner-abuse context demands survivor-safety handling (do not auto-remove); this is a scope requirement, not optional.
- Must NOT cover exploit-delivered mercenary spyware (Pegasus/Predator) — that is detecting-mercenary-mobile-spyware-with-mvt — nor device-management trust abuse (detecting-malicious-mobile-configuration-profiles).
