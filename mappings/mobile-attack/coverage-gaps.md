# MITRE ATT&CK for Mobile — coverage-gap triage

Computed against the local ATT&CK for Mobile v19.2 STIX.

- **Base techniques (non-deprecated, non-revoked):** 77
- **Covered by ≥1 skill:** 47 (61%)
- **Uncovered:** 30

All 14 Tier-A skills below are **shipped and merged**; coverage rose from 12/77
(16%) at review time to 47/77 (61%). The remaining 30 are Tier B/C by the triage
below, not a backlog.

The existing coverage is almost entirely offense/analysis/forensics
(`analyzing-android-malware-with-apktool`, `analyzing-ios-app-security-with-objection`,
`conducting-mobile-app-penetration-test`, the MobSF/JADX/Frida/Cellebrite skills) plus one
broad `detecting-mobile-malware-behavior`. The blue-team **detection** side is the real gap.

Mobile detection does not look like endpoint detection: there is rarely a host agent with raw
syscall telemetry. Signal comes from **MDM/UEM** (Intune, Jamf, Workspace ONE, Android Enterprise),
**Mobile Threat Defense** (Lookout, Zimperium, Microsoft Defender for Endpoint on mobile, Wandera),
**device attestation** (Play Integrity, iOS App Attest / DeviceCheck), **Google Play Protect**,
**iOS supervision / configuration-profile inventory**, **MVT (Mobile Verification Toolkit)** for
forensic spyware triage, carrier/IAM/account telemetry, and app-vetting pipelines.

## Triage tiers

- **Tier A — build a detection skill (14).** Mobile-specific, concretely detectable from the
  telemetry above, and distinct from each other and from `detecting-mobile-malware-behavior`.
- **Tier B — fold into an existing (mostly Enterprise) skill.** The technique shares its T-id with
  Enterprise and the detection is not meaningfully mobile-specific, or an existing skill already owns
  the behaviour.
- **Tier C — atomic primitive / impact outcome.** Not independently detectable, or an outcome rather
  than a behaviour; skip.

## Tier A build queue (14) — all shipped

| ATT&CK (Mobile) | Technique(s) folded in | Proposed slug |
|---|---|---|
| T1453 | (+T1516 Input Injection) | `detecting-android-accessibility-service-abuse` |
| T1517 | (+T1636 Protected User Data) | `detecting-mobile-otp-and-notification-theft` |
| T1451 | — | `detecting-sim-swap-attacks` |
| T1404 | — | `detecting-mobile-device-rooting-and-jailbreak` |
| T1617 | (+T1631 Process Injection) | `detecting-mobile-runtime-hooking-and-instrumentation` |
| T1632 | (+T1638 AiTM via rogue proxy/profile) | `detecting-malicious-mobile-configuration-profiles` |
| T1577 | (+T1645, +T1661 App Versioning, +T1474 Supply Chain) | `detecting-repackaged-mobile-apps` |
| T1429 | (+T1512 Video, +T1513 Screen, +T1430 Location) | `detecting-mobile-surveillanceware` |
| T1664 | (+T1658 Client Exec, +T1456 Drive-By) | `detecting-mercenary-mobile-spyware-with-mvt` |
| T1676 | — | `detecting-malicious-device-linking` |
| T1398 | (+T1541, +T1603, +T1624, +T1625) | `detecting-mobile-malware-persistence` |
| T1663 | (+T1604 Proxy Through Victim, +T1643 Generate Traffic) | `detecting-mobile-remote-access-and-proxyware` |
| T1629 | (+T1630 Indicator Removal, +T1628 Hide Artifacts) | `detecting-mobile-security-control-tampering` |
| T1582 | (+T1616 Call Control) | `detecting-mobile-sms-and-call-fraud` |

Primary-vs-folded distinctions that keep the set collision-free:
- **accessibility abuse** (grant of the Accessibility service, overlay/auto-click) vs
  **OTP/notification theft** (NotificationListener reading inbound 2FA) vs
  **SMS/call fraud** (sending premium SMS, forwarding/intercepting calls — an *impact*, not a read).
- **rooting/jailbreak** (device integrity lost) vs **runtime hooking** (Frida/Xposed/Magisk
  instrumenting a specific app) vs **security-control tampering** (disabling Play Protect/MTD,
  revoking device-admin, hiding the app).
- **repackaged apps** (trojanized binary / malicious update in a store) vs **mercenary spyware**
  (zero-click exploit delivery, MVT forensic IOCs) vs **surveillanceware** (mic/cam/screen/location
  sensor abuse by an installed app).

## Tier B — fold into an existing skill (note the overlap, do not build)

| ATT&CK (Mobile) | Technique | Folds into |
|---|---|---|
| T1437 / T1481 / T1509 / T1544 / T1637 / T1644 | App-layer protocol, web service, non-standard port, ingress tool transfer, dynamic resolution, out-of-band data | `detecting-encoded-c2-channels`, `detecting-multi-stage-c2-channels`, `detecting-hidden-c2-infrastructure` |
| T1639 / T1646 | Exfil over alternative protocol / C2 channel | `detecting-automated-data-exfiltration` |
| T1464 / T1642 | Network / endpoint denial of service | `detecting-network-denial-of-service`, `detecting-endpoint-denial-of-service` |
| T1471 | Data encrypted for impact | ransomware-defense skills |
| T1660 | Phishing (mobile) | `executing-phishing-simulation-campaign` family / phishing-defense |
| T1634 | Credentials from password store (keychain/keystore) | mobile app assessment skills already cover insecure storage |
| T1670 | Virtualization solution (app cloning) | folds into repackaged-apps context |

## Tier C — atomic primitive / impact outcome (skip)

Discovery primitives (T1418 Software Discovery, T1420 File/Dir, T1421 Network Connections,
T1423 Network Service Scanning, T1424 Process Discovery); execution primitives (T1575 Native API,
T1623 Command and Scripting Interpreter); collection primitives (T1532 Archive Collected Data,
T1533 Data from Local System); evasion primitives (T1627 Execution Guardrails); impact outcomes
(T1640 Account Access Removal, T1641 Data Manipulation, T1662 Data Destruction); and
physical/edge cases (T1461 Lockscreen Bypass, T1458 Replication Through Removable Media,
T1428 Exploitation of Remote Services — delivery folded into mercenary-spyware).

These are not independently detectable from mobile telemetry in isolation, or they are outcomes
whose detectable behaviour is already owned by a Tier-A skill above.
