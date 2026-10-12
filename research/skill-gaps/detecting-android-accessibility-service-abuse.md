# Detecting Android Accessibility Service Abuse — research notes

- **Proposed slug:** detecting-android-accessibility-service-abuse
- **ATT&CK (Mobile):** T1453 Abuse Accessibility Features — folds in T1516 Input Injection (synthetic taps / text entry), and relates to T1417.001 Input Capture: Keylogging and T1516/overlay credential capture
- **Status:** research (not yet a skill)

## Defensive goal
Detect Android malware that abuses the Accessibility API to read screen content,
overlay fake login screens, auto-grant its own permissions, and inject synthetic
input (taps/gestures/text) on the user's behalf — the core capability of banking
trojans and RATs such as Anatsa/TeaBot, Cerberus and BRATA. The detection catches
an accessibility grant to a non-allowlisted app and the behavioural traces of
input injection and overlay abuse, from both MDM/MTD telemetry and forensic logs.

## Data sources / telemetry
- **Accessibility-grant audit (primary signal).** The Android secure setting
  `enabled_accessibility_services` lists every service the user has enabled; a
  service declares the `android.permission.BIND_ACCESSIBILITY_SERVICE` permission
  in its manifest. Readable via `adb shell settings get secure
  enabled_accessibility_services` and in a `bugreport`. MDM/MTD app inventory and
  the Android Enterprise managed-configuration/permission report expose which
  apps hold accessibility grants.
- **MTD behavioural alerts.** Lookout, Zimperium zIPS and Microsoft Defender for
  Endpoint (mobile) raise on sideloaded/known-trojan apps and on
  accessibility/overlay abuse; these feed Intune compliance.
- **Permission combination.** Dangerous combos in the manifest / granted set:
  BIND_ACCESSIBILITY_SERVICE + `SYSTEM_ALERT_WINDOW` (overlay) + `QUERY_ALL_PACKAGES`
  + `REQUEST_INSTALL_PACKAGES` (dropper) + SMS permissions — classic trojan profile.
- **Forensics / logcat.** `adb logcat` entries from `AccessibilityManager` /
  `AccessibilityService` for a non-system package; `SYSTEM_ALERT_WINDOW` overlay
  draws; dynamically downloaded DEX/payload (Anatsa multi-stage droppers). MVT
  can triage Android backups/ADB output against IOC sets.
- **Play Protect / app-vetting.** Play Protect verdicts; MobSF/VirusTotal static
  flags on the APK (accessibility service + overlay + dynamic code loading).

## Detection logic / approach
1. **Non-allowlisted accessibility grant.** Enumerate
   `enabled_accessibility_services`; diff against an org allowlist of legitimate
   assistive/automation apps. Any other package holding the grant → alert. This
   is the single highest-value rule.
   ```
   # pseudo-rule
   svc = settings.secure.enabled_accessibility_services
   for pkg in svc.packages:
       if pkg not in ACCESSIBILITY_ALLOWLIST: alert(pkg, "unexpected a11y grant")
   ```
2. **Dropper/trojan permission profile.** App has BIND_ACCESSIBILITY_SERVICE +
   SYSTEM_ALERT_WINDOW and is sideloaded (installer != com.android.vending) or
   loads code dynamically → high severity. Anatsa droppers bypassed Android 13
   restricted-settings specifically to re-enable the a11y grant — flag apps that
   prompt the user through the restricted-settings path.
3. **Input injection / overlay behaviour (T1516).** MTD runtime alert for
   synthetic-input automation (permission auto-granting, auto-clicking),
   accessibility-driven screen reads of other apps' fields, and overlays on top
   of banking apps. Correlate with SMS interception from the same package.
4. **Fleet KQL (Defender for Endpoint / Sentinel).** Join MTD device-threat
   events to Entra sign-in risk; surface devices where an a11y-abuse alert
   precedes a sensitive app launch.

## Response / mitigation
Conditional Access: mark device non-compliant and block corporate access on MTD
accessibility-abuse / malicious-app verdict; revoke sessions. Push a compliance
policy that fails on the malicious package and on sideloading
(`REQUEST_INSTALL_PACKAGES` from unknown sources). Remote-wipe or selective-wipe
managed profile. Harden: Android Enterprise work profile with managed Google Play
only; restrict SYSTEM_ALERT_WINDOW and accessibility grants via policy; user
education that legitimate apps rarely need the accessibility grant. Keep Play
Protect enabled.

## Real tools
Android secure settings (`enabled_accessibility_services`), ADB/logcat,
`bugreport`, Android Enterprise / managed Google Play, Microsoft Intune
compliance + Conditional Access, Lookout, Zimperium zIPS, Microsoft Defender for
Endpoint (mobile), Google Play Protect, MobSF, VirusTotal, MVT. Trojan family
names for recognition only: Anatsa/TeaBot, Cerberus, BRATA.

## Draft frontmatter mappings
- mitre_attack: [T1453, T1516]
- nist_csf: [DE.CM-09, DE.CM-01, DE.AE-02, PR.PS-01, ID.AM-02, PR.AA-05]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-malware-behavior

## Draft description (<=1024 chars)
Detects Android Accessibility Service abuse by banking trojans and RATs (Anatsa,
Cerberus, BRATA) — the accessibility grant used to read screen content, draw fake
login overlays, auto-grant permissions, and inject synthetic taps and text on the
user's behalf (T1453, T1516 Input Injection). Works from the
enabled_accessibility_services grant audit, dangerous permission combinations
(BIND_ACCESSIBILITY_SERVICE plus SYSTEM_ALERT_WINDOW plus install-from-unknown),
MTD behavioural alerts (Lookout, Zimperium, Defender for Endpoint mobile), logcat
AccessibilityManager traces, and Intune compliance. Use when an unexpected app
holds an accessibility grant, overlays appear over banking apps, or MTD flags
auto-clicker behaviour. Keywords: accessibility service abuse, BIND_ACCESSIBILITY_SERVICE,
input injection, overlay attack, Anatsa, auto-clicker, T1453, T1516. Do not use
for generic mobile malware triage - use detecting-mobile-malware-behavior.

## Key references
- MITRE ATT&CK Mobile T1453 Abuse Accessibility Features: https://attack.mitre.org/techniques/T1453/
- MITRE ATT&CK Mobile T1516 Input Injection (+ DET0612): https://attack.mitre.org/techniques/T1516/
- ThreatFabric Anatsa campaign write-up: https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach
- Android accessibility API docs (verify constant names): https://developer.android.com/guide/topics/ui/accessibility/service
- Microsoft Intune Mobile Threat Defense: https://learn.microsoft.com/mem/intune/protect/mobile-threat-defense

## Open questions / scope boundaries
- Author must decide the allowlist baseline (which assistive/automation apps are
  legitimate in the fleet) and how to ingest the grant list at scale (MDM
  inventory vs ADB vs MTD).
- MUST NOT cover whole-device root/jailbreak (that is
  detecting-mobile-device-rooting-and-jailbreak) nor app-specific Frida/Xposed
  hooking (detecting-mobile-runtime-hooking-and-instrumentation). This skill is
  specifically the Accessibility grant + overlay + synthetic-input vector.
- Verify the exact secure-setting key and permission constant against current
  Android docs before shipping pseudo-rules.
