---
name: detecting-android-accessibility-service-abuse
description: 'Detects Android Accessibility Service abuse by banking trojans and RATs (Anatsa, Cerberus, BRATA): the accessibility grant used to read screen content, draw fake login overlays, auto-grant permissions, and inject synthetic taps and text on behalf of the user (T1453 Abuse Accessibility Features, T1516 Input Injection). Works from the enabled-accessibility-services grant audit, dangerous permission combinations (accessibility bind plus screen overlay plus install-from-unknown-sources), MTD alerts from Lookout, Zimperium and Defender for Endpoint, logcat AccessibilityService traces, and Intune compliance. Use when an unexpected app holds an accessibility grant, overlays appear over banking apps, or MTD flags auto-clicker or synthetic-input behaviour. Keywords: accessibility service abuse, BIND_ACCESSIBILITY_SERVICE, input injection, overlay attack, synthetic taps, auto-clicker, Anatsa, Android, T1453, T1516. Do not use for generic mobile malware triage - use detecting-mobile-malware-behavior.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile
- android
- accessibility-service-abuse
- input-injection
- overlay-attack
- banking-trojan
- t1453
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.CM-01
- DE.AE-02
- PR.PS-01
- ID.AM-02
- PR.AA-05
mitre_attack:
- T1453
- T1516
---

# Detecting Android Accessibility Service Abuse

## When to Use

Use this skill to detect Android malware that abuses the **Accessibility API**
(ATT&CK T1453) to read on-screen content, draw fake login overlays, silently
grant its own permissions, and inject synthetic input — taps, gestures and text —
on behalf of the user (T1516 Input Injection). This is the core capability of
banking trojans and RATs such as Anatsa/TeaBot, Cerberus and BRATA. Reach for it
when:

- An unexpected, non-allowlisted app holds an accessibility grant.
- Overlays appear on top of banking or authenticator apps.
- MTD flags auto-clicker / permission auto-granting / synthetic-input behaviour.
- A sideloaded app requests the accessibility grant through the Android
  restricted-settings path.

For generic suspicious-app triage without this specific vector, use
`detecting-mobile-malware-behavior`. For whole-device root use
`detecting-mobile-device-rooting-and-jailbreak`; for Frida/Xposed app
instrumentation use `detecting-mobile-runtime-hooking-and-instrumentation`.

## Prerequisites

- **Accessibility-grant inventory (primary signal).** Which apps hold an
  accessibility grant, from MDM/MTD app inventory, the Android Enterprise
  managed-configuration / permission report, or — for a single device under
  investigation — the Android secure setting that lists enabled accessibility
  services (illustratively `enabled_accessibility_services`; verify the exact key
  against current Android docs) read via `adb shell settings get secure ...` or a
  `bugreport`.
- **An org allowlist** of legitimate assistive / automation apps that are
  *expected* to hold the grant. Detection is a diff against this list.
- **MTD**: Lookout, Zimperium zIPS, or Microsoft Defender for Endpoint (mobile)
  feeding device-threat level into Intune compliance.
- **Forensics**: ADB/logcat and `bugreport` for a device pulled for triage;
  optionally MVT for IOC triage, MobSF/VirusTotal for APK vetting.

## Workflow

1. **Baseline** the allowlist of apps that may legitimately hold an accessibility
   grant (screen readers, password managers, legitimate automation, OEM assistive
   tools). Everything else is suspect.
2. **Non-allowlisted accessibility grant (highest-value rule).** Enumerate the
   apps holding an accessibility grant from inventory; any package not on the
   allowlist raises an alert. Behavioural framing beats string matching here: the
   signal is *an unexpected app holding a powerful grant*, independent of the exact
   setting key.
3. **Dropper / trojan permission profile.** Raise severity when the same package
   combines the accessibility grant with a screen-overlay capability
   (illustratively `SYSTEM_ALERT_WINDOW`), install-from-unknown-sources
   (illustratively `REQUEST_INSTALL_PACKAGES`), broad package visibility, or SMS
   permissions, **and** was sideloaded (installer is not the Play Store) or loads
   code dynamically. Anatsa droppers specifically walk the user through the
   restricted-settings path to re-enable the grant — flag that prompt flow.
4. **Input-injection / overlay behaviour (T1516).** Use MTD runtime alerts for
   synthetic input (auto-clicking, automatic permission granting), accessibility
   reads of other apps' fields, and overlays over banking apps. Correlate with SMS
   interception or notification access from the same package (a multi-capability
   trojan).
5. **Fleet correlation.** Join MTD device-threat events to Entra ID sign-in risk;
   surface devices where an accessibility-abuse alert precedes a sensitive app
   launch or a corporate sign-in.
6. **Respond** (see *Response*).

## Key Concepts

- **The grant is the chokepoint.** Reading other apps' screens, overlaying them,
  and injecting input all require the accessibility grant. Auditing *who holds it*
  against an allowlist is the single highest-value detection and does not depend on
  any malware signature.
- **Behavioural over constant.** Exact setting keys and permission constants drift
  across Android versions; treat any constant here as illustrative and verify it.
  The durable signal is "an app that should not have this grant has it, and is
  acting on it."
- **Permission clusters classify intent.** Accessibility + overlay + unknown-source
  install + SMS is the classic banking-trojan profile; accessibility alone on a
  known assistive app is benign.
- **Restricted-settings bypass.** Modern Android restricts accessibility grants for
  sideloaded apps; malware coaches the user around the restriction, so the
  *user-prompt flow* is itself an indicator.

## Tools & Systems

Android Enterprise / managed Google Play (app inventory, permission report),
Microsoft Intune compliance + Entra Conditional Access, Lookout, Zimperium zIPS,
Microsoft Defender for Endpoint (mobile), Google Play Protect, ADB/logcat,
`bugreport`, MVT, MobSF, VirusTotal. Allowlist legitimate assistive/automation
apps. Trojan families named for recognition only: Anatsa/TeaBot, Cerberus, BRATA.

## Detection Queries

Treat field names, setting keys and thresholds below as **verify/tune** against
your tooling and current Android docs.

### Intune / Android Enterprise -- unexpected accessibility grant (concept)

```
# Over MDM app-inventory / permission-report export:
# for each device, for each installed app granted an accessibility service,
# flag any package NOT in ACCESSIBILITY_ALLOWLIST.
packages_with_a11y_grant - ACCESSIBILITY_ALLOWLIST  -> raise("unexpected a11y grant")
# raise severity if same package also sideloaded (installer != com.android.vending)
```

### Microsoft Sentinel (KQL) -- MTD accessibility/overlay alert then sensitive sign-in

```kql
// verify table/column names for your MTD + Defender connector
DeviceTvmThreatEvents
| where ThreatName has_any ("accessibility", "overlay", "auto-click", "input injection")
| project TimeGenerated, DeviceId, UserPrincipalName, ThreatName
| join kind=inner (
    SigninLogs
    | where AppDisplayName in ("<corporate apps>")   // verify/tune
    | project SigninTime=TimeGenerated, UserPrincipalName, AppDisplayName, RiskLevelDuringSignIn
  ) on UserPrincipalName
| where SigninTime between (TimeGenerated .. TimeGenerated + 1h)
```

### ADB / logcat (single-device triage, concept)

```
adb shell settings get secure enabled_accessibility_services   # verify exact key
adb logcat | grep -Ei 'AccessibilityService|AccessibilityManager|addView.*TYPE_APPLICATION_OVERLAY'
# cross-check: any non-system package binding an accessibility service, or drawing an overlay
```

## Common Scenarios

- **Anatsa dropper:** benign-looking utility sideloaded, prompts the user through
  restricted settings to enable accessibility, later pulls a DEX payload and
  overlays a banking app — unexpected-grant rule plus sideload plus dynamic load.
- **Cerberus/BRATA RAT:** accessibility grant drives auto-clicking and permission
  self-granting; MTD raises synthetic-input behaviour.
- **False positive:** an allowlisted password manager or screen reader holding the
  grant — excluded by the allowlist, so it never alerts.

## Output Format

```
ACCESSIBILITY SERVICE ABUSE DETECTION
  Device:          <device id / user>
  Verdict:         <confirmed | suspected | allowlisted-benign>
  Package:         <suspect app package + installer source>
  Grant:           <accessibility grant held: yes/no, not on allowlist>
  Profile:         <accessibility + overlay + unknown-source + SMS? ...>
  Behaviour:       <synthetic input | overlay over <app> | permission auto-grant | screen read>
  Correlation:     <MTD alert -> sensitive sign-in | SMS/notif access same package>
  ATT&CK:          T1453, T1516
  Actions taken:   <marked non-compliant | CA block + session revoke | selective wipe | app removed>
```

## Response

- **Contain:** mark the device non-compliant on the MTD accessibility-abuse /
  malicious-app verdict, block corporate access via Conditional Access, and revoke
  active sessions. Selective-wipe the work profile; remove the offending package.
- **Harden:** Android Enterprise work profile with managed Google Play only; deny
  accessibility and overlay grants and install-from-unknown-sources by policy; keep
  Play Protect enabled. Educate users that legitimate apps rarely need the
  accessibility grant, and that an app coaching them through "restricted settings"
  to enable it is a red flag.
