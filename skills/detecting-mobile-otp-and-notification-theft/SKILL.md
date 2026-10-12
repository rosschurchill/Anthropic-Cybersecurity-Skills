---
name: detecting-mobile-otp-and-notification-theft
description: 'Detects mobile theft of inbound one-time passcodes and sensitive push content: Android apps abusing NotificationListenerService to read 2FA codes from the notification shade, and apps reading or receiving SMS through the SMS content provider to harvest inbound OTPs (T1517 Access Notifications, T1636 Protected User Data). Works from the notification-access grant audit (enabled notification listeners), the SMS permission audit (SMS read or receive on a non-default-SMS app), MTD behavioural alerts, and identity-side OTP correlation in Entra ID, Okta and Duo sign-in logs. Use when an unexpected app holds notification access or SMS read permission, or a delivered OTP is consumed from unexpected infrastructure. Keywords: OTP theft, NotificationListenerService, BIND_NOTIFICATION_LISTENER_SERVICE, SMS interception, RECEIVE_SMS, 2FA code stealing, Android, T1517, T1636. Do not use for the accessibility overlay and synthetic-input vector - use detecting-android-accessibility-service-abuse.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile
- android
- otp-theft
- notification-access
- sms-interception
- two-factor
- t1517
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.AE-02
- DE.CM-01
- PR.AA-05
- ID.AM-02
- PR.PS-01
mitre_attack:
- T1517
- T1636
---

# Detecting Mobile OTP and Notification Theft

## When to Use

Use this skill to detect mobile apps that steal **inbound** one-time passcodes
and sensitive push content: a notification reader that captures 2FA codes shown
in the notification shade (ATT&CK T1517 Access Notifications), or an app that
reads / receives SMS through the SMS content provider to harvest OTPs (T1636
Protected User Data). This is the harvesting of authentication secrets as they
arrive — the capability that lets a trojan complete an attacker's MFA step. Reach
for it when:

- An unexpected, non-allowlisted app holds notification-listener access.
- A non-default-SMS, non-carrier app holds SMS read/receive permission.
- A delivered SMS-OTP or push is consumed from unexpected infrastructure.

Scope is codes/notifications that **already arrived on the device**. For the
accessibility-overlay and synthetic-input vector (fake login screens, auto-clicking)
use `detecting-android-accessibility-service-abuse`. For off-device, carrier-side
number takeover use `detecting-sim-swap-attacks`.

## Prerequisites

- **Notification-listener inventory (primary signal).** Which apps hold
  notification access, from MDM/MTD app inventory, the Android Enterprise
  permission report, or — for a single device — the Android secure setting listing
  enabled notification listeners (illustratively `enabled_notification_listeners`;
  verify the exact key against current Android docs) via `adb shell settings get
  secure ...` or a `bugreport`.
- **SMS permission inventory.** Which apps hold SMS read/receive and which app is
  the default SMS handler (default-SMS-role changes are themselves a signal).
- **Allowlists** of apps that may legitimately hold each grant: wearable companion
  apps and legitimate automation for notification access; the default SMS app and
  carrier/backup apps for SMS.
- **Identity logs.** Entra ID sign-in logs (authentication detail / MFA method),
  Okta System Log, Duo — for the OTP-consumption correlation.
- **MTD**: Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile).

## Workflow

1. **Baseline** the notification-access and SMS allowlists per the fleet.
2. **Non-allowlisted notification-listener grant (highest-value rule).** Enumerate
   apps holding notification access; any package off the allowlist alerts.
   Notification access is the cleanest path to read a code straight out of the
   shade, so this is the primary signal. Frame it behaviourally — an unexpected app
   holding the grant — rather than on an exact setting string.
3. **SMS-reader profile.** Alert when an app holds SMS read/receive but is neither
   the default SMS handler nor a known carrier/backup app. Raise severity if it
   also has internet access, notification access, or an accessibility grant (a
   multi-capability trojan — pivot to
   `detecting-android-accessibility-service-abuse`).
4. **OTP correlation (identity side).** Flag a successful MFA where the SMS/push
   was delivered to a device currently flagged non-compliant/threat by MTD, or
   where OTP consumption geography/ASN differs from the delivery context, or where
   the code is used faster than a human plausibly could. Join identity sign-in logs
   to Intune/MTD device-threat state.
5. **Fleet hunt.** A new grant of notification or SMS access shortly after a
   sideload, or appearing together with an accessibility grant from the same
   package, indicates a multi-capability trojan.
6. **Respond** (see *Response*).

## Key Concepts

- **Inbound-secret harvesting, not SMS sending.** This vector reads codes that
  arrive; sending SMS or carrier-side takeover is out of scope.
- **Two capture paths, one goal.** NotificationListener reads anything rendered in
  the shade (including authenticator and SMS-OTP notifications); SMS read/receive
  pulls the message directly. Either lets the attacker satisfy an MFA prompt.
- **Grant audit beats signature.** Exact setting keys and permission constants
  drift; verify them and treat them as illustrative. The durable signal is an
  unexpected app holding notification access or non-default SMS access.
- **The identity side confirms impact.** An on-device grant plus an OTP consumed
  from foreign infrastructure is a far stronger, higher-confidence finding than
  either alone.
- **SMS-OTP is the weak factor.** A stolen code is only useful because SMS/shade
  codes are phishable; moving users to phishing-resistant MFA removes the payoff.

## Tools & Systems

Android Enterprise / managed Google Play (inventory, permission report), Microsoft
Intune compliance + Entra Conditional Access, Entra ID sign-in logs, Okta System
Log, Duo, Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile),
ADB/logcat, `bugreport`, MVT, Google Play Protect. Families named for recognition
only: AbstractEmu, Anatsa/TeaBot, Cerberus.

## Detection Queries

Treat field names, setting keys and thresholds as **verify/tune**.

### Intune / Android Enterprise -- unexpected notification or SMS access (concept)

```
# Over MDM app-inventory / permission-report export:
notif_listeners - NOTIF_LISTENER_ALLOWLIST            -> raise("unexpected notification access")
apps_with_sms_read_or_receive - DEFAULT_SMS - CARRIER -> raise("non-default app reads SMS")
# raise severity if same package also sideloaded or holds an accessibility grant
```

### Microsoft Sentinel (KQL) -- SMS-OTP success on an MTD-flagged device

```kql
// verify table/column names for your identity + MTD connectors
SigninLogs
| mv-expand todynamic(AuthenticationDetails)
| where AuthenticationDetails.authenticationMethod in ("Text message", "SMS")  // verify/tune
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, DeviceDetail, IPAddress
| join kind=inner (
    DeviceTvmThreatEvents            // MTD device-threat feed; verify table
    | where ThreatName has_any ("notification listener", "sms", "otp", "interception")
    | project ThreatTime=TimeGenerated, UserPrincipalName, DeviceId, ThreatName
  ) on UserPrincipalName
| where ThreatTime between (TimeGenerated - 24h .. TimeGenerated)
```

### ADB / logcat (single-device triage, concept)

```
adb shell settings get secure enabled_notification_listeners   # verify exact key
adb logcat | grep -Ei 'NotificationListenerService|onNotificationPosted'
# plus: enumerate packages granted SMS read/receive that are not the default SMS app
```

## Common Scenarios

- **Banker reading the shade:** a sideloaded app gains notification access and
  silently forwards authenticator and bank SMS-OTP notifications — unexpected-grant
  rule fires; identity side shows the code reused elsewhere.
- **SMS stealer:** non-default app with RECEIVE_SMS forwards inbound 2FA texts;
  default-SMS-role never changed, so SMS-reader profile catches it.
- **Account-takeover confirmation:** MFA success where the OTP device is
  MTD-flagged and the sign-in ASN differs from the user's norm.
- **False positive:** an allowlisted smartwatch companion app mirroring
  notifications — excluded by the allowlist.

## Output Format

```
OTP / NOTIFICATION THEFT DETECTION
  Device:          <device id / user>
  Verdict:         <confirmed | suspected | allowlisted-benign>
  Package:         <suspect app + installer source>
  Grant:           <notification access | SMS read/receive on non-default app>
  Co-factors:      <internet + accessibility + sideloaded? ...>
  Identity signal: <SMS-OTP success on MTD-flagged device | consumption ASN/geo mismatch | code reused too fast>
  ATT&CK:          T1517, T1636
  Actions taken:   <non-compliant + CA block | session revoke | moved user off SMS MFA | app removed>
```

## Response

- **Contain:** block and revoke sessions when the OTP-delivery device is
  MTD-flagged; selective-wipe the work profile; remove the offending package.
- **Reduce the payoff:** move users from SMS-OTP to phishing-resistant / app-based
  MFA so a stolen inbound code is useless.
- **Harden:** managed Google Play only; deny notification-access and SMS grants to
  non-default apps by policy; advise developers to keep secrets out of notification
  text so a shade reader captures nothing useful.
