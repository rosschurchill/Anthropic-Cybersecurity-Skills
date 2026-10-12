# Detecting Mobile OTP and Notification Theft — research notes

- **Proposed slug:** detecting-mobile-otp-and-notification-theft
- **ATT&CK (Mobile):** T1517 Access Notifications — folds in T1636 Protected User Data (esp. T1636.004 Protected User Data: SMS Messages); relates to T1582 SMS Control
- **Status:** research (not yet a skill)

## Defensive goal
Detect mobile apps that steal inbound one-time passcodes and sensitive push
content — via `NotificationListenerService` (reads every notification, including
2FA codes shown in the shade) or by reading/receiving SMS through the SMS content
provider. This is the harvesting of *inbound* authentication secrets (not sending
SMS), the capability that lets a trojan complete an attacker's MFA step. The
detection surfaces the notification-access / SMS grant to a non-allowlisted app
and correlates with MFA/OTP delivery anomalies.

## Data sources / telemetry
- **Notification-access grant audit (primary).** A reader declares the
  `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE` permission and must be
  enabled by the user; the enabled set lives in the secure setting
  `enabled_notification_listeners` (verify exact key) — readable via
  `adb shell settings get secure enabled_notification_listeners` and in
  `bugreport`. MDM/MTD app inventory and Android Enterprise permission report
  expose it at fleet scale.
- **SMS permission audit.** `READ_SMS` / `RECEIVE_SMS` granted to a
  non-messaging, non-default-SMS app; default-SMS-app role changes. MITRE DET0681
  guidance: give RECEIVE_SMS/READ_SMS extra scrutiny on review.
- **MTD behavioural alerts.** Lookout / Zimperium zIPS / Defender for Endpoint
  (mobile) flags for notification-listener or SMS-interception behaviour and for
  the hosting trojan family.
- **Identity-side OTP anomaly.** Entra ID / Okta / Duo logs: SMS-OTP delivered
  then consumed from unexpected infrastructure, OTP used faster than human,
  authenticator push approved on a device flagged by MTD. SMS-OTP delivery
  receipts vs. where the auth completed.
- **Forensics.** logcat `NotificationListenerService` bind entries for a
  non-system package; MVT IOC triage of Android backups.

## Detection logic / approach
1. **Non-allowlisted notification-listener grant.** Enumerate
   `enabled_notification_listeners`; diff vs allowlist (wearables companion apps,
   legitimate automation). Any other package → alert — notification access is the
   cleanest path to read codes out of the shade.
   ```
   listeners = settings.secure.enabled_notification_listeners
   for pkg in listeners:
       if pkg not in NOTIF_LISTENER_ALLOWLIST: alert(pkg, "unexpected notif access")
   ```
2. **SMS-reader profile.** App holds READ_SMS/RECEIVE_SMS but is not the default
   SMS handler and not a carrier/backup app → alert; raise severity if combined
   with internet + notification access + accessibility.
3. **OTP correlation (identity side).** Successful MFA where the SMS/push was
   delivered to a device currently flagged non-compliant/threat by MTD, or where
   OTP consumption geo/ASN differs from delivery context. KQL join of SigninLogs
   (authenticationDetails / MFA method = SMS) to Intune/MTD device-threat events.
4. **Fleet hunt.** New grant of notification/SMS access shortly after a sideload
   or an accessibility grant from the same package = multi-capability trojan.

## Response / mitigation
Conditional Access: block and revoke sessions when the OTP-delivery device is
MTD-flagged; prefer **phishing-resistant / app-based MFA over SMS-OTP** so a
stolen code is useless (move users off SMS second factor). Compliance policy
fails on the malicious package and on non-default apps holding SMS/notification
access. Selective-wipe the work profile. Harden: managed Google Play only, deny
SYSTEM_ALERT_WINDOW/notification-access grants by policy, developer guidance to
keep secrets out of notification text (MITRE mitigation).

## Real tools
Android secure settings (`enabled_notification_listeners`), ADB/logcat,
`bugreport`, Android Enterprise, Microsoft Intune + Conditional Access, Entra ID
sign-in logs, Okta System Log, Duo, Lookout, Zimperium zIPS, Microsoft Defender
for Endpoint (mobile), MVT, Google Play Protect. Family names for recognition
only: AbstractEmu, Anatsa/TeaBot, Cerberus.

## Draft frontmatter mappings
- mitre_attack: [T1517, T1636, T1636.004]
- nist_csf: [DE.CM-09, DE.AE-02, DE.CM-01, PR.AA-05, ID.AM-02, PR.PS-01]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-malware-behavior

## Draft description (<=1024 chars)
Detects mobile theft of inbound one-time passcodes and sensitive push content:
apps abusing NotificationListenerService to read 2FA codes from the notification
shade, and apps reading or receiving SMS through the SMS content provider to
harvest OTPs (T1517 Access Notifications, T1636 Protected User Data / SMS). Works
from the notification-access grant audit (enabled_notification_listeners), SMS
permission audit (READ_SMS, RECEIVE_SMS on a non-default-SMS app), MTD behavioural
alerts, and identity-side OTP correlation in Entra, Okta and Duo logs. Use when an
unexpected app holds notification access or SMS read permission, or OTPs are used
from unexpected infrastructure. Keywords: OTP theft, NotificationListenerService,
BIND_NOTIFICATION_LISTENER_SERVICE, SMS interception, RECEIVE_SMS, 2FA stealing,
T1517, T1636. Do not use for carrier number takeover - use
detecting-sim-swap-attacks.

## Key references
- MITRE ATT&CK Mobile T1517 Access Notifications: https://attack.mitre.org/techniques/T1517/
- MITRE ATT&CK Mobile T1636.004 Protected User Data: SMS Messages (+ DET0681): https://attack.mitre.org/techniques/T1636/004/
- Android NotificationListenerService docs (verify constant/setting): https://developer.android.com/reference/android/service/notification/NotificationListenerService
- Microsoft Intune Mobile Threat Defense: https://learn.microsoft.com/mem/intune/protect/mobile-threat-defense

## Open questions / scope boundaries
- Author decides the allowlist for notification/SMS access (wearable companions,
  backup/carrier apps) and whether to drive the identity-side OTP correlation or
  leave it to the MFA skill.
- Verify the exact `enabled_notification_listeners` secure-setting key and SMS
  permission constants against current Android docs.
- MUST NOT cover accessibility-overlay/input injection (that is
  detecting-android-accessibility-service-abuse) nor carrier-side number takeover
  (detecting-sim-swap-attacks). Scope is stealing codes/notifications that already
  arrived on the device.
