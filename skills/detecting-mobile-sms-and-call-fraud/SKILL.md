---
name: detecting-mobile-sms-and-call-fraud
description: 'Detects fraud through the messaging and telephony of an Android or iOS device: sending premium-rate SMS, WAP and direct-carrier-billing toll-fraud subscriptions, and covertly sending or deleting texts (T1582), plus making, forwarding, redirecting, blocking, or auto-answering calls without consent (T1616). Uses MDM app-vetting of SEND_SMS, RECEIVE_SMS, default-SMS, call-redirection and call-screening roles, MTD toll-fraud and fleeceware reputation, carrier and store billing for premium short-codes and WAP billing, and MobSF detection of silent WAP-billing WebView flows, SMS suppression, and Wi-Fi-disabling behaviour. Use when a device incurs premium-SMS or carrier-billing charges, an app holds unexpected SMS or call-control roles, or carrier fraud notices vanish. Keywords: premium SMS, WAP billing, toll fraud, Joker, carrier billing, default SMS role, call redirection, call forwarding, T1582, T1616. Do not use for reading inbound OTP or notification codes - use detecting-mobile-otp-and-notification-theft.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- android
- ios
- toll-fraud
- premium-sms
- wap-billing
- call-control
- carrier-billing
- t1582
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
- T1582
- T1616
---

# Detecting Mobile SMS and Call Fraud

## When to Use

Use this skill to detect fraud that **acts through** the device's messaging and
telephony — the outbound fraud/impact action, not inbound code theft:

- **SMS control (T1582)** — sending premium-rate SMS, driving WAP /
  direct-carrier-billing toll-fraud subscriptions, and covertly sending or
  deleting texts without user approval.
- **Call control (T1616)** — making, forwarding, redirecting, blocking, or
  auto-answering calls without consent (premium-rate dialing, call-forwarding to
  intercept, or blocking the carrier's fraud-alert line).

Reach for it when a device **incurs premium-SMS or carrier-billing charges**, an
app holds unexpected SMS or call-control roles, or carrier fraud notices vanish.

**Platform reality:** every on-device mechanism below is **Android-only** —
third-party iOS apps cannot hold an SMS-send or call-control role, so on iOS this
detection reduces to carrier-side signals: billing / CDR review for premium-rate
dialling and premium-SMS or carrier-billing charges, plus the carrier's own
fraud-management alerts.

**Scope boundary (hold this line):** this skill is the *billing/impact and
call-control* action. Reading inbound OTP codes or notification contents for
account takeover is a different objective — use
`detecting-mobile-otp-and-notification-theft`.

## Prerequisites

Mobile detection has **no raw host agent with syscall telemetry** — and much of
the billing evidence is carrier-side, so state which signals need a carrier feed:

- **Permission telemetry via MDM app-vetting** (Microsoft Intune, Jamf Pro,
  VMware Workspace ONE, Android Enterprise): apps holding SMS send/receive
  permissions or acquiring the **default-SMS-handler role**; call permissions and
  the **call-redirection** and **call-screening** roles; phone-state access.
  `ROLE_SMS`, `ROLE_CALL_REDIRECTION` and `ROLE_CALL_SCREENING` are documented
  `android.app.role.RoleManager` constants; the hedge belongs on the **MDM/MTD
  field names** that surface them, which vary by connector — verify those against
  your vendor's current schema. Accessibility service as a cross-check
  (used to auto-click subscription confirmations and dismiss carrier notices).
- **Store / billing & carrier signals**: premium-SMS and WAP / direct-carrier-
  billing charges; carrier fraud-management systems flagging short-code or
  premium-number traffic; auto-confirmation and then suppression of the
  **carrier's** subscription-confirmation SMS (inbound code theft for account
  takeover stays with `detecting-mobile-otp-and-notification-theft`).
  WAP/direct-carrier-billing visibility is **largely carrier-side** — it needs a
  carrier fraud-management feed, not on-device telemetry.
- **MTD app-reputation** (Lookout, Zimperium zIPS, Microsoft Defender for
  Endpoint on mobile, Jamf Threat Defense — formerly Wandera): toll-fraud /
  premium-SMS / fleeceware classifications; network protection on C2 pushing
  target premium numbers or carrier configs.
- **App-vetting / dynamic analysis** (MobSF, Google Play Protect): SMS-send calls
  to short-codes; silent WebView navigation through carrier billing-confirmation
  pages; `abortBroadcast`-style suppression of inbound SMS; dropper dynamic code
  loading; keeping traffic on **cellular** (disabling Wi-Fi) to force carrier
  billing — a documented toll-fraud behaviour.
- **Forensics**: Android `bugreport` / telephony SMS and call logs (with
  authorisation), logcat, iOS `sysdiagnose`; carrier CDR / itemised-bill review.

## Workflow

1. **Allowlist the legitimate holders first.** Sanctioned dialers, messaging apps
   and carrier apps legitimately hold SMS and call roles — allowlist them before
   alerting on anything else.
2. **Premium / WAP toll fraud (T1582).** Flag apps that send SMS to premium
   short-codes or drive WAP / direct-carrier-billing subscriptions, especially
   combined with (a) auto-confirming the carrier's subscription-confirmation SMS
   or WebView prompt, (b) suppressing or deleting that carrier notice so the
   charge goes unnoticed, and (c) disabling Wi-Fi to force cellular billing.
   Because Play restrictions on SMS-send and the default handler
   pushed many families (Joker/Bread) toward WAP billing, **weight the WAP-billing
   WebView flow, not just the SMS-send permission**.
3. **SMS control / covert send-delete (T1582).** Non-default-SMS apps sending
   texts, or apps that both send and silently delete from the SMS store to hide
   activity.
4. **Call control (T1616).** Unexpected use of the call-redirection or
   call-screening role, programmatic call forwarding (e.g. an MMI/USSD
   forwarding string dialed via a call permission — verify the mechanism),
   auto-answer, or blocking of specific inbound numbers (the carrier fraud line).
   Alert on untrusted apps holding these roles.
5. **Behavioural corroboration.** The high-confidence combination is a
   recently-installed, low-reputation app holding SMS/call roles **plus**
   accessibility **plus** billing charges.
6. **Respond** (see *Response*).

## Key Concepts

- **Outbound impact, not inbound capture.** This skill is about billing the victim
  and controlling calls; inbound OTP/notification reading for takeover is the
  separate sibling.
- **WAP billing is the modern path.** Store restrictions on SMS-send moved
  toll-fraud families to WAP/direct-carrier-billing WebView flows — a detector
  that only watches SMS-send permissions misses most current fraud.
- **Suppression is part of the fraud.** Deleting or aborting the carrier's
  confirmation SMS and dismissing its notices is how the charge stays hidden —
  vanishing carrier notices are a signal.
- **Carrier feed is load-bearing for billing.** Premium-SMS and WAP charges are
  mostly visible only carrier-side; name that dependency explicitly.
- **Wi-Fi off to force cellular** is a documented toll-fraud tell that on-device
  vetting can see even when the billing itself is carrier-side.

## Tools & Systems

Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Jamf Threat
Defense (formerly Wandera); Microsoft Intune, Jamf Pro, VMware Workspace ONE,
Google Android Enterprise + Play Protect; MobSF; carrier fraud-management / CDR review; Android
`bugreport`/telephony logs, iOS `sysdiagnose`. Malware families for recognition
only: Joker, Bread, and Wi-Fi-disabling toll-fraud variants.

## Detection Queries

Treat thresholds, connector field names and dial strings as **verify/tune**
against current Android/Apple and carrier docs. The `RoleManager` role
constants are documented, stable API surface and can be relied on as written.

### KQL (Sentinel / Defender) — untrusted app holding SMS or call-control roles

```kql
// verify table/column names against your schema
MobileAppInventory
| where Roles has_any ("ROLE_SMS","ROLE_CALL_REDIRECTION","ROLE_CALL_SCREENING")
   or Permissions has_any ("SEND_SMS","ANSWER_PHONE_CALLS","CALL_PHONE")
| where AppId !in (ApprovedDialerMessagingCarrierAllowlist)
| join kind=leftouter (MobileThreatInfo
    | where ThreatClass in ("toll-fraud","premium-sms","fleeceware")) on AppId
| project DeviceId, AppId, PackageName, Roles, Permissions, ThreatClass
```

### Carrier billing correlation (concept)

```
Join carrier fraud-management / CDR premium-SMS and WAP-billing charges to the
device and its recently installed apps. A premium/WAP charge within a short
window of installing a low-reputation app holding SMS/accessibility roles is the
high-confidence combination. Billing visibility requires the carrier feed.
```

### MobSF — silent WAP-billing WebView + SMS suppression (concept)

```
Scan the MobSF report for: WebView navigation through carrier billing-confirmation
pages with no user interaction; abortBroadcast-style suppression of inbound SMS;
SMS-send to short-codes; and code that disables Wi-Fi to force cellular billing.
Weight the WAP WebView flow even when SEND_SMS is absent.
```

### Call-control (T1616) — concept

```
Flag programmatic call forwarding (MMI/USSD forwarding string via a call
permission), auto-answer, or blocking of the carrier fraud-alert number by an
app outside the dialer allowlist. Verify the forwarding mechanism (dial string
vs telephony API) before encoding a rule.
```

## Common Scenarios

- **Joker-style WAP toll fraud:** a low-reputation app drives a WAP-billing
  WebView subscription, auto-confirms and then deletes the carrier's
  subscription-confirmation SMS, and disables Wi-Fi — carrier charge + suppression + Wi-Fi-off fire.
- **Premium-SMS sender:** a non-default-SMS app sends to premium short-codes and
  deletes the sent record.
- **Call interception:** an untrusted app sets call forwarding and blocks the
  carrier fraud line.
- **False positive:** the sanctioned default messaging app and dialer holding SMS
  and call roles — excluded by the allowlist.

## Output Format

```
MOBILE SMS / CALL FRAUD DETECTION
  Device:          <device id / user>
  App:             <package name / version / install source>
  Verdict:         <confirmed | suspected | sanctioned-allowlisted>
  Fraud type:      <premium SMS | WAP/carrier billing | covert send-delete | call forward/redirect | call block/auto-answer>
  Signal:          <role/permission | carrier/billing charge | WAP WebView flow | SMS suppression | Wi-Fi-off | MTD reputation>
  Carrier:         <premium short-code / WAP charge reference, if from carrier feed>
  ATT&CK:          <T1582 | T1616>
  Actions taken:   <quarantined | marked non-compliant | app removed | carrier charges reversed / blocks enabled>
```

## Response

- **Contain:** quarantine/remove the offending app via MDM and mark the device
  non-compliant. Restrict which apps may hold the default-SMS, call-redirection
  and call-screening roles via MDM, block install to managed Play/VPP, disallow
  sideloading, and keep Play Protect on.
- **Engage the carrier:** reverse premium charges and enable premium-SMS /
  short-code and direct-carrier-billing blocks on managed lines.
- **User guidance:** review itemised bills and watch for disappearing carrier
  notices.
- **For confirmed compromise:** wipe and re-provision.
