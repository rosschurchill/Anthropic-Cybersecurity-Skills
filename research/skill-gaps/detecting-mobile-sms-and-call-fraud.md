# Detecting Mobile SMS and Call Fraud — research notes

- **Proposed slug:** detecting-mobile-sms-and-call-fraud
- **ATT&CK (Mobile):** T1582 SMS Control (tactic: impact / collection) — plus folded/related: T1616 Call Control
- **Status:** research (not yet a skill)

## Defensive goal
Detect fraud that *acts through* the device's messaging and telephony: sending
premium-rate SMS, WAP/carrier direct-billing toll-fraud subscriptions, and
deleting/sending texts without user approval (T1582); and making, forwarding,
redirecting, blocking, or auto-answering calls without consent (T1616) — e.g.
premium-rate dialing, call-forwarding to intercept, or blocking the carrier's
fraud-alert calls. Scope is the *outbound fraud/impact action* (billing the
victim, controlling calls), not reading inbound OTP codes for account takeover
(that is a separate OTP/notification-theft skill).

## Data sources / telemetry
- **Permission telemetry via MDM app-vetting** (Intune, Jamf, Workspace ONE,
  Android Enterprise): apps holding `SEND_SMS` / `RECEIVE_SMS`, or acquiring the
  **default-SMS-handler role** (`RoleManager` `ROLE_SMS`); call permissions
  `CALL_PHONE`, `ANSWER_PHONE_CALLS`, and the **call-redirection role**
  (`ROLE_CALL_REDIRECTION`) or **call-screening role** (`ROLE_CALL_SCREENING`);
  `READ_PHONE_STATE`. Accessibility service as a cross-check (used to auto-click
  subscription confirmations / dismiss carrier notices).
- **Store / billing & carrier signals:** premium-SMS and WAP/direct-carrier-
  billing charges; carrier fraud-management systems flagging short-code or
  premium-number traffic; subscription-confirmation OTP interception then
  suppression of the carrier's SMS notice (the Joker/toll-fraud pattern).
- **MTD app-reputation** (Lookout, Zimperium zIPS, Defender for Endpoint mobile,
  Wandera): toll-fraud / premium-SMS / fleeceware classifications; network
  protection on C2 that pushes target premium numbers / carrier configs.
- **App-vetting / dynamic analysis** (MobSF, Google Play Protect, Microsoft
  analysis): `SmsManager.sendTextMessage`/`sendMultipartTextMessage` to
  short-codes; silent `WebView` navigation through carrier billing confirmation
  pages; abort/`abortBroadcast`-style suppression of inbound SMS; dynamic code
  loading by droppers; keeping traffic on **cellular** (disabling Wi-Fi) to
  force carrier billing — a documented toll-fraud-malware behaviour.
- **Forensics:** Android `bugreport` / telephony provider SMS/call logs (with
  authorisation), logcat, iOS `sysdiagnose`; carrier CDR / itemised-bill review.

## Detection logic / approach
1. **Premium/WAP toll fraud (T1582):** flag apps that send SMS to premium
   short-codes, or drive WAP/direct-carrier-billing subscriptions, especially
   when combined with (a) suppressing/deleting inbound carrier confirmation SMS,
   (b) intercepting the confirmation OTP, and (c) disabling Wi-Fi to force
   cellular billing. Google restricted `SEND_SMS`/default-handler on Play, which
   pushed many families (Joker/Bread) toward WAP billing — so weight WAP-billing
   WebView flows, not just `SEND_SMS`.
2. **SMS control / covert send-delete (T1582):** non-default-SMS apps sending
   texts, or apps that both send and silently delete from the SMS store to hide
   activity.
3. **Call control (T1616):** unexpected use of the call-redirection or
   call-screening role, programmatic call forwarding (e.g. MMI/USSD
   `**21*number#` dialed via `CALL_PHONE`, verify), auto-answer via
   `ANSWER_PHONE_CALLS`, or blocking of specific inbound numbers (carrier fraud
   line). Alert on untrusted apps holding these roles.
4. **Behavioural corroboration:** a recently-installed, low-reputation app with
   SMS/call permissions + accessibility + billing charges is the high-confidence
   combination. Allowlist legitimate dialers, messaging apps, and carrier apps.

## Response / mitigation
Block app install to managed Play/VPP and disallow sideloading; restrict which
apps may hold the default-SMS, call-redirection, and call-screening roles via
MDM; keep Play Protect on (it has disabled known toll-fraud apps). Quarantine/
remove the offending app and mark the device non-compliant. Engage the carrier
to reverse premium charges and enable premium-SMS/short-code and
direct-carrier-billing blocks on managed lines. User guidance: review itemised
bills, watch for disappearing carrier notices. For confirmed compromise, wipe
and re-provision.

## Real tools
Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Wandera;
Microsoft Intune, Jamf, VMware Workspace ONE, Google Android Enterprise + Play
Protect; MobSF; carrier fraud-management / CDR review; Android `bugreport`/
telephony logs, iOS `sysdiagnose`. Malware families for recognition only: Joker,
Bread, and WiFi-disabling toll-fraud variants (Microsoft reporting).

## Draft frontmatter mappings
- mitre_attack: [T1582, T1616]
- nist_csf: [DE.CM-09, DE.CM-01, DE.AE-02, DE.AE-03, PR.PS-01, RS.MI-01, ID.AM-02]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-malware-behavior

## Draft description (<=1024 chars)
Detects fraud carried out through a device's messaging and telephony: sending
premium-rate SMS, WAP and direct-carrier-billing toll-fraud subscriptions, and
covertly sending or deleting texts (T1582), plus making, forwarding,
redirecting, blocking, or auto-answering calls without consent (T1616). Uses MDM
app-vetting of SEND_SMS/RECEIVE_SMS and default-SMS, call-redirection and
call-screening roles, MTD toll-fraud and fleeceware reputation, carrier and
store billing signals for premium short-codes and WAP billing, and MobSF
detection of silent billing-confirmation WebView flows, SMS suppression, and
Wi-Fi-disabling behaviour. Use when a device incurs premium-SMS or
carrier-billing charges, an app holds unexpected SMS or call-control roles, or
carrier fraud notices vanish. Keywords: premium SMS, WAP billing, toll fraud,
Joker, carrier billing, default SMS role, call redirection, call forwarding,
T1582, T1616. Do not use for reading inbound OTP or notification codes for
account takeover - use detecting-mobile-malware-behavior.

## Key references
- MITRE ATT&CK Mobile T1582 SMS Control: https://attack.mitre.org/techniques/T1582/
- MITRE ATT&CK Mobile T1616 Call Control: https://attack.mitre.org/techniques/T1616/
- Google Security Blog "PHA Family Highlights: Bread (and Friends)" (SMS to WAP billing): https://security.googleblog.com/2020/01/pha-family-highlights-bread-and-friends.html
- Microsoft Security blog on Android toll-fraud malware (WiFi disable, OTP/notice suppression): https://www.microsoft.com/en-us/security/blog/
- Android permissions & roles: RoleManager ROLE_SMS / ROLE_CALL_REDIRECTION / ROLE_CALL_SCREENING: https://developer.android.com/reference/android/app/role/RoleManager
- OWASP MASTG (platform API / permission analysis): https://mas.owasp.org/MASTG/

## Open questions / scope boundaries
- Verify exact `RoleManager` role constants (`ROLE_SMS`, `ROLE_CALL_REDIRECTION`,
  `ROLE_CALL_SCREENING`) and whether call-forwarding is best detected via
  MMI/USSD dial strings or telephony APIs before encoding a detector.
- WAP/direct-carrier-billing visibility is largely carrier-side; the skill must
  state which signals require a carrier fraud-management feed vs. on-device
  telemetry.
- Hold the line against the OTP-theft sibling: this skill is the *outbound
  fraud/impact* action (billing, call control), not inbound OTP capture.
- No fabricated premium numbers/short-codes or endpoints; rely on carrier/MTD
  feeds for live IOCs.
