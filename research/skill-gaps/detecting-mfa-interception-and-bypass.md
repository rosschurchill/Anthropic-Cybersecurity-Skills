# Detecting MFA Interception and Bypass — research notes

- **Proposed slug:** detecting-mfa-interception-and-bypass
- **ATT&CK:** T1111 Multi-Factor Authentication Interception (tactic: credential-access) — closely related: T1621 MFA Request Generation (push "fatigue"/bombing), T1556.006 Modify Authentication Process: Multi-Factor Authentication, T1557 Adversary-in-the-Middle (AiTM), T1528 Steal Application Access Token (session-cookie/token replay)
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to adversaries defeating MFA to obtain usable authentication:
intercepting one-time codes/soft tokens (keylogging, SMS/email OTP interception,
smart-card proxying), AiTM reverse-proxy phishing that captures the post-MFA
session cookie, stolen-token/cookie replay, and MFA push "fatigue"/bombing. The
skill surfaces the identity-log and endpoint signals that reveal MFA was
subverted even though the IdP recorded "MFA satisfied."

> Scope note: T1111 proper is the *interception* case (keylogger/soft-token/
> smart-card). Push-bombing is T1621, AiTM is T1557, token replay is T1528. The
> slug's "bypass" spans these; an author should map each detector to its real
> technique ID and verify against attack.mitre.org.

## Data sources / telemetry
- **Identity provider sign-in logs** — Microsoft Entra ID sign-in logs
  (interactive **and non-interactive**), including result/error codes:
  `50074` (strong auth required), `50140`, and especially **`500121`**
  (authentication failed during MFA request / denied or no response);
  Okta System Log events: `user.mfa.attempt_bypass`, `user.mfa.okta_verify.deny_push`,
  repeated `mfa.verify` failures; Duo Admin/Auth logs (denied/fraud reports);
  AWS CloudTrail `ConsoleLogin` with MFA fields.
- **Session/token telemetry** — Entra sign-ins showing session reuse from a new
  IP/ASN, new device fingerprint, impossible-travel, or token used from unusual
  client app shortly after a legit interactive sign-in (AiTM/token replay);
  conditional-access evaluation results; refresh-token/`SessionId` reuse.
- **Endpoint (interception case)** — Sysmon/EDR: keylogger behavior (API hooks,
  `SetWindowsHookEx`, raw keyboard capture), driver loads for keyloggers,
  smart-card API (`SCardTransmit`) use in sessions not initiated by local user
  interaction; process accessing authenticator/soft-token files.
- **Email/web** — AiTM phishing landing pages (reverse-proxy kits: Evilginx,
  EvilProxy, Modlishka), newly registered look-alike auth domains, proxied
  login flows seen in URL/DNS/proxy logs.
- **MFA provider push logs** — count of push prompts and
  denials/timeouts per user (fatigue/bombing).

## Detection logic / approach
1. **MFA push fatigue / bombing (T1621)** — burst of denied/ignored MFA prompts
   then a success. Entra: filter result code `500121` (explicit denial/ignored,
   distinct from generic MFA failure), threshold N denials in window → approval:
   ```
   SigninLogs
   | where ResultType == 500121            // MFA denied/not answered
   | summarize denials=count() by UserPrincipalName, bin(TimeGenerated,10m)
   | where denials >= 5
   // then join a subsequent ResultType==0 (success) for same user/window
   ```
   Datadog ships an Entra "MFA push fatigue" default rule; Okta analog keys on
   repeated `deny_push` then success.
2. **AiTM / token replay (T1557/T1528)** — successful sign-in that *satisfied
   MFA* but the session is then used from a new IP/ASN/geo/device fingerprint,
   or a non-interactive sign-in replays a token from infrastructure never seen
   for that user. Hunt impossible-travel + new-device on non-interactive logs;
   correlate with a preceding phishing click to a reverse-proxy domain.
   Elastic ships "Attempted Bypass of Okta MFA" (`user.mfa.attempt_bypass`) and
   Entra "User Reported Suspicious Activity" prebuilt rules.
3. **Interception (T1111 proper)** — MITRE DET0246: unexpected API calls to
   capture keyboard input, keylogger driver loads, or remote smart-card
   authentication via logon sessions not initiated by local interactive user.

## Response / mitigation
Enforce **phishing-resistant MFA** (FIDO2/WebAuthn, certificate-based,
Windows Hello) — defeats AiTM, OTP interception, and fatigue (M1032). Enable
**number matching** and additional context in authenticator apps (CISA
guidance). Conditional Access: device compliance + token protection / sign-in
risk policies; revoke sessions and rotate refresh tokens on detection; shorten
token lifetimes. User-reported "I didn't request this" → auto-disable/risky
user. Block newly registered look-alike domains; user training on prompt
bombing. For interception, remediate the keylogged/compromised host.

## Real tools
Microsoft Entra ID sign-in logs + Identity Protection, Microsoft Sentinel (KQL),
Okta System Log, Duo, Elastic Security prebuilt rules, Datadog Cloud SIEM
default rules, Splunk/Sentinel, Sysmon/EDR; conditional access / token
protection; FIDO2 security keys. Attack-side kit *names* for recognition only:
Evilginx2, EvilProxy, Modlishka.

## Draft frontmatter mappings
- mitre_attack: [T1111, T1621, T1556.006, T1557, T1528]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, PR.AA-02, PR.AA-05, RS.MI-01]
- d3fend (optional): D3-MFA (Multi-factor Authentication), D3-UGLPA (User Geolocation Logon Pattern Analysis), D3-ANAA (Authentication Event Thresholding), D3-UA (User Account hardening)
- suggested subdomain: soc-operations
- nearest existing sibling (for the negative trigger): detecting-oauth-token-theft

## Draft description (<=1024 chars)
Detects MFA interception and bypass — one-time-code/soft-token interception and
keylogging (T1111), MFA push fatigue/bombing (T1621), adversary-in-the-middle
reverse-proxy phishing that steals the post-MFA session cookie (T1557), and
stolen-token/cookie replay (T1528) — using Entra ID interactive and
non-interactive sign-in logs (result code 500121, impossible-travel, new-device
token reuse), Okta/Duo MFA logs, and endpoint keylogger/smart-card telemetry.
Use when investigating suspicious MFA prompts, logins that "passed MFA" from new
infrastructure, or push-bombing reports. Keywords: MFA interception, MFA fatigue,
push bombing, AiTM, Evilginx, token replay, session cookie theft, 500121, T1111,
T1621. Do not use for OAuth application-consent/token-grant abuse — use
detecting-oauth-token-theft.

## Key references
- MITRE ATT&CK T1111 + DET0246, T1621, T1557, T1528: https://attack.mitre.org/techniques/T1111/
- Elastic prebuilt "Attempted Bypass of Okta MFA": https://www.elastic.co/guide/en/security/current/
- Datadog "Azure AD MFA push fatigue" default rule: https://docs.datadoghq.com/security/default_rules/azure-ad-mfa-push-fatigue
- Microsoft Entra sign-in error codes / Identity Protection: https://learn.microsoft.com/
- CISA number-matching & phishing-resistant MFA guidance (verify): https://www.cisa.gov/

## Open questions / scope boundaries
- Technique mapping is the key decision: this skill spans T1111/T1621/T1557/
  T1528 — confirm each detector's ID; some mappings (AiTM, push bombing) are NOT
  T1111 proper. Decide whether to narrow the skill or keep it an "MFA defeat"
  umbrella.
- Non-interactive sign-in logs are essential for token replay — ensure they are
  ingested; many tenants only watch interactive.
- Must NOT include AiTM phishing-kit setup or OTP-interception procedures — tool
  names are for recognition only.
