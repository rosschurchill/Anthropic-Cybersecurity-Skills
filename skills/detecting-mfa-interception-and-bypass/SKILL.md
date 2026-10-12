---
name: detecting-mfa-interception-and-bypass
description: 'Detects MFA interception and bypass - one-time-code/soft-token interception and keylogging (MITRE T1111), MFA push fatigue/bombing (T1621), adversary-in-the-middle reverse-proxy phishing that steals the post-MFA session cookie (T1557), and stolen-token/cookie replay (T1528) - using Microsoft Entra ID interactive and non-interactive sign-in logs (result code 500121, impossible-travel, new-device token reuse), Okta and Duo MFA logs, and endpoint keylogger/smart-card telemetry. Use when investigating suspicious MFA prompts, logins that passed MFA from new infrastructure, or push-bombing reports. Keywords: MFA interception, MFA fatigue, push bombing, AiTM, Evilginx, token replay, session cookie theft, result code 500121, T1111, T1621. Do not use for OAuth application-consent and token-grant abuse - use detecting-oauth-token-theft.'
domain: cybersecurity
subdomain: soc-operations
tags:
- soc-operations
- threat-detection
- mfa
- credential-access
- aitm
- push-fatigue
- entra-id
- okta
- token-replay
- t1111
- t1621
- identity-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- PR.AA-02
- PR.AA-05
- RS.MI-01
mitre_attack:
- T1111
- T1621
- T1556.006
- T1557
- T1528
---

# Detecting MFA Interception and Bypass

## When to Use

Use this skill to detect and respond to adversaries **defeating MFA** to obtain
usable authentication, even though the IdP recorded "MFA satisfied." It is an
MFA-defeat umbrella spanning:

- **Interception (T1111 proper):** keylogging, SMS/email OTP interception,
  smart-card proxying.
- **Push fatigue / bombing (T1621):** repeated prompts until the user approves.
- **Adversary-in-the-middle (T1557):** reverse-proxy phishing (Evilginx,
  EvilProxy, Modlishka) that captures the post-MFA session cookie.
- **Token / cookie replay (T1528):** reusing a stolen session token from new
  infrastructure.

Reach for it when investigating suspicious MFA prompts, a login that "passed MFA"
but behaves oddly, or a user reporting prompt bombing. Each detector below maps
to its real technique ID. For OAuth application-consent / token-grant abuse, use
`detecting-oauth-token-theft`.

## Prerequisites

- **Entra ID sign-in logs — interactive AND non-interactive** (token replay shows
  up in non-interactive), with result/error codes; Identity Protection
  risk signals and Conditional Access evaluation results.
- **Okta System Log** (`user.mfa.attempt_bypass`, `deny_push`, repeated
  `mfa.verify` failures) and/or **Duo** Auth logs; AWS CloudTrail `ConsoleLogin`
  MFA fields.
- **Endpoint (interception)**: Sysmon/EDR for keylogger behavior
  (`SetWindowsHookEx`, raw keyboard capture), keylogger driver loads, and
  smart-card API (`SCardTransmit`) use not initiated by the local user.
- Web/DNS/proxy logs for AiTM look-alike auth domains.

## Workflow

1. **Push fatigue / bombing (T1621).** In Entra, filter result code **`500121`**
   (MFA denied / not answered); threshold N denials in a window, then join a
   subsequent success (ResultType 0) for the same user. Okta analog: repeated
   `deny_push` then success.
2. **AiTM / token replay (T1557 / T1528).** Flag a sign-in that **satisfied MFA**
   but whose session is then used from a new IP/ASN/geo/device fingerprint, or a
   **non-interactive** sign-in replaying a token from infrastructure never seen
   for that user. Correlate with a preceding click to a reverse-proxy look-alike
   domain.
3. **Interception (T1111 proper).** On endpoints, hunt keyboard-capture API use,
   keylogger driver loads, and remote smart-card auth in logon sessions not
   initiated by a local interactive user.
4. **Auth-process tampering (T1556.006).** Watch for changes to MFA
   configuration/registration (new authenticator added, MFA method downgraded).
5. **Respond** (see *Response*) — treat a user's "I didn't request this" as a
   risky-user signal and revoke sessions.

## Key Concepts

- **"MFA satisfied" is not "user authenticated":** AiTM and token replay produce
  a logged MFA success while the attacker holds the session — the tell is
  *where/how the session is then used*, not the MFA event itself.
- **Non-interactive logs are essential:** token replay largely appears there;
  tenants that only watch interactive sign-ins miss it.
- **`500121` is the push-bombing signal:** it specifically means the MFA request
  was denied or unanswered, distinct from a generic MFA failure.
- **Phishing-resistant MFA is the fix, not more OTP:** FIDO2/WebAuthn defeats
  AiTM, OTP interception, and fatigue at once.

## Tools & Systems

Microsoft Entra ID sign-in logs + Identity Protection, Microsoft Sentinel (KQL),
Okta System Log, Duo, Elastic Security prebuilt rules, Datadog Cloud SIEM,
Splunk, Sysmon/EDR, Conditional Access / token protection, FIDO2 security keys.
(AiTM kit names — Evilginx, EvilProxy, Modlishka — are for recognition only.)

## Detection Queries

### KQL -- MFA push fatigue then success (T1621)

```kql
let denials = SigninLogs
| where ResultType == 500121                 // MFA denied / not answered
| summarize denials = count(), firstDeny=min(TimeGenerated) by UserPrincipalName, bin(TimeGenerated, 10m)
| where denials >= 5;
let successes = SigninLogs | where ResultType == 0
| project UserPrincipalName, successTime = TimeGenerated, IPAddress, DeviceDetail;
denials
| join kind=inner successes on UserPrincipalName
| where successTime between (firstDeny .. firstDeny + 30m)
| project UserPrincipalName, denials, firstDeny, successTime, IPAddress
```

### KQL -- AiTM / token replay: MFA-satisfied then new infrastructure (T1557/T1528)

```kql
SigninLogs
| where ResultType == 0 and AuthenticationRequirement == "multiFactorAuthentication"
| extend asn = tostring(parse_json(tostring(NetworkLocationDetails)))
| summarize ips=make_set(IPAddress,20), devices=dcount(tostring(DeviceDetail.deviceId)),
            cities=dcount(tostring(LocationDetails.city))
          by UserPrincipalName, bin(TimeGenerated, 1h)
| where devices > 1 or cities > 1          // same MFA'd user, multiple device/geo = possible replay
```

### Sigma -- Okta MFA bypass attempt (concept)

```yaml
title: Okta MFA Bypass Attempt
status: experimental
logsource: {product: okta, service: okta}
detection:
  selection:
    eventType:
      - 'user.mfa.attempt_bypass'
      - 'user.mfa.okta_verify.deny_push'
  condition: selection
level: high
```

## Common Scenarios

- **Push bombing:** 20 prompts in 10 minutes, user finally taps approve →
  `500121` burst then success → disable risky user, enforce number matching.
- **Evilginx AiTM:** user clicks a look-alike `login` domain, MFA succeeds, then
  the session is replayed from a VPS ASN minutes later on non-interactive logs.
- **Keylogged OTP:** endpoint with a keylogger captures TOTP; detected by EDR
  keyboard-hook behavior, not the IdP.
- **False positive:** a traveling user on a new device — resolved by Conditional
  Access device compliance and corroborating signals.

## Output Format

```
MFA DEFEAT DETECTION
  User:            <upn>
  Verdict:         <confirmed | suspected>
  Vector:          <push-fatigue T1621 | AiTM T1557 | token-replay T1528 | interception T1111 | auth-config-tamper T1556.006>
  Evidence:        <500121 burst+success | MFA-ok then new IP/ASN/device | keylogger behavior | new MFA method>
  Session:         <original IP/device> -> <replay IP/ASN/device>
  ATT&CK:          <mapped id(s)>
  Actions taken:   <sessions revoked | tokens rotated | user risk-disabled | FIDO2 enforced>
```

## Response

- Enforce **phishing-resistant MFA** (FIDO2/WebAuthn, certificate-based, Windows
  Hello) and **number matching** with context in authenticator apps (ATT&CK
  M1032; NIST CSF PR.AA-02).
- On detection, **revoke sessions and rotate refresh tokens**, shorten token
  lifetimes, and apply Conditional Access device-compliance / token-protection /
  sign-in-risk policies.
- Treat a user-reported "I didn't request this" as a **risky user** → auto-disable
  and investigate.
- Block newly registered look-alike auth domains; for interception, remediate the
  keylogged/compromised host.
