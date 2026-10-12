---
name: detecting-sim-swap-attacks
description: 'Detects SIM swap attacks: carrier or account-side takeover of a victim phone number (number port-out or re-provisioning onto an attacker-controlled SIM or eSIM) so that SMS-OTP and voice MFA and account recovery flow to the adversary, as used by Scattered Spider to bypass MFA (T1451 SIM Card Swap). This is an off-device, identity-and-carrier event, not a malicious app. Correlates carrier SIM-change signals (GSMA Open Gateway and CAMARA SIM Swap API, Twilio Lookup last_sim_swap, port-out alerts, MDM ICCID or phone-number change) and the on-device loss-of-service or SIM-moved notice with a burst of MFA, OTP-delivery-failure and account-recovery activity in Entra ID, Okta and Duo. Use when a number stops receiving SMS, a SIM changes unexpectedly, or account recovery spikes for a user. Keywords: SIM swap, SIM swapping, port-out, number takeover, IMSI change, ICCID, carrier PIN, last_sim_swap, eSIM, T1451. Do not use for on-device mobile malware behaviour analysis - use detecting-mobile-malware-behavior.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile
- android
- ios
- sim-swap
- number-takeover
- mfa-bypass
- t1451
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.AE-02
- DE.CM-09
- DE.CM-01
- PR.AA-05
- ID.AM-02
- PR.PS-01
mitre_attack:
- T1451
---

# Detecting SIM Swap Attacks

## When to Use

Use this skill to detect **carrier / account-side takeover of a victim's phone
number** (ATT&CK T1451 SIM Card Swap): an adversary porting the number out or
re-provisioning it onto a SIM or eSIM they control, so that SMS-OTP, voice MFA and
account-recovery codes flow to the attacker. This is an **off-device, identity and
carrier event** — not a malicious app on the handset — famously used by Scattered
Spider to bypass MFA. Reach for it when:

- A managed number suddenly stops receiving SMS / loses cellular service.
- A carrier or aggregator reports a recent SIM / line-identifier change.
- Account-recovery, password-reset or SMS-OTP activity spikes for one identity.

Because the attack is off-device, the detection is a **correlation of
carrier/line signals with identity activity**, not an on-device scan. For on-device
malware that steals codes already on the handset, use
`detecting-mobile-otp-and-notification-theft`; for generic app triage, use
`detecting-mobile-malware-behavior`.

## Prerequisites

- **Carrier / line-change signal.** One of: a SIM-swap query API (GSMA Open
  Gateway / CAMARA SIM Swap API, or Twilio Lookup's SIM Swap package), carrier
  number-port / port-out notifications, or an MDM-visible ICCID / IMSI /
  phone-number change. In Twilio Lookup v2 `sim_swap` is an **object**, not a
  timestamp: the portable field is the boolean `swapped_in_period`, evaluated
  over a `swapped_period` the provider configures, while
  `last_sim_swap.last_sim_swap_date` is returned only for a limited set of
  countries (GB, DE, ES, NL). For most fleets — the US included — there is no
  date to subtract, so the analytic must ask "did a swap happen in the requested
  period?" rather than compute a local time delta.
- **MDM/UEM inventory.** Intune, Jamf Pro or VMware Workspace ONE device inventory
  exposing phone number / ICCID so changes can be diffed. IMSI visibility is
  limited at scale because reading it requires `READ_PRIVILEGED_PHONE_STATE`, a
  signature|privileged permission not available to ordinary apps — so expect to
  diff ICCID / phone number, not IMSI.
- **Identity / IAM telemetry.** Entra ID sign-in and Identity Protection, Okta
  System Log, Duo — recovery flows, MFA method changes, SMS-OTP delivery failures,
  new-device enrollment.
- **An on-device user-facing signal** where available: the OS "your SIM was
  transferred to another device" notice and an unexpected cellular-service drop.

## Workflow

1. **SIM change + MFA/recovery burst correlation (the core analytic).** Correlate
   a recent SIM/line-identifier change (a carrier-API swap reported inside the
   requested period, or an MDM ICCID change, or the OS SIM-moved notice plus a
   cellular drop) with
   near-term account-recovery / SMS-OTP / password-reset activity for the **same
   identity** — high severity.
2. **Pre-auth gate at high-risk steps.** At account recovery or a sensitive sign-in,
   query the SIM-swap API; if it reports a swap inside the period, step up to a
   non-SMS factor or hold the recovery. What you tune here is the **requested
   period** sent to (or configured with) the provider — not a local time delta,
   because outside the few countries that return `last_sim_swap_date` you get
   only the in-period boolean.
3. **MDM inventory diff.** Alert on ICCID / phone-number change for a managed
   device that does not match a planned re-provisioning ticket.
4. **Loss-of-service + enrollment.** A managed device drops cellular while a new
   MFA device enrolls for the same user elsewhere — strong takeover indicator.

## Key Concepts

- **Off-device by nature.** The compromise happens at the carrier or account, so no
  handset scan sees it; the device only shows the *consequence* (lost service, SIM
  moved). Detection lives in carrier feeds and identity logs.
- **The correlation is the signal.** A SIM change alone can be a legitimate upgrade;
  a recovery burst alone can be benign. Together, inside a tight window, they are
  the attack.
- **SMS/voice MFA is the target and the weakness.** The whole point is to redirect
  phishable factors; phishing-resistant MFA (FIDO2) removes the prize.
- **Carrier variance.** Which SIM-swap API or port-out feed is available depends on
  operator and region — the integration, not the logic, is the hard part.
- **Window tuning.** Too wide a correlation window floods false positives from
  normal upgrades; too narrow misses a patient attacker. Tune per fleet.

## Tools & Systems

GSMA Open Gateway / CAMARA SIM Swap API, Twilio Lookup (SIM Swap), carrier
number-port / port-out alerts, Microsoft Intune, Jamf Pro, VMware Workspace ONE
device inventory, Microsoft Entra ID (sign-in / Identity Protection), Okta System
Log, Duo. Threat actor named for recognition only: Scattered Spider.

## Detection Queries

Treat table/column names and windows as **verify/tune**; the Twilio Lookup
`sim_swap` fields named below are the documented ones.

### Pre-auth SIM-swap gate (concept)

```
# At account recovery or step-up auth:
resp = sim_swap_api.lookup(msisdn)          # GSMA/CAMARA or Twilio Lookup
# sim_swap is an object. swapped_in_period is the field available everywhere;
# tune the REQUESTED/provider-configured swapped_period, not a local delta.
if resp.sim_swap.swapped_in_period:
    hold_recovery(); require_non_sms_factor(); notify_fraud_team()
# last_sim_swap.last_sim_swap_date exists only for a few countries (GB, DE, ES,
# NL); do not build the core analytic on it.
```

### Microsoft Sentinel (KQL) -- recovery/MFA burst after a SIM change

```kql
// SIMChangeEvents is your carrier/MDM-fed custom table; verify schema
SIMChangeEvents
| where TimeGenerated > ago(7d)
| project SwapTime=TimeGenerated, UserPrincipalName, Msisdn, Source
| join kind=inner (
    SigninLogs
    | where ResultType != 0 or AuthenticationRequirement == "multiFactorAuthentication"
    | where tostring(AuthenticationDetails) has_any ("SMS", "Text message", "Voice call")  // verify/tune
    | summarize events=count(), methods=make_set(AuthenticationMethodsUsed)
             by UserPrincipalName, bin(TimeGenerated, 1h)
    | where events >= 3                    // tune: recovery/OTP burst threshold
  ) on UserPrincipalName
| where TimeGenerated between (SwapTime .. SwapTime + 24h)
```

### MDM inventory diff (concept)

```
# Nightly over Intune/Jamf/Workspace ONE inventory:
# alert where device.iccid or device.phoneNumber changed and no re-provisioning ticket exists
```

## Common Scenarios

- **Scattered-Spider-style takeover:** help-desk or carrier social-engineered to
  port a number; minutes later a flood of recovery and SMS-OTP events for that
  identity — correlation fires.
- **eSIM re-provisioning:** attacker provisions the number onto an eSIM; victim
  device loses service and shows the SIM-moved notice.
- **Pre-auth block:** recovery attempt arrives, SIM-swap API returns
  `swapped_in_period = true` for the configured period, recovery is held pending
  out-of-band verification.
- **False positive:** a planned device upgrade with a matching re-provisioning
  ticket and no recovery burst — excluded.

## Output Format

```
SIM SWAP DETECTION
  Identity:        <user / MSISDN>
  Verdict:         <confirmed | suspected | planned-change-benign>
  SIM signal:      <swapped_in_period true over <period> | MDM ICCID change | OS SIM-moved + service drop>
  Identity burst:  <recovery/OTP/reset events in window, methods used>
  Window:          <SIM change time -> auth/recovery activity>
  ATT&CK:          T1451
  Actions taken:   <recovery held | sessions revoked | account blocked | carrier fraud line notified | moved off SMS MFA>
```

## Response

- **Contain:** revoke sessions, block the account, and hold any in-flight recovery;
  force re-verification through an out-of-band channel; reset recovery methods;
  distrust (via Conditional Access) any auth that depended on the swapped number.
- **Carrier side (primary hardening):** set a carrier **port-freeze / number-lock
  and account PIN/passcode** with the operator; alert the user and the carrier
  fraud line.
- **Identity side:** remove SMS and voice as MFA/recovery methods; require
  phishing-resistant MFA (FIDO2) so a redirected number is worthless.
