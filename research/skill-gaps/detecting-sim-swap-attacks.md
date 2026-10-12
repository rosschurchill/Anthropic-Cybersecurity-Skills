# Detecting SIM Swap Attacks — research notes

- **Proposed slug:** detecting-sim-swap-attacks
- **ATT&CK (Mobile):** T1451 SIM Card Swap (platforms: Android, iOS)
- **Status:** research (not yet a skill)

## Defensive goal
Detect carrier/account-side takeover of a victim's phone number — an adversary
porting the number or re-provisioning it onto a SIM/eSIM they control, so that
SMS-OTP and voice-based MFA and account-recovery flow to the attacker. This is an
*off-device, identity/carrier-side* attack (used by Scattered Spider to bypass
MFA), not a malicious app, so the detection correlates carrier SIM/line-change
and loss-of-service signals with a burst of MFA/recovery activity.

## Data sources / telemetry
- **Carrier / line-change signals.** Carrier or aggregator SIM-swap APIs report
  the timestamp of the last SIM change for a number — e.g. GSMA Open Gateway /
  CAMARA **SIM Swap API**, Twilio **Lookup SIM Swap** (`last_sim_swap`), and
  carrier number-port / port-out notifications. IMSI/ICCID change on the line.
- **On-device OS signal (MITRE DET0658 / AN1747 Android, AN1748 iOS).** The OS
  may notify the user that the SIM was transferred to another device, and the
  device sees an unexpected loss of cellular service — a user-facing signal, not
  a carrier feed. Android `SIM_STATE_CHANGED` / telephony state; `READ_PHONE_STATE`
  / IMSI read is privileged (`READ_PRIVILEGED_PHONE_STATE`) so MDM/carrier-app
  context is usually needed — verify.
- **MDM/UEM.** MITRE M1012: monitor SIM-card changes through EMM/MDM; Intune /
  Jamf / Workspace ONE can surface ICCID/phone-number change in device inventory.
- **Identity / IAM telemetry.** Entra ID / Okta / Duo: SMS-OTP delivery failures
  or sudden method change, account-recovery and password-reset bursts, new-device
  enrollment, impossible-travel right after a number change. IdP risk signals.

## Detection logic / approach
1. **SIM change + MFA burst correlation (the core analytic, AN1747-style).**
   Correlate a recent SIM/line-identifier change (carrier API `last_sim_swap`
   within N hours, or MDM ICCID change, or OS "SIM moved" notice + cellular
   drop) with near-term account-recovery / SMS-OTP / password-reset activity for
   the same identity → high-severity alert.
   ```
   if (sim_swap.last_change within 24h) and
      (idp.recovery_or_smsotp_events(user) spike): alert("possible SIM swap takeover")
   ```
2. **Pre-auth gate.** At high-risk auth/recovery steps, query the SIM Swap API;
   if the SIM changed within a short window (e.g. 24-72h), step up to a
   non-SMS factor or hold the recovery.
3. **MDM inventory diff.** Alert on ICCID / phone-number change for a managed
   device not matching a planned re-provisioning.
4. **Loss-of-service + enrollment.** Managed device goes off cellular while a new
   MFA device enrolls for the same user elsewhere.

## Response / mitigation
Carrier-side hardening is primary: set a **carrier port-freeze / number-lock and
account PIN/passcode** with the mobile operator. In IAM: **remove SMS/voice as an
MFA/recovery method**, require phishing-resistant MFA (FIDO2); on detection,
revoke sessions, block the account, force re-verification through an out-of-band
channel, and reset recovery methods. Conditional Access: distrust auth that
depended on the swapped number. Alert the user and the carrier fraud line.

## Real tools
GSMA Open Gateway / CAMARA SIM Swap API, Twilio Lookup (SIM Swap), carrier
number-port/port-out alerts, Microsoft Intune, Jamf Pro, VMware Workspace ONE
device inventory, Microsoft Entra ID (sign-in / Identity Protection), Okta System
Log, Duo. Threat actor name for recognition only: Scattered Spider.

## Draft frontmatter mappings
- mitre_attack: [T1451]
- nist_csf: [DE.AE-02, DE.CM-09, DE.CM-01, PR.AA-05, ID.AM-02, PR.PS-01]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-malware-behavior

## Draft description (<=1024 chars)
Detects SIM swap attacks — carrier or account-side takeover of a victim phone
number (number port-out or re-provisioning onto an attacker SIM or eSIM) so that
SMS-OTP and voice MFA and account recovery flow to the adversary, as used by
Scattered Spider to bypass MFA (T1451 SIM Card Swap). Correlates carrier
SIM-change signals (GSMA/CAMARA SIM Swap API, Twilio Lookup last_sim_swap, port-out
alerts, MDM ICCID change) and the on-device loss-of-service or SIM-moved notice
with a burst of MFA, OTP-delivery-failure, and account-recovery activity in Entra,
Okta and Duo. Use when a number stops receiving SMS, a SIM changes unexpectedly,
or account recovery spikes. Keywords: SIM swap, SIM swapping, port-out, number
takeover, IMSI change, ICCID, carrier PIN, last_sim_swap, T1451. Do not use for
on-device SMS or OTP stealing malware - use detecting-mobile-otp-and-notification-theft.

## Key references
- MITRE ATT&CK Mobile T1451 SIM Card Swap (+ DET0658, AN1747/AN1748): https://attack.mitre.org/techniques/T1451/
- CAMARA / GSMA Open Gateway SIM Swap API: https://camaraproject.org/sim-swap/
- Twilio Lookup SIM Swap: https://www.twilio.com/docs/lookup/v2-api/sim-swap
- Microsoft Entra Identity Protection: https://learn.microsoft.com/entra/id-protection/

## Open questions / scope boundaries
- Author must decide the carrier/aggregator integration (which SIM-swap API the
  org can actually query) and the correlation window; carrier-side feeds vary by
  operator and region.
- Verify whether IMSI/ICCID is readable on managed devices at scale given
  `READ_PRIVILEGED_PHONE_STATE` restrictions.
- MUST NOT cover on-device OTP/notification stealing malware (that is
  detecting-mobile-otp-and-notification-theft). Scope is the number-takeover event
  itself, off-device.
