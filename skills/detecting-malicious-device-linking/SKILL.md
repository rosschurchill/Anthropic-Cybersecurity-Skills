---
name: detecting-malicious-device-linking
description: 'Detects malicious device linking (T1676) - abuse of the linked or companion-device feature of WhatsApp, Signal, Matrix, or Telegram to clone a messaging session (ghost pairing, QR-link hijack), where a user is phished into scanning a QR code masqueraded as a group invite or security alert and the account is paired to an attacker device that mirrors messages. Works from account-side signals: the linked-device and active-session list (unknown device, unfamiliar location or last-active time) and new-link alert events, since linked-device state is account-side and not a host artifact. Victim-protective detection and response only. Use when a user sees an unexpected linked device, a surprise link-attempt alert, or a suspicious pairing QR code. Keywords: linked devices, companion device, ghost pairing, QR code, WhatsApp, Signal, session hijack, Android, iOS, T1676. Do not use for device-resident malware triage, use detecting-mobile-malware-behavior.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- android
- ios
- linked-devices
- companion-device
- session-hijack
- qr-phishing
- messaging
- t1676
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- PR.AA-05
- DE.CM-09
- DE.AE-02
- DE.CM-01
mitre_attack:
- T1676
---

# Detecting Malicious Device Linking

## When to Use

Use this skill to detect **abuse of the linked / companion-device feature** of
messaging apps (WhatsApp, Signal, Matrix, Telegram) to clone a messaging session
— "ghost pairing" / QR-link hijack — where an attacker links the victim's
account to a device they control and silently mirrors messages (ATT&CK T1676
Linked Devices). The typical lure is a QR code masqueraded as a group invite,
security alert, or pairing instruction; on WhatsApp, scanning it triggers an
automatic end-to-end-encrypted upload of recent message history to the attacker
device. Reach for it when:

- A user notices an **unexpected linked device** in their messaging app.
- A user gets a surprise **link-attempt alert** ("someone is trying to link a
  new device").
- A suspicious pairing **QR code** is reported.

This is an **account / session artifact**, not device malware or an app binary:
the evidence lives in the account's linked-device list and link events, not on
the handset's filesystem. For device-resident malware triage use
`detecting-mobile-malware-behavior`; for a tampered app binary use
`detecting-repackaged-mobile-apps`.

This skill is **victim-protective: detection and response only.** It never
describes how to link, pair, or clone someone's account.

## Target safety (read first)

- A linked session means message history up to the point of unlink may be
  **already exposed.** Treat the content as compromised.
- Only the **primary device** can unlink a companion — the attacker cannot lock
  the owner out, so the owner retains control. Reassure the user of this.
- In an intimate-partner-abuse context, consider whether removing the link could
  tip off the attacker, and follow safety-planning guidance before acting;
  preserve a screenshot of the linked-device entry (device type, location hint,
  last-active time) as evidence first.

## Prerequisites

- Access to the account's **linked-device / active-session list**: WhatsApp
  "Linked Devices", Signal "Linked Devices", Matrix/Element session management,
  Telegram "Devices / Active Sessions". This is the primary detection surface.
- The device's OS/app **new-link notifications** enabled (the real-time signal).
- An organizational **phishing-report pipeline** able to receive QR-pairing
  lures.
- MDM app inventory (Intune/Jamf/Workspace ONE) for managed-device context —
  note most linked-device state is account-side and not visible to a host agent.

## Workflow

1. **Review the linked-device list.** Walk the WhatsApp/Signal/Matrix/Telegram
   session list with the user. Flag any device the user does not recognize — an
   unfamiliar device type, an approximate location they cannot account for, or a
   last-active time they did not generate. **Verify the exact metadata each
   screen exposes (location granularity, last-active semantics) against the
   vendor's current help docs**, since wording varies.
2. **Treat a surprise link-attempt alert as high-signal.** An unsolicited
   "someone is trying to link a new device" alert — especially during a phishing
   wave — is a live attempt; the correct user action is **"Don't link."**
3. **Trace the lure.** Look for a QR code presented as a group invite or
   security check that pairs a device rather than joining a chat. Feed it to the
   phishing-report pipeline.
4. **Org-wide (where supported).** For a managed messaging platform that exposes
   a companion-session API, pull and review companion-session lists periodically;
   otherwise fold QR-pairing lures into security-awareness monitoring and the
   report-phishing pipeline. (Which platforms expose a programmatic session API
   vs. manual user review only — verify per platform.)
5. **Respond** (see *Response*, and the safety note above).

## Key Concepts

- **No host log.** Linked-device state is account-side; detection depends on the
  account UI/API and the OS link notification, not a device agent. Be explicit
  about this limit.
- **The new-link event is the real-time signal.** The linked-device list is the
  after-the-fact inventory; the link-attempt alert is the chance to stop it.
- **QR "invite" that pairs, not joins.** Legitimate flows never ask you to scan
  a QR to "join" or "verify" — a scan that links a device is the tell.
- **Owner keeps control.** Only the primary phone can unlink companions, so the
  attacker cannot evict the owner — remediation is always available.

## Tools & Systems

WhatsApp Linked Devices and link-attempt alerts; Signal Linked Devices;
Matrix/Element session management; Telegram Active Sessions; an organizational
phishing-report pipeline (for QR-pairing lures); MDM app inventory (Intune /
Jamf Pro / Workspace ONE) for managed-device context.

## Detection Queries

There is usually no SIEM log here; these are structured review checks. Field
semantics vary by app — **verify** against current vendor docs.

### Linked-device review (concept)

```text
# For each entry in the app's Linked Devices / Active Sessions list:
FLAG IF device_type NOT recognized by owner
     OR approx_location unfamiliar to owner
     OR last_active time the owner cannot account for
# Any flagged entry => treat as an unauthorized companion session.
```

### Link-attempt alert triage (concept)

```text
# On an OS/app notification "a new device is trying to link this account":
HIGH-SIGNAL IF the owner did not initiate a link right now
ACTION: choose "Don't link"; report the lure to the phishing pipeline.
```

### QR-lure awareness pattern (concept)

```text
# A QR code delivered via message/email/web, framed as a group invite,
# security prompt, or "scan to continue" step, that on scan pairs a device
# rather than joining a chat. Report, do not scan.
```

### Managed-fleet concept

```text
# Where a managed messaging platform exposes a companion-session API, pull
# each account's companion sessions on a schedule and diff against the set the
# user acknowledges. Most platforms are manual-review only - verify per app.
```

## Common Scenarios

- **Ghost pairing via fake group invite:** a user scans a QR framed as a group
  invite; WhatsApp links an attacker device and uploads recent history.
- **Link-attempt during a phishing wave:** an unsolicited link alert appears;
  the user correctly declines.
- **Stale unknown session:** a linked device with an unfamiliar location and a
  last-active time the owner cannot explain surfaces in a periodic review.
- **False positive:** the user's own legitimate desktop/web companion session —
  confirmed by the user and left in place.

## Output Format

```text
MALICIOUS DEVICE LINKING DETECTION
  Account:         <messaging app + owner>
  App:             <WhatsApp | Signal | Matrix | Telegram>
  Verdict:         <confirmed rogue link | suspected | owner-recognized session>
  Companion:       <device type / approx location / last-active>
  Signal:          <unknown linked device | link-attempt alert | QR lure reported>
  Exposure:        <message history assumed exposed up to unlink>
  ATT&CK:          T1676
  Safety:          <evidence screenshot taken; safety plan considered>
  Actions taken:   <device unlinked | account re-verified | lure reported>
```

## Response

- **Unlink.** From the primary phone, remove the unrecognized linked device
  (only the primary device can unlink companions).
- **Re-verify.** Re-register / re-verify the account; enable WhatsApp two-step
  verification or Signal registration lock — this does not evict an already-
  paired device but blocks account number/email changes and re-registration
  abuse.
- **Assume exposure.** Treat message history up to the unlink as exposed; notify
  affected contacts if the content was sensitive.
- **Harden.** User education that legitimate flows never ask you to scan a QR to
  "join" or "verify"; keep message history minimal; periodically audit the
  linked-devices list; route QR-pairing lures to the phishing-report pipeline.
