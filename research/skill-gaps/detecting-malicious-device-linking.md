# Detecting Malicious Device Linking — research notes

- **Proposed slug:** detecting-malicious-device-linking
- **ATT&CK (Mobile):** T1676 Linked Devices (tactic: collection). Detection strategy: **DET0716**. No folded-in sub-techniques. MITRE: adversaries abuse the linked/companion-device feature of messaging apps to register the victim's account to an attacker-controlled device, typically by phishing the user into scanning a QR code masqueraded as a group invite, security alert, or pairing instruction; on WhatsApp, scanning triggers an automatic end-to-end-encrypted upload of recent message history to the adversary device.
- **Status:** research (not yet a skill)

## Defensive goal
Detect abuse of companion / linked-device features (WhatsApp, Signal, Matrix, Telegram) to clone a messaging session — "ghost pairing" / QR-link hijack — where an attacker links the victim's account to a device they control and silently mirrors messages. This is an **account/session artifact**, not device malware or an app binary: the evidence lives in the account's linked-device list and in new-link events, not on the handset's filesystem.

## Data sources / telemetry
- **Account-side linked/companion-device list:** WhatsApp "Linked Devices" screen (each session's approximate location, last-activity time, device type); Signal "Linked Devices"; Matrix session list; Telegram "Devices / Active Sessions". This is the primary detection surface.
- **New-link events / notifications (DET0716):** the OS or app notifies the user when the account is linked to a new device; WhatsApp now raises a link-attempt alert with a "Don't link" option and a location hint. These events are the real-time signal.
- **User-reported phishing:** QR codes delivered via message/email/web masquerading as a group invite, security prompt, or "scan to continue" pairing step.
- **MDM/managed context:** on managed devices, inventory of installed messaging apps and (where exposed) companion-session state; note most linked-device state is account-side and not visible to a host agent.

## Detection logic / approach
Per DET0716, detection hinges on the **new-link event and the linked-device inventory**, since there is no host log:
- Alert/triage on any linked-device the user does not recognize in the WhatsApp/Signal/Matrix session list — unexpected device type, unfamiliar approximate location, or a last-active time the user cannot account for.
- Treat an unsolicited link-attempt alert ("someone is trying to link a new device") during a phishing wave as high-signal; the correct user action is "Don't link."
- Awareness pattern: a QR code presented as a group invite or security check that, when scanned, pairs a device rather than joining a chat.
- For an org, fold into security-awareness monitoring: report-phishing pipeline for QR-pairing lures; where a managed messaging platform exposes session APIs, pull and review companion-session lists periodically.

## Response / mitigation
- Remove the unknown linked device from the primary phone (only the primary device can unlink companions — the attacker cannot lock the owner out).
- Re-verify/re-register the account; enable WhatsApp two-step verification / Signal registration lock (does not evict an already-paired device but blocks account-email/number changes and re-registration abuse).
- Assume message history up to the unlink was exposed; notify affected contacts if sensitive.
- Preventive: user education that legitimate flows never ask you to scan a QR to "join" or "verify," keep message history minimal, periodically audit the linked-devices list.

## Real tools
WhatsApp Linked Devices + link-attempt alerts; Signal Linked Devices; Matrix/Element session management; Telegram Active Sessions; organizational phishing-report pipeline (for QR-pairing lures); MDM app inventory (Intune/Jamf/Workspace ONE) for managed-device context.

## Draft frontmatter mappings
- mitre_attack: [T1676]
- nist_csf: [PR.AA-05, DE.CM-09, DE.AE-02, DE.CM-01]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-malware-behavior

## Draft description (<=1024 chars)
Detects malicious device linking (T1676) — abuse of the linked/companion-device feature of WhatsApp, Signal, Matrix, or Telegram to clone a messaging session ("ghost pairing", QR-link hijack), where a user is phished into scanning a QR code masqueraded as a group invite or security alert and the account is paired to an attacker device that mirrors messages. Works from account-side signals: the linked-device/active-session list (unknown device, unfamiliar location or last-active time) and new-link alert events per DET0716, since linked-device state is account-side and not a host artifact. Use when a user sees an unexpected linked device, a surprise link-attempt alert, or a suspicious pairing QR code. Keywords: linked devices, companion device, ghost pairing, QR code, WhatsApp, Signal, session hijack, T1676, DET0716. Do not use for device-resident malware triage, use detecting-mobile-malware-behavior.

## Key references
- https://attack.mitre.org/techniques/T1676/
- https://attack.mitre.org/detectionstrategies/DET0716/
- https://faq.whatsapp.com/ (Linked Devices and linked-device security — verify exact help page)
- https://support.signal.org/ (Signal linked devices)

## Open questions / scope boundaries
- Verify the exact WhatsApp/Signal help-page URLs and the precise metadata each linked-device screen exposes (location granularity, last-active semantics) against the vendors' own current docs — secondary sources vary on wording.
- Largely a user/account-telemetry skill; author must be explicit that there is usually no host-agent log and that detection depends on the account UI/API and the OS link notification.
- Must NOT drift into device-malware behavior (detecting-mobile-malware-behavior) or app-binary tampering (detecting-repackaged-mobile-apps) — the artifact is the messaging account session, not the handset.
- Open: which messaging platforms expose a programmatic companion-session API for automated org-wide auditing vs. manual user review only.
