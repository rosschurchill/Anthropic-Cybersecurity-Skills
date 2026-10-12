# Detecting Email Bombing Attacks — research notes

- **Proposed slug:** detecting-email-bombing-attacks
- **ATT&CK:** T1667 Email Bombing (tactic: impact) — no sub-techniques
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to email bombing: a flood of (often individually benign)
messages to one mailbox or small set of mailboxes to bury legitimate mail —
security alerts, help-desk tickets, transaction confirmations — and frequently
as the opening move of a social-engineering pretext (e.g. Storm-1811 /
Black Basta flooding a target then calling as "IT support" to push remote-access
tooling). The skill detects the inbound-volume anomaly, links it to any
follow-on vishing/remote-support attempt, and drives containment.

## Data sources / telemetry
- **Microsoft 365 Unified Audit Log / message trace** — `m365:unified`
  Send/Receive (`MessageTrace`, `Deliver`/`Receive` events); Defender for
  Office 365 Threat Explorer inbound volume per recipient; Exchange Online
  message-trace API.
- **Google Workspace** — Gmail log events (BigQuery export) / Email Log Search:
  inbound message count per recipient over time.
- **Secure email gateway logs** — Proofpoint, Mimecast, Cisco ESA: per-recipient
  delivery counts, newsletter/list-confirmation ("please confirm your
  subscription") surges, many distinct senders/domains to one recipient.
- **Mailbox signals** — sudden spike in unread/rules activity; subscription
  confirmation emails; identical/near-identical attachments repeated.
- **Correlation sources** — help-desk ticketing, Teams/phone (vishing attempt),
  EDR for subsequent remote-tool install (QuickAssist, AnyDesk, TeamViewer) —
  the hand-off from bombing to intrusion.

## Detection logic / approach
MITRE detection strategy DET0355 / AN1008: unusually high inbound message
volume, or repeated attachments, to a single mailbox in a short window, over
`m365:unified` Send/Receive — with a configurable time window and per-recipient
threshold.

Pseudo-rule (spirit; tune window/threshold to each mailbox baseline):
```
# inbound messages per recipient, sliding window
count(messages where direction=inbound) by recipient, bin(time, 5m)
 -> alert if count > baseline_p99 * K  (e.g. >N messages / 5 min)
# enrichers that raise confidence:
#  - high distinct-sender-domain cardinality to one recipient
#  - surge of "confirm your subscription"/list-signup bodies
#  - recipient is privileged / finance / exec
#  - followed within hours by a vishing call or remote-tool install
```
Because each message is usually clean, content/AV filters miss it — detection is
inherently **volume/velocity + sender-diversity**, not reputation. KQL over
`EmailEvents` (Defender) or SPL over message-trace works. Pair with a
behavioral rule: email-bomb spike → new inbound Teams/phone contact → remote
assistance tool execution = active social-engineering intrusion.

## Response / mitigation
Temporarily apply aggressive rate limiting / quarantine for the targeted
recipient; enable mailbox rules to triage the flood; preserve a sample for IR.
Proactively warn the targeted user NOT to act on unsolicited "IT support"
contact (the common follow-on). Harden: subscription/bulk-mail filtering,
graymail controls, SEG volume anomaly rules, block consumer remote-support
tools at the endpoint unless sanctioned. SPF/DKIM/DMARC (M1054) help spoofing
but do NOT stop legitimate-newsletter flooding — note this limit.

## Real tools
Microsoft Defender for Office 365 / Threat Explorer + Advanced Hunting (KQL),
Exchange Online message trace, Microsoft Purview Unified Audit Log, Google
Workspace Email Log Search / BigQuery, Proofpoint/Mimecast/Cisco ESA analytics,
Splunk/Sentinel, EDR (for the remote-tool follow-on).

## Draft frontmatter mappings
- mitre_attack: [T1667, T1656, T1219]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, RS.MI-01, PR.PS-01]
- d3fend (optional): D3-MA (Message Analysis), D3-UGLPA adjacent, D3-ITF (Inbound Traffic Filtering)
- suggested subdomain: soc-operations
- nearest existing sibling (for the negative trigger): detecting-business-email-compromise

## Draft description (<=1024 chars)
Detects email bombing — a flood of (often individually benign) messages to one
mailbox to bury legitimate mail and set up a social-engineering pretext, as
used by Storm-1811/Black Basta before a fake "IT support" call. Uses
per-recipient inbound-volume and sender-diversity anomalies over Microsoft 365
message trace / Defender EmailEvents (KQL), Google Workspace logs, and secure
email gateway analytics, then correlates the spike with any follow-on vishing
or remote-tool install. Use when a user reports a sudden email deluge,
subscription-confirmation surge, or buried alerts (ATT&CK T1667). Keywords:
email bombing, email flood, subscription bomb, mail bomb, Storm-1811, Black
Basta, inbound volume anomaly, T1667. Do not use for account-takeover fraud or
spoofed-sender business email compromise — use detecting-business-email-compromise.

## Key references
- MITRE ATT&CK T1667 + detection strategy DET0355: https://attack.mitre.org/techniques/T1667/
- Microsoft / CISA advisories on Black Basta & Storm-1811 social engineering (verify current URLs): https://www.cisa.gov/
- Microsoft Defender for Office 365 Advanced Hunting (EmailEvents) docs: https://learn.microsoft.com/
- Google Workspace Email Log Search / BigQuery export docs: https://support.google.com/

## Open questions / scope boundaries
- Per-mailbox baselines vary hugely (shared mailboxes, mailing lists) — ship a
  baselining method, not a fixed threshold.
- Decide how much to cover the social-engineering follow-on (vishing +
  remote-tool, T1219) here vs cross-referencing — the hand-off is the highest-
  value signal but risks scope creep.
- Must NOT include instructions to send bulk mail. Confirm M365 vs Google vs
  SEG coverage split (likely a references file per platform).
