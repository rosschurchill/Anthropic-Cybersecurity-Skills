---
name: detecting-email-bombing-attacks
description: 'Detects email bombing (MITRE T1667) - a flood of often individually benign messages to one mailbox to bury legitimate mail and set up a social-engineering pretext, as used by Storm-1811/Black Basta before a fake "IT support" call. Uses per-recipient inbound-volume and sender-diversity anomalies over Microsoft 365 message trace / Defender EmailEvents (KQL), Google Workspace log events, and secure email gateway analytics (Proofpoint/Mimecast), then correlates the spike with any follow-on vishing or remote-tool install. Use when a user reports a sudden email deluge, subscription-confirmation surge, or buried security alerts. Keywords: email bombing, email flood, subscription bomb, mail bomb, Storm-1811, Black Basta, inbound volume anomaly, QuickAssist, T1667. Do not use for account-takeover fraud or spoofed-sender business email compromise - use detecting-business-email-compromise.'
domain: cybersecurity
subdomain: soc-operations
tags:
- soc-operations
- threat-detection
- email-bombing
- email-security
- social-engineering
- storm-1811
- black-basta
- microsoft-365
- t1667
- phishing-defense
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-03
- RS.MI-01
- PR.PS-01
mitre_attack:
- T1667
- T1684.001
- T1219
---

# Detecting Email Bombing Attacks

## When to Use

Use this skill to detect and respond to **email bombing** (ATT&CK T1667): a flood
of (often individually benign) messages to one mailbox or a few mailboxes to
bury legitimate mail — security alerts, help-desk tickets, transaction
confirmations — and frequently the opening move of a social-engineering pretext.
The Storm-1811 / Black Basta pattern floods a target, then calls posing as "IT
support" to push remote-access tooling. Reach for it when:

- A user reports a sudden email deluge or a surge of "confirm your subscription"
  messages.
- Security alerts or finance/exec mail appear buried under volume.
- You want to catch the **hand-off** from bombing to a vishing / remote-support
  intrusion.

For account-takeover fraud or spoofed-sender wire-fraud, use
`detecting-business-email-compromise`.

## Prerequisites

- **Microsoft 365**: Unified Audit Log / message trace, Defender for Office 365
  Threat Explorer + Advanced Hunting (`EmailEvents`), Exchange Online
  message-trace API.
- **Google Workspace**: Gmail log events (BigQuery export) / Email Log Search.
- **Secure email gateway** logs (Proofpoint, Mimecast, Cisco ESA): per-recipient
  delivery counts.
- Correlation sources: help-desk ticketing, Teams/phone records (vishing), and
  **EDR** for a subsequent remote-tool install (Quick Assist, AnyDesk,
  TeamViewer).
- A **per-mailbox inbound-volume baseline**.

## Workflow

1. **Baseline inbound volume per recipient** (shared mailboxes and list members
   are naturally high — baseline each, do not use one global number).
2. **Detect the volume/velocity anomaly.** Alert when inbound message count to a
   recipient over a short window exceeds the mailbox's baseline by a tuned factor.
3. **Add confidence enrichers:** high distinct-sender-domain cardinality to one
   recipient, a surge of subscription-confirmation / list-signup bodies, and the
   recipient being privileged / finance / exec.
4. **Correlate the hand-off (highest value).** Email-bomb spike → new inbound
   Teams/phone contact → remote-assistance tool execution on the endpoint =
   active social-engineering intrusion. This chain is far stronger than the bomb
   alone.
5. **Respond** (see *Response*) and, critically, **warn the targeted user** not
   to act on unsolicited "IT support" contact.

## Key Concepts

- **Content filters miss it:** each message is usually clean (real newsletters,
  real confirmations), so detection is inherently **volume/velocity +
  sender-diversity**, not reputation or AV.
- **The bomb is a smokescreen:** its purpose is to bury a real alert (e.g. a
  fraudulent transaction confirmation) or to justify a follow-up "support" call.
- **SPF/DKIM/DMARC do not stop it:** anti-spoofing controls don't block
  legitimate-sender newsletter floods — a key limitation to communicate.
- **Follow-on tools:** Quick Assist, AnyDesk, TeamViewer execution shortly after
  a bomb is the pivot from nuisance to breach (T1219).

## Tools & Systems

Microsoft Defender for Office 365 / Threat Explorer + Advanced Hunting (KQL),
Exchange Online message trace, Microsoft Purview Unified Audit Log, Google
Workspace Email Log Search / BigQuery, Proofpoint/Mimecast/Cisco ESA analytics,
Splunk/Microsoft Sentinel, EDR (for the remote-tool follow-on).

## Detection Queries

### KQL -- Defender EmailEvents: per-recipient inbound surge + sender diversity

```kql
EmailEvents
| where EmailDirection == "Inbound"
| summarize msgs = count(), senders = dcount(SenderFromDomain),
            subjects = make_set(Subject, 20)
          by RecipientEmailAddress, bin(Timestamp, 10m)
| where msgs > 60 and senders > 30        // tune to each mailbox baseline
| order by msgs desc
```

### Splunk -- message-trace inbound flood

```spl
`m365_messagetrace` direction=Inbound
| bin _time span=5m
| stats count as msgs dc(sender_domain) as senderDomains by recipient, _time
| eventstats avg(msgs) as base p99(msgs) as p99 by recipient
| where msgs > (p99*3) AND senderDomains > 20
| table _time, recipient, msgs, senderDomains
```

### KQL -- hand-off: bomb spike then remote-tool execution (behavioral)

```kql
let bombed = EmailEvents
| where EmailDirection=="Inbound"
| summarize msgs=count() by RecipientEmailAddress, bin(Timestamp,10m)
| where msgs > 60
| project user = RecipientEmailAddress, bombTime = Timestamp;
let remoteTools = DeviceProcessEvents
| where FileName in~ ("quickassist.exe","anydesk.exe","teamviewer.exe","msra.exe");
bombed
| join kind=inner (remoteTools | project AccountUpn, DeviceName, ToolTime=Timestamp, FileName)
    on $left.user == $right.AccountUpn
| where ToolTime between (bombTime .. bombTime + 6h)
| project user, DeviceName, FileName, bombTime, ToolTime
```

## Common Scenarios

- **Storm-1811 / Black Basta:** thousands of newsletter signups hit a user's
  inbox, then a Teams/phone "IT support" call pushes Quick Assist — the join
  query above is the detection.
- **Transaction burial:** a bomb buries a fraudulent-payment confirmation so it
  goes unnoticed.
- **False positive:** a user signs up for many services during onboarding, or a
  shared mailbox is naturally high-volume — resolved by per-mailbox baseline and
  absence of the follow-on chain.

## Output Format

```
EMAIL BOMBING DETECTION
  Recipient:       <mailbox> (role: <exec|finance|standard|shared>)
  Verdict:         <confirmed | suspected | organic>
  Peak:            <msgs> msgs / <window>, distinct sender domains <n>
  Body pattern:    <subscription confirmations | mixed newsletters | repeated attachment>
  Hand-off:        <none | vishing call | remote-tool exec: <tool> on <host>>
  ATT&CK:          T1667[, T1684.001, T1219]
  Actions taken:   <recipient rate-limited/quarantined | user warned | remote tools blocked>
```

## Response

- Temporarily apply **aggressive rate limiting / quarantine** for the targeted
  recipient and triage the flood with mailbox rules; preserve a sample for IR.
- **Proactively warn the targeted user** not to act on unsolicited "IT support"
  contact — this interrupts the kill chain.
- Harden: subscription/bulk-mail and graymail filtering, SEG volume-anomaly
  rules, and **block consumer remote-support tools** at the endpoint unless
  sanctioned (ATT&CK M1042; NIST CSF PR.PS-01).
- Note the limit: SPF/DKIM/DMARC (M1054) help spoofing but do **not** stop
  legitimate-newsletter flooding.
