---
name: detecting-mobile-remote-access-and-proxyware
description: 'Detects mobile remote-access software and RATs that give an operator control or screen and data access on a managed Android or iOS device (T1663), and residential-proxy and ad-fraud SDKs that relay third-party traffic through the device (T1604) or generate traffic from it for ad fraud and click injection (T1643). Uses MTD app-reputation for RAT, proxyware and ad-fraud classifications, MDM app inventory and VpnService and accessibility role review, network-protection egress telemetry showing the device relaying or bursting traffic, and MobSF detection of embedded proxy SDKs. Use when a device unexpectedly relays traffic, carries a proxy or VPN monetisation SDK, shows ad-fraud network bursts, or runs unapproved remote-control software. Keywords: mobile RAT, proxyware, residential proxy SDK, Proxylib, LumiApps, ad fraud, click injection, VpnService, network protection, T1663, T1604, T1643. Do not use for persistence mechanics or on-device payload behaviour - use detecting-mobile-malware-behavior.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- android
- ios
- remote-access
- proxyware
- residential-proxy
- ad-fraud
- vpnservice
- t1663
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- PR.PS-01
mitre_attack:
- T1663
- T1604
- T1643
---

# Detecting Mobile Remote Access and Proxyware

## When to Use

Use this skill to detect two overlapping abuses of a managed Android/iOS device:

- **Remote access software / RATs (T1663)** — an app giving an operator
  interactive control or screen/data access (accessibility-driven control,
  `MediaProjection` screen capture, overlay, input injection).
- **Proxyware / proxy-through-victim (T1604)** — a residential-proxy or SDK that
  enrols the device as a relay node for third-party traffic.
- **Generate traffic from victim (T1643)** — ad-fraud and click-injection SDKs
  that manufacture impressions and clicks from the device.

Both abuses monetise or weaponise the device's **network identity** and usually
ship inside otherwise-functional apps (VPNs, utilities) or as SDKs bundled into
legitimate apps. Reach for it when a device **relays traffic it did not
originate**, carries a proxy/VPN monetisation SDK, shows ad-fraud bursts, or runs
unapproved remote-control software.

For reboot-survival persistence mechanics, or the broader on-device payload
behaviour, use `detecting-mobile-malware-behavior`.

## Prerequisites

Mobile detection has **no raw host agent with syscall telemetry** — it is built
from MTD, MDM/UEM, network-egress and app-vetting signals:

- **MTD app-reputation** (Lookout, Zimperium zIPS, Microsoft Defender for
  Endpoint on mobile, Wandera): RAT / remote-control, proxyware /
  residential-proxy, and ad-fraud / click-fraud classifications; network-protection
  alerts on proxy-broker or C2 infrastructure.
- **MDM/UEM** (Microsoft Intune, Jamf Pro, VMware Workspace ONE, Android
  Enterprise): app inventory and sideload state; apps requesting broad network
  plus always-on VPN or a VPN-service role (verify the exact `BIND_VPN_SERVICE` /
  `VpnService` constant against current Android docs); foreground-service abuse
  keeping a relay alive; per-app data-usage where exposed.
- **Network protection / egress** (MTD network module, corporate DNS, secure web
  gateway for on-net devices): the device acting as a *source* of inbound-relayed
  traffic, high outbound destination cardinality to unrelated hosts, or traffic
  volume/pattern inconsistent with foreground use.
- **App-vetting / dynamic analysis** (MobSF, vendor sandboxes): embedded proxy
  SDKs (Proxylib-style Go relay libraries, LumiApps SDK — recognition only),
  silent relay with no user notification, ad-SDK click-injection, hidden WebView
  ad rendering.
- **Consent-text review**: confusing or absent consent for "share your
  connection" monetisation SDKs.
- **Forensics**: Android `bugreport` (`dumpsys netstats`, `connectivity`,
  running services), logcat, iOS `sysdiagnose`.

## Workflow

1. **Build the allowlist first — it is load-bearing.** Sanctioned mobile
   remote-support tools (approved MDM remote view, vendor support apps),
   sanctioned VPNs, and corporate always-on VPN must be explicitly allowlisted.
   The boundary with these legitimate tools is the main false-positive risk.
2. **RAT (T1663).** Alert on any remote-access-capable app outside the allowlist,
   keyed on MTD reputation **plus** a permission profile of accessibility, screen
   capture (`MediaProjection`), overlay and input injection. Correlate a newly
   granted broad permission set with an unknown or low-reputation app.
3. **Proxyware (T1604).** Flag apps classified as residential-proxy SDKs, then
   corroborate behaviorally: the device relaying traffic (inbound-then-outbound to
   unrelated destinations), high destination cardinality, and network activity
   while the screen is off and the app is backgrounded. Measurement studies find a
   large share of proxy-SDK APKs are flagged by multiple AV engines and some relay
   silently with no notification.
4. **Generate traffic / ad fraud (T1643).** Hunt bursty HTTP(S) to ad networks,
   click URLs or impression endpoints disproportionate to user interaction;
   WebView activity with no foreground UI; and battery/data anomalies.
5. **Classify after detecting.** Many VPN-monetiser families sit at the
   T1604/T1643 boundary — detect on behaviour, then classify.
6. **Respond** (see *Response*).

## Key Concepts

- **The network identity is the asset.** Proxyware and ad fraud monetise the
  device's IP and reputation; the on-device "payload" may be minimal.
- **Behaviour over IOCs.** Proxy-broker destinations change constantly — rely on
  MTD reputation feeds, not hard-coded endpoint lists. ATT&CK publishes no
  official detection logic for T1604/T1643; these detectors are derived from
  behaviour plus MTD classification.
- **Backgrounded relay is the tell.** Legitimate use is foreground-correlated;
  traffic that flows while the screen is off and the app is backgrounded is the
  discriminator for a relay.
- **The allowlist decides the signal.** Without an explicit sanctioned-VPN /
  remote-support allowlist, every legitimate tool is a false positive.
- **RAT = device compromise.** A confirmed RAT means an operator had interactive
  access — treat credentials used on the device as exposed.

## Tools & Systems

Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Wandera;
Microsoft Intune, Jamf Pro, VMware Workspace ONE, Google Android Enterprise +
Play Protect; MobSF and vendor dynamic-analysis sandboxes; MTD network protection
/ secure web gateway; Android `bugreport`/`dumpsys netstats`, iOS `sysdiagnose`.
Campaign/SDK names for recognition only: Proxylib, LumiApps SDK, Oko VPN, Asocks.

## Detection Queries

Treat thresholds, field names and API/permission constants as **verify/tune**.

### KQL (Sentinel / Defender) — unapproved remote-access permission profile

```kql
// verify table/column names against your MTD connector schema
MobileAppInventory
| where Permissions has_any ("accessibility","MediaProjection","SYSTEM_ALERT_WINDOW")
| join kind=inner (MobileThreatInfo
    | where ThreatClass in ("rat","remote-control","proxyware","ad-fraud")
       or AppReputation in ("low","unknown","malicious")) on AppId
| where AppId !in (ApprovedRemoteSupportAllowlist)
| project DeviceId, AppId, PackageName, Permissions, ThreatClass
```

### Network protection — device relaying while backgrounded (concept)

```
From MTD network / SWG egress: per device, count distinct outbound destinations
and bytes while the screen is off and no foreground app is network-active.
High destination cardinality + sustained bytes with no foreground app -> suspect
proxy relay (T1604). Verify screen-state/foreground fields against the feed.
```

### MobSF — embedded proxy / monetisation SDK (concept)

```
Scan the MobSF report for bundled relay SDKs (Go-based relay libraries, known
monetisation SDK package names), a VpnService declaration with no user-facing VPN
feature, and relay start with no notification. Corroborate with consent-text
review. Rely on MTD reputation for live SDK names, not a static IOC list.
```

### Ad-fraud burst (T1643) — concept

```
Flag bursty HTTP(S) to ad/click/impression endpoints disproportionate to user
interaction, and WebView rendering with no foreground UI. Verify ad-network
destinations via MTD reputation; do not hard-code endpoints.
```

## Common Scenarios

- **Unapproved RAT:** a sideloaded app with accessibility + screen-capture +
  overlay, flagged remote-control by MTD, not on the support allowlist.
- **Silent residential proxy:** a free VPN relays traffic to unrelated
  destinations while backgrounded (Proxylib/LumiApps-style SDK).
- **Ad-fraud SDK:** bursty impression traffic and headless WebView rendering with
  no user interaction.
- **False positive:** the sanctioned corporate always-on VPN carrying normal
  egress — excluded by the allowlist.

## Output Format

```
MOBILE REMOTE-ACCESS / PROXYWARE DETECTION
  Device:          <device id / user>
  App:             <package name / version / install source>
  Verdict:         <confirmed | suspected | sanctioned-allowlisted>
  Class:           <RAT | proxyware/residential-proxy | ad-fraud/click-injection>
  Signal:          <MTD reputation | permission profile | backgrounded relay | ad burst | proxy SDK>
  Network:         <destination cardinality | relay evidence | broker/C2 hit>
  ATT&CK:          <T1663 | T1604 | T1643>
  Actions taken:   <quarantined | marked non-compliant | broker blocked | VPN/accessibility role revoked>
```

## Response

- **Contain:** quarantine/remove the app via MDM; mark the device non-compliant to
  trigger Conditional Access and cut corporate access; block proxy-broker / C2
  infrastructure at the secure web gateway and MTD network layer.
- **Reduce the surface:** restrict installs to managed Play / VPP, disallow
  sideloading, keep Play Protect on, and review and revoke VPN and accessibility
  roles.
- **For a confirmed RAT:** treat as device compromise — rotate credentials used on
  the device, inspect for data access, and consider a wipe.
