# Detecting Mobile Remote Access and Proxyware — research notes

- **Proposed slug:** detecting-mobile-remote-access-and-proxyware
- **ATT&CK (Mobile):** T1663 Remote Access Software (tactic: command-and-control) — plus folded/related: T1604 Proxy Through Victim, T1643 Generate Traffic from Victim
- **Status:** research (not yet a skill)

## Defensive goal
Detect two overlapping abuses on managed Android/iOS devices: (1) mobile remote
access software / RATs that give an operator interactive control or screen/data
access (T1663), and (2) residential-proxy and ad-fraud SDKs that enrol the
device as a proxy node to relay third-party traffic through it (T1604) or
generate traffic from it — ad fraud, click injection, fake impressions (T1643).
Both monetise or weaponise the device's network identity and often ship inside
otherwise-functional apps (VPNs, utilities) or SDKs bundled into legitimate
apps.

## Data sources / telemetry
- **MTD app-reputation** (Lookout, Zimperium zIPS, Microsoft Defender for
  Endpoint mobile, Wandera): classifications for RAT / remote-control, proxyware
  / residential-proxy SDK, and ad-fraud/click-fraud behaviour; network
  protection alerts on connections to proxy-broker or C2 infrastructure.
- **MDM/UEM** (Intune, Jamf, Workspace ONE, Android Enterprise): app inventory
  and sideload state; apps requesting broad network + always-on VPN or
  `BIND_VPN_SERVICE` (`VpnService`) roles; foreground-service abuse keeping a
  relay alive; per-app data-usage telemetry where exposed.
- **Network protection / egress** (MTD network module, corporate DNS, secure web
  gateway for on-net devices): device acting as a *source* of inbound-relayed
  traffic, connections to known residential-proxy brokers (Asocks, etc. — names
  for recognition), high outbound connection fan-out to many unrelated
  destinations, or traffic volume/pattern inconsistent with foreground use.
- **App-vetting / dynamic analysis** (MobSF, vendor sandboxes): embedded proxy
  SDKs (e.g. Proxylib-style Golang relay libraries, LumiApps SDK — recognition),
  silent traffic relay with no user notification, ad-SDK click-injection
  indicators, hidden WebView ad rendering.
- **Billing/store signals + consent text review:** confusing or absent consent
  for "share your connection" monetisation SDKs.
- **Forensics:** Android `bugreport` (`dumpsys netstats`, `connectivity`,
  running services), logcat, iOS `sysdiagnose`.

## Detection logic / approach
1. **RAT (T1663):** MITRE DET0624 — build an allowlist of approved mobile
   remote-support tools (sanctioned MDM remote view, vendor support apps) and
   alert on any other remote-access-capable app, keyed on MTD reputation plus
   permission profile (accessibility, screen capture/`MediaProjection`, overlay,
   input injection). Primary ATT&CK data component is Permissions Request
   (DC0116). Correlate a newly granted broad permission set with an unknown app.
2. **Proxyware / proxy-through-victim (T1604):** flag apps classified as
   residential-proxy SDKs; corroborate with network telemetry showing the device
   *relaying* traffic (inbound-then-outbound to unrelated destinations, high
   destination cardinality, activity while the screen is off and app is
   backgrounded). Academic measurement shows ~48% of APKs carrying such SDKs are
   flagged malicious by 5+ AV engines and some relay silently with no
   notification.
3. **Generate-traffic / ad fraud (T1643):** bursty HTTP(S) to ad networks, click
   URLs, or impression endpoints disproportionate to user interaction; WebView
   activity with no foreground UI; battery/data anomalies. Many families (VPN
   monetisers) sit at the T1604/T1643 boundary — detect behaviourally, then
   classify.
False-positive guards: sanctioned VPNs, legitimate remote-support tooling, and
corporate always-on VPN must be allowlisted explicitly.

## Response / mitigation
Quarantine/remove the app via MDM; mark non-compliant to trigger Conditional
Access and cut corporate access; block proxy-broker/C2 infrastructure at the
secure web gateway and MTD network layer. Restrict install sources to managed
Play/VPP, disallow sideloading, and keep Play Protect on. Review and revoke VPN
and accessibility roles. For confirmed RAT, treat as device compromise:
rotate credentials used on the device, inspect for data access, consider wipe.

## Real tools
Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Wandera;
Microsoft Intune, Jamf, VMware Workspace ONE, Google Android Enterprise + Play
Protect; MobSF and vendor dynamic-analysis sandboxes; MTD network protection /
secure web gateway; Android `bugreport`/`dumpsys netstats`, iOS `sysdiagnose`.
Campaign/SDK names for recognition only: Proxylib, LumiApps SDK, Oko VPN,
Asocks.

## Draft frontmatter mappings
- mitre_attack: [T1663, T1604, T1643]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, PR.PS-01, RS.MI-01, ID.AM-02]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-malware-behavior

## Draft description (<=1024 chars)
Detects mobile remote-access software and RATs that give an operator control or
screen/data access to a managed device (T1663), and residential-proxy and
ad-fraud SDKs that relay third-party traffic through the device (T1604) or
generate traffic from it for ad fraud and click injection (T1643). Uses MTD
app-reputation (RAT / proxyware / ad-fraud classifications), MDM app inventory
and VPN/accessibility role review, network-protection egress telemetry showing
the device relaying or bursting traffic, and MobSF detection of embedded proxy
SDKs. Use when a device unexpectedly relays traffic, carries a proxy or VPN
monetisation SDK, shows ad-fraud network bursts, or runs unapproved
remote-control software. Keywords: mobile RAT, proxyware, residential proxy SDK,
Proxylib, LumiApps, ad fraud, click injection, VpnService, network protection,
T1663, T1604, T1643. Do not use for persistence mechanics or on-device payload
behaviour - use detecting-mobile-malware-behavior.

## Key references
- MITRE ATT&CK Mobile T1663 Remote Access Software + DET0624: https://attack.mitre.org/techniques/T1663/
- MITRE ATT&CK Mobile T1604 Proxy Through Victim: https://attack.mitre.org/techniques/T1604/
- MITRE ATT&CK Mobile T1643 Generate Traffic from Victim: https://attack.mitre.org/techniques/T1643/
- HUMAN Security "PROXYLIB" residential-proxy Android campaign (verify title): https://www.humansecurity.com/learn/blog/
- "Your Phone is My Proxy: Detecting and Understanding Mobile Proxy Networks" (NDSS/academic): https://dev.ndss-symposium.org/
- Microsoft Defender for Endpoint on mobile / network protection docs: https://learn.microsoft.com/defender-endpoint/
- OWASP MASTG (network/traffic analysis of mobile apps): https://mas.owasp.org/MASTG/

## Open questions / scope boundaries
- MITRE lists no official detection logic for T1604/T1643; detectors here are
  derived from behaviour + MTD classification — mark as such.
- Exact proxy-broker destination lists change constantly; the skill should rely
  on MTD reputation feeds rather than hard-coding IOCs (no fabricated endpoints).
- Boundary with sanctioned VPN/remote-support is the main FP risk — the
  allowlist is load-bearing; document it as a prerequisite.
- Decide how much ad-fraud (T1643) overlaps with a dedicated ad-fraud skill if
  one is later authored; keep this one network/relay-centric.
