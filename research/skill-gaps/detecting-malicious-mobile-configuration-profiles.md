# Detecting Malicious Mobile Configuration Profiles — research notes

- **Proposed slug:** detecting-malicious-mobile-configuration-profiles
- **ATT&CK (Mobile):** T1632 Subvert Trust Controls (tactic: defense-evasion) — plus T1638 Adversary-in-the-Middle (the primary payoff a rogue profile enables). Detection strategy: **DET0657** (Android + iOS). Data component: System Settings (DC0118), observed via the device UI — no separate log channel. Android analytic **AN1745** (scan the trusted-certificate store for anomalies). Sub-technique T1632.001 Code Signing Policy Modification has its own strategy DET0619.
- **Status:** research (not yet a skill)

## Defensive goal
Detect device-management artifacts that subvert the platform's trust controls: a rogue iOS `.mobileconfig` configuration profile, an attacker-installed trusted root CA, or an unexpected MDM enrollment. The headline abuse is a profile that installs a root CA **and** a proxy/VPN payload so that TLS traffic can be decrypted by an attacker-controlled server (T1638 Adversary-in-the-Middle). This is a **device-management artifact**, not an app — keep it distinct from repackaged-app and surveillanceware detection.

## Data sources / telemetry
- **iOS profile inventory (MDM):** the MDM `ProfileList` command returns every installed configuration profile (identifier, whether it is managed/unmanaged, payload types, signing). `CertificateList` returns installed certs. Intune, Jamf Pro, Workspace ONE and Android Enterprise expose installed-profile and installed-CA inventories.
- **iOS payload types that matter:** root-CA payloads (PayloadType `com.apple.security.root` / `com.apple.security.pkcs1` — *verify exact strings*), VPN/proxy payloads (`com.apple.vpn.managed`, global HTTP proxy), and MDM enrollment (`com.apple.mdm`). Unmanaged profiles installed out-of-band (Safari download, email, AirDrop) are the suspicious set.
- **Android trusted-CA store (AN1745):** user-installed CAs under Settings → Security → Encryption & credentials → Trusted credentials (User tab); MDM trusted-cert inventory. Note Android 7+ apps do not trust user-added CAs unless their `networkSecurityConfig` opts in, so a user CA paired with a side-loaded app is the higher-signal combination.
- **On-device review surface:** iOS Settings → General → VPN & Device Management shows profiles and MDM enrollments; this is the UI the user/analyst inspects.
- **MTD network telemetry:** Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Wandera — on-device AiTM / rogue-proxy / untrusted-CA detection.

## Detection logic / approach
Per DET0657, the core signal is a **deviation from the expected enterprise profile/CA baseline**:
- Alert on any installed CA or configuration profile not present in the MDM-pushed baseline; alert hard when an unmanaged profile carries both a root-CA payload and a proxy/VPN payload (the AiTM pattern).
- Alert on unexpected MDM enrollment (`com.apple.mdm` payload pointing at a server hostname not on the org allowlist).
- Correlate a new user CA on Android with a concurrent side-load / unknown-sources enablement.
- Enrich: resolve the MDM server hostname and the rogue CA against certificate-transparency logs and threat intel; treat newly registered infrastructure as higher risk.
- MDM compliance policy: fail devices whose CA/profile inventory drifts from baseline, and quarantine via conditional access.

## Response / mitigation
- Remove the profile/CA (iOS: delete the configuration profile; Android: remove the user CA), then rotate any credentials that may have transited the rogue proxy.
- Re-enroll the device from a known-good MDM flow; verify no residual MDM enrollment remains.
- Preventive: supervise corporate iOS devices (supervision restricts unmanaged profile installs), push a restriction that blocks user CA/profile installation, user training not to install unexpected profiles, and conditional access that requires a compliant CA/profile baseline.

## Real tools
Microsoft Intune, Jamf Pro, VMware/Omnissa Workspace ONE, Android Enterprise (profile + certificate inventory, compliance policy); Apple Configurator / `profiles` MDM commands (`ProfileList`, `CertificateList`); Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Wandera (on-device AiTM / untrusted-CA detection); certificate-transparency log search (crt.sh) for rogue CA/MDM infrastructure.

## Draft frontmatter mappings
- mitre_attack: [T1632, T1638]
- nist_csf: [DE.CM-01, DE.CM-09, PR.PS-01, DE.AE-02]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): implementing-mobile-application-management

## Draft description (<=1024 chars)
Detects malicious mobile configuration profiles and trust-control subversion (T1632) that enable adversary-in-the-middle interception (T1638): rogue iOS .mobileconfig profiles, attacker-installed trusted root CAs, unexpected MDM enrollments, and profiles that pair a root-CA payload with a proxy or VPN payload to decrypt TLS. Compares the installed-profile and trusted-CA inventory from Intune, Jamf, or Workspace ONE against the enterprise baseline, scans the Android user-CA store, and enriches rogue CA and MDM hostnames via certificate-transparency logs. Use when hunting rogue profiles, untrusted root CAs, unauthorized MDM enrollment, or mobile AiTM via a planted proxy. Keywords: mobileconfig, configuration profile, root CA, com.apple.mdm, ProfileList, trusted credentials, MDM enrollment, proxy, AiTM, T1632, T1638, DET0657. Do not use for deploying app-level policy or app protection, use implementing-mobile-application-management.

## Key references
- https://attack.mitre.org/techniques/T1632/
- https://attack.mitre.org/detectionstrategies/DET0657/
- https://attack.mitre.org/techniques/T1638/
- https://support.apple.com/guide/security/ (Apple Platform Security — configuration profiles, MDM, supervision)
- https://support.apple.com/guide/deployment/ (iOS/iPadOS MDM commands: ProfileList, CertificateList)

## Open questions / scope boundaries
- Verify the exact iOS PayloadType identifiers for root-CA and proxy payloads against current Apple MDM/Configuration-Profile reference before shipping any rule that matches on them.
- The high-signal AiTM combination (root CA + proxy in one unmanaged profile) needs a documented way to build the per-org "expected baseline" of managed profiles/CAs; without a baseline this is noisy.
- Must NOT cover app-binary integrity (that is detecting-repackaged-mobile-apps) or app permission abuse (detecting-mobile-surveillanceware) — this skill is strictly the device-management trust layer.
- Android user-CA detection only matters where an app opts into user CAs via networkSecurityConfig; author should document that nuance so analysts don't over-alert on a benign lone user CA.
