---
name: detecting-malicious-mobile-configuration-profiles
description: 'Detects malicious mobile configuration profiles and trust-control subversion (T1632) that enable adversary-in-the-middle interception (T1638): rogue iOS .mobileconfig profiles, attacker-installed trusted root CAs, unexpected MDM enrollments, and profiles pairing a root-CA payload with a proxy or VPN payload to decrypt TLS. Compares the installed-profile and trusted-CA inventory from Intune, Jamf, or Workspace ONE against the enterprise baseline, scans the Android user-CA store, and enriches rogue CA and MDM hostnames via certificate-transparency logs. Use when hunting rogue profiles, untrusted root CAs, unauthorized MDM enrollment, or mobile AiTM via a planted proxy. Keywords: mobileconfig, configuration profile, root CA, com.apple.mdm, ProfileList, trusted credentials, MDM enrollment, proxy, AiTM, iOS, Android, T1632, T1638. Do not use for deploying app-level policy or app protection, use implementing-mobile-application-management.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- ios
- android
- configuration-profile
- trust-controls
- adversary-in-the-middle
- mdm
- root-ca
- t1632
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- PR.PS-01
- DE.AE-02
mitre_attack:
- T1632
- T1638
---

# Detecting Malicious Mobile Configuration Profiles

## When to Use

Use this skill to detect **device-management artifacts that subvert the
platform's trust controls** (ATT&CK T1632 Subvert Trust Controls) and, through
them, enable traffic interception (T1638 Adversary-in-the-Middle). The headline
abuse is a profile that installs a **root CA** *and* a **proxy or VPN payload**,
so an attacker-controlled server can decrypt the device's TLS. Reach for it
when:

- Hunting an unexpected iOS configuration profile (`.mobileconfig`) installed
  out-of-band (Safari download, email attachment, AirDrop, a phished link).
- An untrusted root CA appears in the device trust store.
- A device shows an MDM enrollment pointing at a server you do not operate.
- MTD flags on-device AiTM / rogue-proxy / untrusted-CA activity.

This is strictly the **device-management trust layer**. For app-binary
tampering use `detecting-repackaged-mobile-apps`; for a sensor-abusing installed
app use `detecting-mobile-surveillanceware`. To *deploy* app-protection policy
(not hunt rogue profiles) use `implementing-mobile-application-management`.

## Prerequisites

- An MDM/UEM that can inventory installed profiles and certificates: Microsoft
  Intune, Jamf Pro, VMware/Omnissa Workspace ONE, or Android Enterprise.
- For iOS, the ability to issue the MDM `ProfileList` and `CertificateList`
  query commands (Apple Configurator or the MDM's own device-query surface).
- A documented **expected baseline** of org-managed profiles and CAs per device
  class. Without this baseline the detection is noisy — building it is the hard
  part of the skill.
- Optional: an MTD agent (Lookout, Zimperium zIPS, Microsoft Defender for
  Endpoint mobile, Jamf Threat Defense — formerly Wandera) for on-device
  untrusted-CA / AiTM detection.
- Certificate-transparency search (for example crt.sh) for enriching a rogue
  CA or MDM hostname.

## Workflow

1. **Build the baseline.** Enumerate the profiles and trusted CAs the org
   legitimately pushes to each device class; mark everything else as subject to
   review. Record which profiles are **managed** vs **unmanaged** — an
   unmanaged (user-installed) profile is the suspicious set on a corporate
   device.
2. **Collect the installed inventory.** iOS: `ProfileList` and `CertificateList`
   via MDM. Android: trusted-credentials (User tab) and the MDM trusted-cert
   inventory. Workspace ONE / Jamf / Intune expose equivalent reports.
3. **Diff against baseline.** Flag any installed CA or profile not in the
   baseline.
4. **Score the payload mix (core signal).** Inspect each flagged iOS profile's
   payload types. **Alert hard** when a single unmanaged profile carries both a
   root-CA payload and a proxy/VPN payload — that is the AiTM pattern. The
   illustrative iOS `PayloadType` strings are a root-CA payload (for example
   `com.apple.security.root` / `com.apple.security.pkcs1`), a VPN/proxy payload
   (for example `com.apple.vpn.managed` or a global HTTP proxy), and MDM
   enrollment (`com.apple.mdm`) — **verify the exact PayloadType constant
   against current Apple Configuration-Profile reference** before matching on
   it; prefer the behavioral framing (an unmanaged profile combining trust +
   interception payloads) which does not depend on the exact string.
5. **Check enrollment.** Flag an MDM enrollment whose server hostname is not on
   the org allowlist.
6. **Correlate Android.** A new user-installed CA matters most when paired with
   a concurrent side-load / unknown-sources enablement, because Android 7+ apps
   do not trust user-added CAs unless their network-security config opts in — a
   lone benign user CA is low-signal, the CA + side-loaded app combination is
   high-signal.
7. **Enrich.** Resolve the rogue CA and MDM hostname against certificate-
   transparency logs and threat intel; treat newly registered infrastructure as
   higher risk.
8. **Respond** (see *Response*).

## Key Concepts

- **Trust + interception in one artifact is the discriminator.** A benign VPN
  profile or a benign enterprise CA alone is common; the two **paired** in an
  unmanaged profile is what lets an attacker MITM TLS.
- **Managed vs unmanaged.** Supervision/MDM-pushed profiles are expected;
  out-of-band unmanaged profiles on a corporate device are the hunt set.
- **Android user-CA nuance.** Modern apps ignore user CAs by default, so alert
  on the CA + opted-in or side-loaded app combination, not every lone user CA.
- **This is not an app.** The evidence is the profile/CA inventory, not a
  binary hash or a runtime permission — keep it distinct from the app skills.

## Tools & Systems

Microsoft Intune, Jamf Pro, VMware/Omnissa Workspace ONE, Android Enterprise
(profile + certificate inventory and compliance policy); the MDM `ProfileList` /
`CertificateList` query commands (and, on macOS, the `profiles` CLI); Lookout,
Zimperium zIPS, Microsoft Defender for Endpoint (mobile), Jamf Threat Defense
(formerly Wandera) for on-device AiTM / untrusted-CA detection;
certificate-transparency search (crt.sh) for rogue CA / MDM infrastructure.

## Detection Queries

Field names, verdict strings, and thresholds below are illustrative — **verify
and tune** against your MDM schema and current platform docs.

### Intune / compliance concept — profile or CA drift from baseline

```text
# Device marked non-compliant when its installed-profile or trusted-CA
# inventory contains an item absent from the managed baseline set.
NONCOMPLIANT IF (installed_profiles - baseline_profiles) != {}
             OR (installed_cas       - baseline_cas)       != {}
# Conditional access then quarantines the device from corporate resources.
```

### KQL (Microsoft Sentinel / Defender) — unmanaged profile with trust + proxy payloads

```kql
// Pseudo-schema: an MDM profile-inventory table. Verify table/column names.
MDMProfileInventory
| where ManagedState == "unmanaged"
| where PayloadTypes has_any ("root-ca", "pkcs1")          // trust payload (verify constant)
| where PayloadTypes has_any ("vpn", "global-http-proxy")  // interception payload (verify)
| project TimeGenerated, DeviceId, ProfileIdentifier, PayloadTypes, SigningState
```

### Jamf smart-group concept — unexpected root CA

```text
# Smart group membership: "Installed Certificates" contains a CA whose
# SHA-256 is NOT in the extension-attribute allowlist of org-managed CAs.
```

### Android — user-added CA correlated with side-load

```text
# From MDM device attributes (verify attribute names / tune window):
user_installed_ca_count > 0  AND  unknown_sources_enabled == true
# Raise priority when a side-loaded (non-managed-store) package was installed
# within the same review window.
```

## Common Scenarios

- **AiTM profile:** a phished `.mobileconfig` installs a root CA plus a global
  HTTP proxy; the unmanaged profile carrying both payloads fires the hard
  alert, and MTD corroborates untrusted-CA traffic.
- **Rogue MDM enrollment:** a profile enrolls the device to an attacker MDM
  hostname not on the allowlist, giving remote command and config control.
- **Android proxy CA:** a user-installed CA appears alongside a freshly side-
  loaded app whose network-security config trusts user CAs.
- **False positive:** a single benign enterprise VPN profile, or a lone Android
  user CA with no opted-in app — excluded by requiring the trust + interception
  pairing (or the CA + side-load correlation).

## Output Format

```text
MALICIOUS CONFIGURATION PROFILE DETECTION
  Device:          <device id / owner>
  Platform:        <iOS | Android>
  Verdict:         <confirmed AiTM | suspected rogue profile | benign-baseline>
  Artifact:        <profile identifier | CA subject/SHA-256 | MDM enrollment>
  Managed state:   <managed | unmanaged / user-installed>
  Payload mix:     <root-CA + proxy/VPN | MDM enrollment | lone user CA>
  Baseline diff:   <item absent from managed baseline>
  Enrichment:      <CT-log / intel result for CA or MDM hostname>
  ATT&CK:          T1632, T1638
  Actions taken:   <profile/CA removed | device quarantined | creds rotated | re-enrolled>
```

## Response

- **Contain.** Quarantine the device via conditional access; capture the full
  profile/CA inventory as evidence before removal.
- **Remove.** Delete the rogue iOS configuration profile; remove the Android
  user CA. Verify no residual MDM enrollment remains.
- **Rotate.** Rotate any credentials or tokens that may have transited the rogue
  proxy, since TLS to those services may have been decrypted.
- **Re-enroll** the device from a known-good MDM flow.
- **Harden.** Supervise corporate iOS devices (supervision restricts unmanaged
  profile installs); push a restriction blocking user CA / profile installation;
  require a compliant CA/profile baseline for conditional access; train users
  not to install unexpected profiles or scan unknown pairing prompts.
