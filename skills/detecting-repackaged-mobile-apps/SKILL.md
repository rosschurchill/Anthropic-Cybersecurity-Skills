---
name: detecting-repackaged-mobile-apps
description: 'Detects repackaged, trojanized, or cloned mobile app binaries and malicious app updates (T1577), including compromised client binaries (T1645), out-of-band version tampering (T1661), and malicious SDK or supply-chain injection (T1474). Compares signing-certificate SHA-256 and APK or DEX hashes against the official store baseline, flags signer mismatch and side-loaded packages, consumes Play Integrity and App Attest verdicts such as UNRECOGNIZED_VERSION and failing device integrity, and reconciles MDM app-version inventory fleet-wide. Covers Janus (CVE-2017-13156) and v1-signature downgrade. Use when hunting repackaged apps, fake clones, poisoned updates, trojanized APKs, or malicious SDKs. Keywords: repackaging, Play Integrity, App Attest, signer mismatch, apksigner, Janus, side-load, APK hash, Android, iOS, T1577. Do not use for deep static reverse-engineering of one APK, use performing-android-app-static-analysis-with-mobsf.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- android
- ios
- repackaging
- app-integrity
- play-integrity
- supply-chain
- signer-mismatch
- t1577
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- ID.AM-02
- PR.PS-01
- PR.PS-02
- DE.CM-09
mitre_attack:
- T1577
- T1645
- T1661
- T1474
---

# Detecting Repackaged Mobile Apps

## When to Use

Use this skill to detect **tampered app binaries and malicious updates** — an
attacker decompiles a legitimate app, inserts a payload, re-signs it, and
distributes it (side-load, third-party store, or a poisoned update) so malicious
code runs under a trusted app's identity. It covers ATT&CK T1577 Compromise
Application Executable, T1645 Compromise Client Software Binary, T1661
Application Versioning (malicious update), and T1474 Supply Chain Compromise
(malicious SDK). Reach for it when:

- Hunting repackaged / cloned apps, trojanized APKs, or fake lookalikes.
- An app backend sees Play Integrity or App Attest verdicts failing at scale.
- A managed-fleet app inventory shows an off-baseline version or signer.
- A legitimate-looking app was installed from outside the managed store.

This is strictly **fleet-scale binary / app-integrity** detection. For a deep
static reverse-engineering teardown of a single APK use
`performing-android-app-static-analysis-with-mobsf`; for config-profile trust
abuse use `detecting-malicious-mobile-configuration-profiles`.

## Prerequisites

- A **trusted signing-cert and hash baseline** per package name, sourced from
  the official store metadata / Play Console. Account for legitimate re-signing
  (Play App Signing can present a different signer than the upload key) — this
  is the hard part and must be documented, not assumed.
- Server-side integrity attestation wired into the app backend: Google **Play
  Integrity API** (Android) and Apple **App Attest** / `DCAppAttestService`
  (iOS).
- MDM/UEM app inventory: Intune, Jamf Pro, Workspace ONE, or Android Enterprise,
  exposing installed version, signer, and side-load / unknown-sources state.
- `apksigner` for signature-scheme verification; VirusTotal for APK hash
  reputation; optionally an MTD (Lookout, Zimperium zIPS, Defender for Endpoint
  mobile) with tamper/repackaging classification and Play Protect.

## Workflow

1. **Baseline.** For each in-scope package, record the official signing-
   certificate SHA-256, the APK/DEX hash set, and the legitimate version
   history. Note the Play App Signing key where it applies.
2. **Signer-mismatch check (strongest single signal).** For a known
   `packageName`, compare the installed signing-cert SHA-256 against the store
   value. A mismatch means the app was re-signed by someone other than the
   legitimate publisher.
3. **Hash / distribution check.** Compare APK/DEX hashes to the baseline; flag
   any package with no trusted distribution path (side-loaded, unknown source,
   non-managed store).
4. **Consume attestation verdicts.** Server-side, alert on
   `appIntegrity.appRecognitionVerdict` reporting the app as an unrecognized
   version (`UNRECOGNIZED_VERSION`, versus `PLAY_RECOGNIZED` or `UNEVALUATED`),
   on a mismatched `appIntegrity.certificateSha256Digest`, and on a
   `deviceIntegrity.deviceRecognitionVerdict` that lacks
   `MEETS_DEVICE_INTEGRITY`. These field names and enums are current and
   documented verbatim — re-check the Play Integrity docs before shipping, since
   fields do get added — but prefer the behavioral framing (attestation says
   "not the published binary") over hard-coding a string.
5. **Version-tamper check (T1661).** Flag an out-of-band version bump absent
   from the store release history, or an install that downgrades the APK
   signature scheme.
6. **Janus awareness.** Janus (CVE-2017-13156) prepends bytes to an APK/DEX
   without breaking a v1 (JAR) signature. Require APK Signature Scheme v2/v3
   verification (which defeats Janus) and flag apps relying on v1-only
   signatures. Use `apksigner verify --verbose --print-certs` to see which
   schemes verified.
7. **Supply-chain (T1474).** Diff the app's dependency / SDK set against a
   known-good build to catch a malicious or compromised embedded SDK.
8. **Fleet hunt.** Diff the MDM app-version/hash inventory against the official
   baseline; investigate any package present outside the managed store.
9. **Respond** (see *Response*).

## Key Concepts

- **Signer mismatch beats everything.** Same package name, different signing
  cert = repackaged. Attestation and hashes corroborate.
- **Attestation is server-side.** The repackaged binary runs on a device you do
  not control; the reliable signal is the verdict the genuine backend receives,
  not an on-device check the attacker can patch out.
- **Janus is a v1-only problem.** v2/v3 scheme verification closes it; alerting
  on v1-only reliance is a cheap preventive hunt.
- **Re-signing is sometimes legitimate.** Play App Signing changes the observed
  signer — baseline it, or you will false-positive the whole fleet.

## Tools & Systems

Google Play Integrity API, Play Protect; Apple App Attest (`DCAppAttestService`);
Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile)
tamper/repackaging detection; Intune / Jamf Pro / Workspace ONE / Android
Enterprise app inventory and version baselines; `apksigner` (signature-scheme
verification); OWASP MASTG resiliency / anti-tampering tests; VirusTotal (APK
hash reputation).

## Detection Queries

MDM schema names and thresholds are illustrative — **verify and tune** against
your MDM schema; the Play Integrity field and enum names below are documented,
but re-check the docs before shipping.

### apksigner — confirm v2/v3 and read the signer

```bash
# Defeats Janus (requires v2/v3) and prints the signing cert SHA-256
apksigner verify --verbose --print-certs app.apk
# Flag when only "Verified using v1 scheme: true" with v2/v3 false,
# or when the printed SHA-256 != the official baseline for this package.
```

### KQL (Microsoft Sentinel) — signer mismatch from MDM inventory

```kql
// Pseudo-schema: MDM app-inventory table. Verify table/column names.
MDMAppInventory
| extend BaselineSigner = _lookup_baseline(PackageName)   // official SHA-256
| where isnotempty(BaselineSigner) and SignerSha256 != BaselineSigner
| project TimeGenerated, DeviceId, PackageName, SignerSha256, BaselineSigner, InstallSource
```

### Backend attestation concept — fail unrecognized app versions

```text
# On each integrity-protected request, evaluate the Play Integrity verdict:
BLOCK / step-up IF appIntegrity.appRecognitionVerdict != PLAY_RECOGNIZED
                OR appIntegrity.certificateSha256Digest NOT IN baseline_set
                OR deviceIntegrity.deviceRecognitionVerdict lacks MEETS_DEVICE_INTEGRITY
# Revoke server-side sessions keyed to failing verdicts.
```

### Fleet hunt concept — off-store package

```text
# Investigate any installed package whose InstallSource is not the managed
# store AND whose signer/hash is off-baseline (tune to your enrolled fleet).
```

## Common Scenarios

- **Trojanized banking clone:** a popular app, re-signed with an attacker key
  and side-loaded; signer mismatch fires, Play Integrity reports it
  unrecognized.
- **Poisoned update (T1661):** an out-of-band version appears that is not in the
  store release history and downgrades the signature scheme.
- **Janus tamper:** an APK verifies under v1 only; v2/v3 verification fails —
  flagged as integrity-unsound.
- **Malicious SDK (T1474):** the legitimate signer is intact but the dependency
  set contains an SDK absent from the known-good build.
- **False positive:** Play App Signing presenting a different-but-legitimate
  signer — resolved by baselining the Play signing key.

## Output Format

```text
REPACKAGED APP DETECTION
  Device/App:      <device id / packageName / version>
  Platform:        <Android | iOS>
  Verdict:         <repackaged | poisoned-update | malicious-SDK | benign-baseline>
  Signer:          <installed SHA-256> vs <baseline SHA-256>
  Attestation:     <Play Integrity / App Attest verdict summary>
  Scheme:          <v1-only (Janus-exposed) | v2/v3 verified>
  Source:          <managed store | side-load / unknown source>
  ATT&CK:          T1577, T1645, T1661, T1474
  Actions taken:   <app removed | device quarantined | sessions revoked | creds rotated>
```

## Response

- **Contain.** Quarantine the device or block the app via MDM conditional
  access; revoke server-side sessions keyed to failing integrity verdicts.
- **Remove and reinstall.** Uninstall the repackaged app (Play Protect) and
  reinstall from the official store.
- **Rotate** credentials and tokens the trojanized app could reach.
- **Harden.** Managed app store only; disable unknown sources; enforce Play
  Integrity / App Attest server-side; require v2/v3 signatures; apply OWASP
  MASTG anti-tampering resilience checks in the build pipeline.
