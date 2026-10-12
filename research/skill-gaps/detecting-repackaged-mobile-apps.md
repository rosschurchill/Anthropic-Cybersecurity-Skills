# Detecting Repackaged Mobile Apps — research notes

- **Proposed slug:** detecting-repackaged-mobile-apps
- **ATT&CK (Mobile):** T1577 Compromise Application Executable (tactic: persistence) — plus T1645 Compromise Client Software Binary, T1661 Application Versioning (malicious update), T1474 Supply Chain Compromise (malicious SDK / distribution). Detection strategy: **DET0649**, Android analytic **AN1730** (package install/update events, hash/code drift, signer mismatch). MITRE notes the behavior is "seamless to the user" and often undetectable on-device.
- **Status:** research (not yet a skill)

## Defensive goal
Detect trojanized, cloned, or tampered app binaries and malicious app updates: an attacker decompiles a legitimate app, inserts a payload, re-signs it, and distributes it (side-load, third-party store, or a poisoned update), so malicious code executes under a trusted app's identity. This is strictly **binary / app-integrity** — keep it distinct from config-profile abuse and from permission-abusing surveillanceware.

## Data sources / telemetry
- **App integrity attestation:** Google **Play Integrity API** verdicts — `deviceIntegrity` (`MEETS_DEVICE_INTEGRITY` / `MEETS_BASIC_INTEGRITY` / `MEETS_STRONG_INTEGRITY`) and `appIntegrity.appRecognitionVerdict` (`PLAY_RECOGNIZED` vs `UNRECOGNIZED_VERSION` vs `UNEVALUATED`) — a repackaged/re-signed APK yields `UNRECOGNIZED_VERSION` and a mismatched `certificateSha256Digest`. iOS: App Attest (`DCAppAttestService`) binds attestation to the genuine app+team.
- **Signer / hash baseline:** package install and update events (Android `PackageInstaller`, logcat package events; MDM app inventory) — compare signing-certificate SHA-256 and APK/DEX hashes against the official store baseline. A signer mismatch for a known package name is the strongest single signal.
- **MDM/UEM app inventory:** Intune, Jamf, Workspace ONE, Android Enterprise app-version baselines, unknown-sources / side-load state, managed-vs-unmanaged app flag.
- **MTD repackaging/tampering alerts:** Lookout, Zimperium zIPS, Defender for Endpoint (mobile) app-reputation and tamper/clone detection; Google Play Protect app classification.
- **Supply-chain (T1474):** malicious or compromised SDK embedded in an otherwise legitimate app; compare dependency/SDK set against a known-good build.

## Detection logic / approach
Per DET0649 / AN1730: flag package install or update where the **signing cert or binary hash drifts** from the trusted baseline for that package name, or where there is no trusted distribution path (side-loaded, unknown source). Specifics:
- Signer-mismatch rule: same `packageName`, different signing-cert SHA-256 than the Play Store value.
- Version/update anomaly (T1661): an out-of-band version bump not reflected in the store's release history, or an install that downgrades signature scheme.
- **Janus awareness (CVE-2017-13156):** bytes prepended to an APK/DEX without breaking a v1 (JAR) signature — require v2/v3 APK Signature Scheme verification, which defeats Janus; flag apps relying on v1-only signatures.
- Server-side: enforce Play Integrity in the app backend and alert on `UNRECOGNIZED_VERSION` / failing device-integrity verdicts at scale.
- Fleet hunt: diff MDM app-version/hash inventory against the official baseline; investigate any package present outside the managed store.

## Response / mitigation
- Block/quarantine the device or app via MDM conditional access; remove the repackaged app (Play Protect uninstall), reinstall from the official store.
- Rotate credentials/tokens the trojanized app had access to; revoke server-side sessions keyed to failing integrity verdicts.
- Preventive: managed app store only, disable unknown sources, enforce Play Integrity / App Attest server-side, OWASP MASTG resilience (anti-tampering) checks in the build.

## Real tools
Google Play Integrity API, Play Protect; Apple App Attest (`DCAppAttestService`); Lookout, Zimperium zIPS, Microsoft Defender for Endpoint (mobile) tamper/repackaging detection; Intune / Jamf / Workspace ONE app inventory & version baselines; `apksigner` (signature-scheme verification), OWASP MASTG resiliency testing; VirusTotal (APK hash reputation).

## Draft frontmatter mappings
- mitre_attack: [T1577, T1645, T1661, T1474]
- nist_csf: [ID.AM-02, PR.PS-01, PR.PS-02, DE.CM-09]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): performing-android-app-static-analysis-with-mobsf

## Draft description (<=1024 chars)
Detects repackaged, trojanized, or cloned mobile app binaries and malicious app updates (T1577), including compromised client binaries (T1645), out-of-band version tampering (T1661), and malicious SDK or supply-chain injection (T1474). Compares signing-certificate SHA-256 and APK/DEX hashes against the official store baseline, flags signer mismatch and side-loaded packages, consumes Play Integrity and App Attest verdicts (UNRECOGNIZED_VERSION, failing device integrity), and reconciles MDM app-version inventory fleet-wide. Covers Janus (CVE-2017-13156) and v1-signature downgrade. Use when hunting repackaged apps, fake clones, poisoned updates, trojanized APKs, or malicious SDKs. Keywords: repackaging, Play Integrity, App Attest, signer mismatch, apksigner, Janus, side-load, APK hash, T1577, DET0649. Do not use for deep static reverse-engineering of one APK, use performing-android-app-static-analysis-with-mobsf.

## Key references
- https://attack.mitre.org/techniques/T1577/
- https://attack.mitre.org/detectionstrategies/DET0649/
- https://developer.android.com/google/play/integrity (Play Integrity verdict fields)
- https://developer.apple.com/documentation/devicecheck (App Attest)
- https://mas.owasp.org/MASTG/ (resilience / anti-tampering tests)

## Open questions / scope boundaries
- Verify current Play Integrity response field names and verdict enums against the live Play Integrity docs before shipping any rule — Google has renamed verdict fields across API revisions.
- Building the trusted signing-cert / hash baseline per package is the hard part; author must document sourcing it (Play Console, official store metadata) and handling legitimate re-signing (Play App Signing).
- Must NOT be a single-APK reverse-engineering procedure (that is performing-android-app-static-analysis-with-mobsf / analyzing-ios-app-security-with-objection) — this skill is fleet-scale integrity detection and response.
- Supply-chain (T1474) via malicious SDK overlaps with software-supply-chain skills; scope here is the mobile-app binary specifically.
