---
name: detecting-mobile-runtime-hooking-and-instrumentation
description: 'Detects runtime hooking and instrumentation of a specific mobile app: Frida, Xposed/LSPosed and Magisk modules hooking methods, and code injected into a live process (ptrace, dylib or .so injection) to tamper with, trace or extract secrets from the target app (T1617 Hooking, T1631 Process Injection). This is the RASP and app-integrity concern, distinct from whole-device root. Works from in-app RASP signals (frida-agent in the process memory map, the default Frida listener port, a nonzero TracerPid, Xposed hook-bridge classes, inline-hook prologue patches), MTD instrumentation alerts, MobSF dynamic analysis, and the attestation failure hooking requires. Use when an app detects Frida or a debugger attach, hook-bridge classes load, or dylib injection is suspected. Keywords: Frida, Xposed, LSPosed, Magisk, hooking, ptrace, TracerPid, process injection, RASP, instrumentation, Android, iOS, T1617, T1631. Do not use for whole-device root or jailbreak state - use detecting-mobile-device-rooting-and-jailbreak.'
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile
- android
- ios
- runtime-hooking
- instrumentation
- frida
- process-injection
- t1617
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.AE-02
- PR.PS-01
- DE.CM-01
- ID.AM-02
- PR.AA-05
mitre_attack:
- T1617
- T1631
---

# Detecting Mobile Runtime Hooking and Instrumentation

## When to Use

Use this skill to detect **runtime instrumentation of a specific running app**:
Frida, Xposed/LSPosed and Magisk modules hooking methods (ATT&CK T1617 Hooking),
and code injected into another live process's address space — ptrace, dylib/`.so`
injection — to tamper with, trace or extract secrets from the target app (T1631
Process Injection). This is the **RASP / app-integrity** concern: hooking usually
rides on existing root, but the detectable behaviour is instrumentation *inside
one app process* (for example a dylib injected into SpringBoard, FjordPhantom, or
Triada ptrace). Reach for it when:

- An app's own protection detects Frida or a debugger attach.
- Hook-bridge classes load into a target app.
- Injection into an app or system process is suspected.

Scope is **one app process**. For the underlying whole-device state — is this
device rooted or jailbroken at all — use
`detecting-mobile-device-rooting-and-jailbreak`. The two are a deliberate split:
root is the platform, hooking is the instrumentation that runs on it.

## Prerequisites

- **In-app RASP / app-protection SDK (primary — the only source with process-level
  visibility).** Only the app process can reliably see Frida/ptrace; a mobile
  app-protection SDK or custom checks that report **server-side** (so a hooked app
  cannot simply suppress its own verdict).
- **Server-side attestation.** Google Play Integrity API / Apple App Attest — the
  coarse gate that flags the compromised environment hooking requires.
- **MTD / app-vetting.** Lookout, Zimperium zIPS, Microsoft Defender for Endpoint
  (mobile) may flag instrumentation frameworks and debugger attachment; MobSF
  dynamic analysis detects Frida usage during triage.
- **Forensics.** ADB/logcat around the target package; process memory maps; MVT
  where injection into system processes suggests targeted spyware.

## Workflow

1. **Frida presence check (in-app).** The app scans its own process memory map and
   threads for instrumentation artifacts (frida-agent in the maps, injector thread
   names, a listener on the default Frida port) and reports telemetry
   server-side — never a client-only verdict a hooked app could rewrite. Treat the
   exact artifact names, thread names and the default port number as **illustrative,
   verify against current tool versions**; the durable signal is an unexpected
   injected agent in the process, not a fixed string.
2. **Debugger / ptrace detection.** A nonzero `TracerPid` in `/proc/<pid>/status`
   when no legitimate debugger is expected, or an unexpected trace attach, indicates
   injection/tracing (T1631 ptrace-based). That is an Android/Linux construct; iOS
   has no procfs, so the equivalent check there is the `P_TRACED` flag read via
   `sysctl`.
3. **Hook-framework artifacts.** Xposed/LSPosed hook-bridge classes on the call
   stack, Magisk/Zygisk module traces injecting into the app's zygote, or patched
   function prologues (inline hooks) in native code. Verify package identifiers
   against current framework versions.
4. **Environment correlation.** Because hooking needs root/jailbreak, correlate any
   of the above with a **failed attestation verdict** — instrumentation plus
   integrity loss is a strong, high-severity signal. Attestation is the coarse gate;
   the in-app checks localise it to the targeted app.
5. **Respond** (see *Response*).

## Key Concepts

- **No single client check is authoritative.** A rooted device can falsify what
  on-device checks see, so combine in-app signals with server-side attestation and
  anti-tamper, so the *reporting path itself* resists the hook.
- **Process-level visibility is unique to the app.** MTD and attestation see the
  compromised environment; only the app process sees Frida/ptrace against *itself*,
  which is why RASP telemetry is the primary source.
- **Behavioural over constant.** Default ports, agent names and bridge-class package
  names change between tool releases — treat them as illustrative and verify. The
  signal is "something is instrumenting this process," not a specific token.
- **Rides on root but is not root.** Hooking localises the threat to one app;
  whole-device root is the separate, coarser state — keep the two skills distinct.
- **System-process injection is worse.** Injection into SpringBoard, the zygote or
  another system process points to targeted spyware, not a hobbyist hook — escalate
  and run forensics.

## Tools & Systems

In-app RASP / mobile app-protection SDKs, Google Play Integrity API, Apple App
Attest / DeviceCheck, MobSF (dynamic analysis), Lookout, Zimperium zIPS, Microsoft
Defender for Endpoint (mobile), Microsoft Intune compliance + Entra Conditional
Access, ADB/logcat, MVT. Instrumentation tool / family names for recognition only:
Frida, Xposed/LSPosed, Magisk/Zygisk, LightSpy, FjordPhantom, Triada.

## Detection Queries

Treat artifact names, port numbers, field names and thresholds as
**verify/tune** against current tool versions.

### In-app RASP self-check (concept)

```
# Runs inside the protected app; reports result SERVER-SIDE, not as a local verdict.
if proc_maps_contains("frida-agent")                 # verify artifact name
   or thread_named_like("gum-js-loop", "gmain")      # verify thread names
   or listener_on(default_frida_port):               # verify current default port
       report_server("frida instrumentation", package, device)
if tracer_pid() != 0 and no_expected_debugger():     # ptrace / debugger attach
       report_server("debugger/ptrace attach", package, device)
```

### Hook-framework / inline-hook artifacts (concept)

```
# Xposed/LSPosed: hook-bridge classes on the stack (verify package identifiers)
# Magisk/Zygisk: module traces injecting into the app zygote
# Native: patched function prologues (inline hooks), unexpected .so in the memory map
```

### Microsoft Sentinel (KQL) -- MTD instrumentation alert with attestation failure

```kql
// MTD instrumentation detections surface as ALERTS, not in a DeviceTvm* table:
// use AlertInfo/AlertEvidence (Defender XDR advanced hunting, also available in
// Sentinel via the XDR connector) or SecurityAlert (Sentinel-native).
// Verify table/column names for your MTD + attestation telemetry.
AlertInfo
| where Title has_any ("Frida", "Xposed", "instrumentation", "debugger", "injection")  // verify/tune
| join kind=inner (AlertEvidence | where isnotempty(DeviceId)
                   | project AlertId, DeviceId, AccountUpn) on AlertId
| project TimeGenerated, DeviceId, UserPrincipalName = AccountUpn, ThreatName = Title
| join kind=inner (
    AttestationResults                      // your Play Integrity / App Attest sink; verify
    | where VerdictPassed == false
    | project AttestTime=TimeGenerated, DeviceId, Verdict
  ) on DeviceId
| where AttestTime between (TimeGenerated - 1h .. TimeGenerated + 1h)
```

## Common Scenarios

- **Frida on a banking app:** RASP reports frida-agent in the maps and a listener on
  the default port; attestation also fails — high-severity, session rejected.
- **LSPosed module:** hook-bridge classes load into the target app to defeat a
  security check; correlated with a failed integrity verdict.
- **Targeted spyware injection:** a dylib injected into a system process (e.g.
  SpringBoard) — escalated as possible targeted compromise, MVT forensics run.
- **False positive:** an in-house QA build instrumented on a known test device —
  excluded by a test-device exception, not shipped to production policy.

## Output Format

```
RUNTIME HOOKING / INSTRUMENTATION DETECTION
  Device:          <device id / user / platform>
  App:             <target package>
  Verdict:         <confirmed | suspected | test-device-benign>
  Signal:          <frida-agent in maps | listener on Frida port | TracerPid != 0 | Xposed bridge | inline hook | dylib injection>
  Attestation:     <Play Integrity / App Attest verdict (pass/fail)>
  Severity driver: <instrumentation + failed attestation | system-process injection>
  ATT&CK:          T1617, T1631
  Actions taken:   <session/transaction rejected | CA block + revoke | app non-compliant | MVT forensics on injection>
```

## Response

- **Server-side:** reject sessions/transactions from app instances reporting
  instrumentation or failing attestation; require Play Integrity / App Attest before
  sensitive operations; certificate-pin and obfuscate so a hook yields less.
- **Fleet:** an MTD instrumentation alert marks the device non-compliant in Intune,
  and Conditional Access blocks and revokes sessions.
- **Harden high-value apps** (banking, auth) with anti-tamper / RASP whose reporting
  path resists the very hook it detects.
- **Treat injection into system processes** (SpringBoard, zygote) as possible
  targeted spyware and run MVT/forensics.
