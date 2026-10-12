# Detecting Mobile Runtime Hooking and Instrumentation — research notes

- **Proposed slug:** detecting-mobile-runtime-hooking-and-instrumentation
- **ATT&CK (Mobile):** T1617 Hooking — folds in T1631 Process Injection (esp. T1631.001 Process Injection: Ptrace System Calls)
- **Status:** research (not yet a skill)

## Defensive goal
Detect runtime instrumentation of a *specific running app*: Frida, Xposed/LSPosed
and Magisk modules hooking methods, and code injected into another live process's
address space (ptrace, library injection) to tamper with, trace or extract
secrets from the target app at runtime. This is the RASP / app-integrity concern,
distinct from whole-device root: hooking typically rides on existing root but the
detectable behaviour is instrumentation of the app process (LightSpy injecting a
dylib into SpringBoard; FjordPhantom; Triada/INSOMNIA ptrace).

## Data sources / telemetry
- **In-app RASP / SDK signals (primary — the only source with process-level
  visibility).** The app itself (or an in-app protection SDK) checks for:
  - **Frida:** default server port **27042** / listening gadget, frida-server
    process, D-Bus handshake strings, injected `frida-agent` / `gum-js-loop` and
    `gmain` threads, named pipes / maps entries referencing frida.
  - **Xposed/LSPosed:** presence of the framework, hooked-method bridge classes,
    stack frames through the hook bridge, `de.robv.android.xposed` artifacts
    (verify package names).
  - **Magisk modules / Zygisk** injecting into the app zygote.
  - **ptrace / debugger attach (T1631.001):** `TracerPid` nonzero in
    `/proc/self/status`, unexpected `PTRACE_ATTACH`, anti-debug self-trace defeat.
  - **Native integrity:** modified GOT/PLT, inline hooks (patched prologues),
    unexpected `.so` in the process memory map.
- **MTD / app-vetting.** Lookout / Zimperium zIPS / Defender for Endpoint (mobile)
  may flag instrumentation frameworks and debugger attachment; MobSF dynamic
  analysis detects Frida usage; app-attestation (Play Integrity / App Attest)
  flags the compromised environment that hooking requires.
- **Forensics.** logcat around the target package for hook-bridge class loads;
  process maps; MVT for spyware-linked injection into system processes.

## Detection logic / approach
1. **Frida presence check (in-app).** Scan own process maps/threads for
   frida-agent artifacts; probe/expect no listener on 27042; detect the D-Bus
   handshake. Report telemetry server-side (not a client-only verdict a hooked
   app could suppress).
   ```
   if proc_maps_contains("frida-agent") or thread_named("gum-js-loop")
      or port_open(27042): report("frida instrumentation")
   ```
2. **Debugger / ptrace (T1631.001).** `TracerPid != 0` in `/proc/self/status`
   when no legitimate debugger is expected → injection/trace attempt.
3. **Hook-framework artifacts.** Xposed/LSPosed bridge classes on the stack,
   Magisk/Zygisk module traces, patched function prologues (inline hooks).
4. **Environment correlation.** Because hooking needs root/jailbreak, correlate
   any of the above with a failed attestation verdict — instrumentation + integrity
   loss is a strong, high-severity signal; attestation alone is the coarse gate,
   the in-app checks localise it to the targeted app.
5. **Caveat (MITRE DET0719).** A rooted device can falsify what on-device checks
   see, so no single client check is authoritative — combine with server-side
   attestation and anti-tamper so the reporting path itself resists the hook.

## Response / mitigation
Server-side: reject sessions/transactions from app instances reporting
instrumentation or failing attestation; require Play Integrity / App Attest before
sensitive operations; certificate-pin and obfuscate so hooking yields less. For
managed fleets, MTD instrumentation alert → non-compliant via Intune → Conditional
Access block + session revoke. Ship anti-tamper / RASP in high-value apps
(banking, auth). Treat injection into *system* processes (SpringBoard, zygote) as
possible targeted spyware and run forensics.

## Real tools
In-app RASP / mobile app-protection SDKs, Google Play Integrity API, Apple App
Attest / DeviceCheck, MobSF (dynamic), Lookout, Zimperium zIPS, Microsoft Defender
for Endpoint (mobile), Microsoft Intune + Conditional Access, ADB/logcat, MVT.
Instrumentation tool / family names for recognition only: Frida, Xposed/LSPosed,
Magisk/Zygisk, LightSpy, FjordPhantom, Triada.

## Draft frontmatter mappings
- mitre_attack: [T1617, T1631, T1631.001]
- nist_csf: [DE.CM-09, DE.AE-02, PR.PS-01, DE.CM-01, ID.AM-02, PR.AA-05]
- suggested subdomain: mobile-security
- nearest existing sibling (negative trigger): detecting-mobile-device-rooting-and-jailbreak

## Draft description (<=1024 chars)
Detects runtime hooking and instrumentation of a specific mobile app: Frida,
Xposed/LSPosed and Magisk modules hooking methods, and code injected into a live
process (ptrace, dylib/.so injection) to tamper with or extract secrets from the
target app (T1617 Hooking, T1631 Process Injection, T1631.001 Ptrace System Calls).
Works from in-app RASP signals (frida-agent in process maps, port 27042, TracerPid
nonzero, Xposed hook-bridge classes, inline-hook prologue patches), MTD
instrumentation alerts, MobSF dynamic analysis, and attestation failure that
hooking requires. Use when an app detects Frida or a debugger attach, hook-bridge
classes load, or injection into a process is suspected. Keywords: Frida, Xposed,
LSPosed, Magisk, hooking, ptrace, TracerPid, process injection, RASP, port 27042,
T1617, T1631. Do not use for whole-device root or jailbreak state - use
detecting-mobile-device-rooting-and-jailbreak.

## Key references
- MITRE ATT&CK Mobile T1617 Hooking (+ DET0719): https://attack.mitre.org/techniques/T1617/
- MITRE ATT&CK Mobile T1631 Process Injection + T1631.001 Ptrace: https://attack.mitre.org/techniques/T1631/
- OWASP MASTG resilience / anti-tamper & anti-debug testing: https://mas.owasp.org/MASTG/
- Google Play Integrity API: https://developer.android.com/google/play/integrity/overview

## Open questions / scope boundaries
- Author must decide where detection runs — in-app RASP SDK vs MTD vs app-vetting
  — since only the app process can see Frida/ptrace reliably, and a hooked app can
  suppress its own verdict (needs server-side reporting + attestation).
- Verify exact Frida/Xposed artifact names and package identifiers against current
  tool versions rather than hard-coding.
- MUST NOT cover whole-device integrity (that is
  detecting-mobile-device-rooting-and-jailbreak) — scope is instrumentation of a
  specific app process, even though it usually rides on root.
