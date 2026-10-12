# Detecting Drive-by Compromise — research notes

- **Proposed slug:** detecting-drive-by-compromise
- **ATT&CK:** T1189 Drive-by Compromise (tactic: initial-access). Detection strategy: **DET0176** (behavior-based, multi-platform). Legacy data-source guidance: DS0015 Application Log / network. Related: T1203 Exploitation for Client Execution, T1059 Command and Scripting Interpreter, T1566.002 Spearphishing Link (email-delivered — distinct), T1204 User Execution.
- **Status:** research (not yet a skill)

## Defensive goal
Detect initial access where a user's browser is compromised simply by visiting a web page — via a compromised legitimate site (watering hole), malicious advertising, abused cloud-hosted scripts, XSS-injected content, exploit kits, or malicious browser push notifications. The skill chains a web fetch from a browser to the suspicious execution that follows (unusual child processes, injected memory, dropped files) within a short window, rather than relying on exploit-specific signatures.

## Data sources / telemetry
- **Browser → process behavior (DET0176 core):** Sysmon Event ID **1** process-create for children of `chrome.exe`/`msedge.exe`/`firefox.exe` (especially `cmd.exe`, `powershell.exe`, `wscript/cscript`, `rundll32`, `mshta`); Sysmon **8** (CreateRemoteThread) / **10** (process access) for injection into/from the browser; Sysmon **11** (file create) for downloads/droppers in browser cache/temp paths; Sysmon **3/22** (network/DNS) from the browser.
- **Windows process creation:** Security 4688 with parent = browser.
- **HTTP/network content:** proxy/web-gateway logs and Zeek `http.log`/`files.log` — URL, referrer, response `Content-Type`, file hashes; IDS (Suricata/Snort) for exploit-kit landing/redirect signatures.
- **Reputation / enrichment (legacy DS0015):** domain age, registrant, prevalence (how many users connected), URL/parameter reputation from the proxy or firewall.
- macOS/Linux equivalents: EDR telemetry for browser child processes and file drops.

## Detection logic / approach
Per DET0176: correlate a suspicious browser fetch with unusual child processes, memory injection, or file drops within a **~2-minute window** (tune for caching/latency), and allowlist high-volume benign domains/CDNs. Network-content signals: HTTP responses with unexpected content types for script URLs, suspicious referrers, and obfuscated JavaScript.

Sigma (browser spawns script interpreter — concept):
```yaml
detection:
  selection:
    ParentImage|endswith: ['\chrome.exe','\msedge.exe','\firefox.exe']
    Image|endswith: ['\powershell.exe','\cmd.exe','\wscript.exe','\cscript.exe','\mshta.exe','\rundll32.exe']
  condition: selection
```
KQL (Microsoft Defender for Endpoint, browser child + recent download):
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe","wscript.exe")
| join kind=inner (DeviceFileEvents
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
    | where ActionType == "FileCreated") on DeviceId
| where abs(datetime_diff('second', TimeGenerated, TimeGenerated1)) < 120
```
Zeek/proxy: flag script URLs returning non-script content types, long/obfuscated JS, newly-registered or low-reputation domains in the redirect chain, and malvertising ad-network referrers.

## Response / mitigation
- Isolate the host; collect browser history/cache, dropped files, and process tree; block the landing/redirect domains at proxy/DNS.
- Hardening: keep browsers and plugins patched (reduces T1203 exploitation), enable browser exploit mitigations (sandboxing, site isolation), remote browser isolation for high-risk users, ad/script blocking and DNS filtering, SmartScreen/Safe Browsing, application control to stop browser-spawned interpreters.
- Hunt the redirect chain for other victims (same watering-hole/malvertising source) and submit URLs for analysis.

## Real tools
Zeek, Suricata/Snort, Sysmon, Microsoft Defender for Endpoint (DeviceProcessEvents/DeviceFileEvents), CrowdStrike Falcon, web proxy / SWG (Zscaler, Palo Alto, Netskope), urlscan.io, VirusTotal, Any.Run; browser isolation (Menlo, Cloudflare); DNS filtering (Umbrella/Quad9).

## Draft frontmatter mappings
- mitre_attack: [T1189, T1203, T1059, T1204]
- nist_csf: [DE.CM-01, DE.CM-07, DE.AE-02, PR.PS-02, PR.IR-01]
- suggested subdomain: endpoint-security
- nearest existing sibling (for the negative trigger): analyzing-malicious-url-with-urlscan

## Draft description (<=1024 chars)
Detects drive-by compromise (T1189) — browser-based initial access from watering-hole sites, malvertising, abused cloud-hosted scripts, XSS-injected content, exploit kits, and malicious push notifications — using a behavior-based chain (DET0176): a suspicious browser fetch followed within ~2 minutes by unusual child processes (powershell/cmd/mshta/rundll32), memory injection, or dropped files. Combines Sysmon process/file/network events and Windows 4688 with Zeek/proxy HTTP content signals (unexpected content types for script URLs, obfuscated JavaScript, low-reputation redirect domains). Use when hunting browser exploitation, exploit kits, watering holes, or malvertising. Keywords: drive-by, watering hole, malvertising, exploit kit, browser child process, obfuscated JavaScript, Sysmon, Zeek http.log, T1189, DET0176. Do not use for email-delivered phishing links (use detecting-spearphishing-with-email-gateway) or static URL triage (use analyzing-malicious-url-with-urlscan).

## Key references
- https://attack.mitre.org/techniques/T1189/
- https://attack.mitre.org/detectionstrategies/DET0176
- https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html (http.log fields)
- https://learn.microsoft.com/en-us/defender-endpoint/ (DeviceProcessEvents schema)

## Open questions / scope boundaries
- DET0176's 2-minute correlation window and CDN allowlist need per-environment tuning; author must document how to build the benign-domain allowlist.
- Must NOT duplicate exploit-specific analysis (T1203 / analyzing-heap-spray-exploitation) or JavaScript malware reversing (deobfuscating-javascript-malware) — reference them for deep-dive.
- Must NOT cover email-delivered links (T1566.002) — that is a different initial-access vector with email-gateway telemetry.
- Author must decide platform scope (Windows-centric Sysmon vs. cross-platform EDR) and whether to include network-sensor-only detection for environments without endpoint telemetry.
