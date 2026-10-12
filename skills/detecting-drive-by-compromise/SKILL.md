---
name: detecting-drive-by-compromise
description: 'Detects drive-by compromise (MITRE T1189) - browser-based initial access from watering-hole sites, malvertising, abused cloud-hosted scripts, XSS-injected content, exploit kits, and malicious push notifications - using a behavior-based chain: a suspicious browser fetch followed within ~2 minutes by unusual child processes (powershell/cmd/mshta/rundll32), memory injection, or dropped files. Combines Sysmon process/file/network events and Windows Event ID 4688 with Zeek/proxy HTTP content signals (unexpected content types for script URLs, obfuscated JavaScript, low-reputation redirect domains). Use when hunting browser exploitation, exploit kits, watering holes, or malvertising. Keywords: drive-by, watering hole, malvertising, exploit kit, browser child process, obfuscated JavaScript, Sysmon, Zeek http.log, T1189. Do not use for email-delivered phishing links - use detecting-spearphishing-with-email-gateway.'
domain: cybersecurity
subdomain: endpoint-security
tags:
- endpoint-security
- threat-detection
- initial-access
- drive-by-compromise
- watering-hole
- malvertising
- exploit-kit
- sysmon
- t1189
- browser-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.PS-02
- PR.IR-01
mitre_attack:
- T1189
- T1203
- T1059
- T1204
---

# Detecting Drive-by Compromise

## When to Use

Use this skill to detect **initial access where a user's browser is compromised
simply by visiting a web page** (ATT&CK T1189) — via a compromised legitimate
site (watering hole), malicious advertising, abused cloud-hosted scripts,
XSS-injected content, exploit kits, or malicious browser push notifications. The
detection chains a **web fetch from a browser to the suspicious execution that
follows** (unusual child processes, injected memory, dropped files) within a
short window, rather than relying on exploit-specific signatures. Reach for it
when:

- Hunting browser exploitation / exploit kits / watering holes / malvertising.
- A browser process spawns an interpreter or drops an executable.

For email-delivered phishing links use
`detecting-spearphishing-with-email-gateway`; for static URL triage use
`analyzing-malicious-url-with-urlscan`.

## Prerequisites

- **Browser → process behavior**: Sysmon Event ID 1 (children of
  `chrome.exe`/`msedge.exe`/`firefox.exe`), 8/10 (injection to/from the browser),
  11 (file create in browser cache/temp), 3/22 (network/DNS); Windows Security
  4688 with parent = browser.
- **HTTP/network content**: proxy/web-gateway logs and Zeek `http.log`/`files.log`
  (URL, referrer, response Content-Type, file hashes); IDS (Suricata/Snort) for
  exploit-kit landing/redirect signatures.
- Reputation enrichment: domain age, prevalence, URL/parameter reputation.
- A **CDN/benign-domain allowlist** for correlation.

## Workflow

1. **Baseline benign browser behavior** and high-volume CDNs so the behavior
   chain doesn't fire on normal browsing.
2. **Browser-spawns-interpreter.** Alert when a browser process spawns
   `powershell`/`cmd`/`wscript`/`cscript`/`rundll32`/`mshta` (Sysmon 1 / 4688).
3. **Injection / drop.** Flag CreateRemoteThread/process-access (Sysmon 8/10)
   to/from the browser, and droppers written to browser cache/temp (Sysmon 11).
4. **Correlate the chain.** Tie a suspicious browser fetch to the child process /
   injection / file drop within a **~2-minute window** (tune for caching/latency).
5. **Network-content signals.** Flag script URLs returning non-script content
   types, suspicious referrers, obfuscated JavaScript, and newly-registered /
   low-reputation domains in the redirect chain (malvertising ad-network
   referrers).
6. **Respond** (see *Response*) and hunt the redirect chain for other victims.

## Key Concepts

- **No user action beyond a visit:** unlike phishing links, drive-by needs no
  click on an attachment — the page itself exploits the browser, so the tell is
  the *post-visit execution*, not an email.
- **Behavior over signature:** exploit kits rotate payloads; the durable
  detection is "browser → interpreter/injection/drop within a short window."
- **The redirect chain matters:** watering-hole and malvertising flow through
  redirectors to a landing page — enriching the chain finds the campaign and
  other victims.
- **Window tuning is key:** too wide and benign downloads alias in; ~2 minutes
  balances caching/latency against noise.

## Tools & Systems

Zeek, Suricata/Snort, Sysmon, Microsoft Defender for Endpoint
(DeviceProcessEvents/DeviceFileEvents), CrowdStrike Falcon, web proxy / SWG,
urlscan.io, VirusTotal, Any.Run; browser isolation; DNS filtering.

## Detection Queries

### Sigma -- browser spawns a script interpreter

```yaml
title: Browser Spawning Script Interpreter (possible drive-by)
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: ['\chrome.exe','\msedge.exe','\firefox.exe']
    Image|endswith: ['\powershell.exe','\cmd.exe','\wscript.exe','\cscript.exe','\mshta.exe','\rundll32.exe']
  condition: selection
falsepositives:
  - Rare legitimate browser-launched helper apps (allowlist)
level: high
```

### KQL -- browser child + recent download within 2 minutes (Defender)

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe","wscript.exe")
| join kind=inner (
    DeviceFileEvents
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
    | where ActionType == "FileCreated"
    | project DeviceId, dropTime=TimeGenerated, FileName1=FileName
  ) on DeviceId
| where abs(datetime_diff('second', TimeGenerated, dropTime)) < 120
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, FileName1
```

### Zeek -- script URL returning non-script content / obfuscated JS

```
# http.log: URI ends .js but response is text/html, or long high-entropy body
http.log | where uri matches /\.js(\?|$)/ and resp_mime_types !has "javascript"
# enrich redirect host with domain age / reputation; flag newly-registered
```

## Common Scenarios

- **Exploit kit:** malvertising redirects to a landing page that exploits the
  browser; `chrome.exe` spawns `powershell -enc` — Sigma + KQL fire.
- **Watering hole:** a compromised industry site serves a dropper to visitors;
  browser writes an exe to temp then executes it.
- **Fake update:** a page prompts a "browser update" that drops a loader —
  browser-child + drop chain.
- **False positive:** a legitimate web app launching an approved helper —
  allowlisted.

## Output Format

```
DRIVE-BY COMPROMISE DETECTION
  Host/user:       <host> / <user>
  Verdict:         <confirmed | suspected | benign>
  Chain:           <browser> -> <child proc / injection / dropped file> within <n>s
  Landing/redirect: <url / domain> (age/reputation)
  Content signal:  <script-url wrong content-type | obfuscated JS | low-rep redirect>
  ATT&CK:          T1189[, T1203, T1059, T1204]
  Actions taken:   <host isolated | artifacts collected | domains blocked | redirect chain hunted>
```

## Response

- **Isolate the host**; collect browser history/cache, dropped files, and the
  process tree; block the landing/redirect domains at proxy/DNS.
- **Harden:** keep browsers/plugins patched (reduces T1203), enable browser
  sandboxing / site isolation, use remote browser isolation for high-risk users,
  ad/script blocking + DNS filtering, SmartScreen/Safe Browsing, and application
  control to stop browser-spawned interpreters (NIST CSF PR.PS-02).
- **Hunt the redirect chain** for other victims of the same watering-hole /
  malvertising source and submit URLs for analysis.
