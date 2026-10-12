---
name: detecting-malicious-software-extensions
description: 'Detects persistence via malicious or abused add-on extensions inside trusted apps (MITRE T1176): browser extensions (Chrome/Edge/Firefox) that steal cookies/sessions, inject into pages, or proxy traffic, and IDE extensions (VS Code, IntelliJ) that execute on dev/CI hosts - including abuse of benign features like code tunnel / Remote-SSH for a persistent reverse tunnel. Inventories installed extensions (osquery chrome_extensions), diffs against an approved allowlist, flags non-policy/sideloaded and high-permission add-ons, and catches IDE-tunnel process and network chains. Use when hunting extension-based persistence or triaging unknown browser/IDE add-ons. Keywords: T1176, browser extension, IDE extension, VS Code tunnel, code.exe tunnel, Remote-SSH, osquery chrome_extensions, ExtensionInstallForcelist, Open VSX. Do not use for registry/service/WMI autostart persistence - use analyzing-malware-persistence-with-autoruns.'
domain: cybersecurity
subdomain: endpoint-security
tags:
- endpoint-security
- threat-detection
- persistence
- browser-extensions
- ide-extensions
- osquery
- vs-code-tunnel
- cookie-theft
- t1176
- supply-chain-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.PS-01
- PR.PS-05
- ID.AM-02
mitre_attack:
- T1176
- T1176.001
- T1176.002
---

# Detecting Malicious Software Extensions

## When to Use

Use this skill to detect persistence established through **add-on extensions
that run inside a trusted application** (ATT&CK T1176). Two surfaces:

- **Browser extensions (T1176.001):** Chrome/Edge/Firefox add-ons that persist,
  steal cookies/sessions, inject into pages, or proxy traffic — arriving via
  malicious store listings, social engineering, sideloading, or enterprise
  force-install policy.
- **IDE extensions (T1176.002):** VS Code / IntelliJ / Eclipse extensions that
  execute on developer machines and CI, including abuse of benign features like
  `code tunnel` / Remote-SSH for a persistent reverse tunnel (Mustang Panda;
  Open VSX supply-chain compromises).

Reach for it when hunting extension-based persistence or triaging unknown
browser/IDE add-ons. For OS-level autostart persistence (registry/service/WMI)
use `analyzing-malware-persistence-with-autoruns`; for browser artifact
forensics use `extracting-browser-history-artifacts`.

## Prerequisites

- **Browser extension inventory**: osquery `chrome_extensions` / `firefox_addons`
  (join `users`); on-disk extension dirs; enterprise force-install policy and
  install source (policy vs user vs sideload).
- **IDE extension inventory & activity**: `~/.vscode/extensions`, JetBrains
  plugins dir; Sysmon/EDR process creation (Event ID 1) and network (Event ID 3)
  for `code.exe`/`code` running with `tunnel`/`--install-extension`/`serve-web`
  or spawning shells/ssh.
- EDR fields: process ancestry, command line, signer, profile file writes, DNS/
  connection destinations.
- An **approved-extension allowlist** and a maintained known-bad ID feed.

## Workflow

1. **Browser inventory + diff.** Run a scheduled osquery on `chrome_extensions`,
   diff against the approved allowlist, and alert on any new/unknown extension ID
   and on extensions **not** installed via managed policy.
2. **Browser reputation + risk.** Cross-reference IDs against known-bad
   advisories; flag high-risk permissions (`<all_urls>`, `webRequest`, `cookies`,
   `debugger`), unpacked/`development_mode` loads, and update-URL changes
   (bait-and-switch).
3. **IDE process chain.** Alert when an IDE binary starts on a **non-developer
   endpoint / server**, especially with `tunnel`/`serve-web`/`--install-extension`
   flags, followed by extension files appearing under the profile and outbound
   connections to marketplace/tunnel services; flag IDEs spawning shells,
   interpreters, `ssh`, or package managers.
4. **Scope to cut FPs.** Apply the IDE rules to non-developer users / production
   servers; account for the ~2-hour VS Code extension auto-update delay.
5. **Respond** (see *Response*).

## Key Concepts

- **The host app is trusted:** an extension inherits the browser's sessions or
  the IDE's execution context, so persistence hides inside a signed, allowed
  process — inventory + source + permissions, not a binary signature, is the
  detection.
- **Install source is decisive:** a sideloaded (non-policy) extension on a managed
  fleet is the single strongest browser signal.
- **`code tunnel` is living-off-the-land persistence:** a legitimate VS Code
  feature becomes a reverse tunnel; its appearance on a server is high-signal.
- **Cookie theft needs re-auth:** a malicious browser extension may have exported
  session cookies — remediation must force re-authentication.

## Tools & Systems

osquery (`chrome_extensions`, `firefox_addons`), CrowdStrike Falcon for IT,
Elastic Security/Defend, Sysmon, Microsoft Defender; Chrome Enterprise / Edge /
Firefox ADMX policies; VS Code / Open VSX, JetBrains Marketplace vetting; Atomic
Red Team T1176 (detection validation).

## Detection Queries

### osquery -- browser extensions per user (non-webstore / known-bad)

```sql
SELECT u.username, e.name, e.identifier, e.version, e.permissions,
       e.from_webstore, e.path
FROM users u CROSS JOIN chrome_extensions e USING (uid)
WHERE e.from_webstore = '0'
   OR e.identifier IN (/* known-bad extension IDs */)
   OR e.permissions LIKE '%<all_urls>%';
```

### Sigma -- VS Code tunnel on a non-developer host (IDE extension abuse)

```yaml
title: VS Code Tunnel Execution (possible persistence)
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: ['\code.exe','\code-tunnel.exe']
    CommandLine|contains: ' tunnel'
  condition: selection
falsepositives:
  - Developers legitimately using VS Code tunnels (scope rule to non-dev hosts)
level: high
```

### Splunk -- new browser extension diff + high-risk permissions

```spl
`osquery_chrome_extensions`
| search NOT [ | inputlookup approved_extensions | fields identifier ]
| where from_webstore=0 OR match(permissions, "(?i)(all_urls|webRequest|cookies|debugger)")
| table _time, host, username, name, identifier, version, permissions, path
```

## Common Scenarios

- **Cookie-stealer extension:** a sideloaded Chrome extension with `cookies` +
  `<all_urls>` exfiltrates session tokens — non-webstore + high-permission fires;
  remediation forces re-auth.
- **Open VSX supply chain:** a trojanized VS Code extension beacons out on a dev
  machine.
- **`code tunnel` persistence:** attacker runs `code tunnel` on a server for a
  durable reverse channel — Sigma rule fires.
- **False positive:** a developer installing an approved extension — allowlisted;
  IDE rules scoped to non-dev hosts.

## Output Format

```
MALICIOUS EXTENSION DETECTION
  Host/user:       <host> / <user>
  Verdict:         <confirmed | suspected | approved>
  Surface:         <browser (T1176.001) | IDE (T1176.002)>
  Extension:       <name/id/version>, source <policy|user|sideload>, perms <high-risk?>
  IDE chain:       <code tunnel | serve-web | spawned shell/ssh | n/a>
  ATT&CK:          T1176[.001/.002]
  Actions taken:   <extension removed | sessions revoked/re-auth | fleet hunted for ID | tunnel killed | dev creds rotated>
```

## Response

- **Browser:** enforce allow/deny lists via Group Policy / Chrome Enterprise /
  Edge policy (`ExtensionInstallBlocklist=*` + allowlist/forcelist); remove
  unknown extensions and **revoke/rotate any sessions** a cookie-stealer could
  have taken (NIST CSF PR.PS-05).
- **IDE:** restrict extension sources to a vetted internal gallery / Open VSX
  mirror; block `code tunnel`/Remote-SSH on servers and non-dev endpoints via
  egress + process controls; monitor dev machines and CI runners.
- **Respond:** remove the extension, preserve its package/manifest for analysis,
  hunt the same ID across the fleet, revoke tunnel sessions, and rotate dev
  credentials/tokens the extension could reach.
