# Detecting Malicious Software Extensions — research notes

- **Proposed slug:** detecting-malicious-software-extensions
- **ATT&CK:** T1176 Software Extensions (tactic: persistence) — sub-techniques: **T1176.001 Browser Extensions** and **T1176.002 IDE Extensions** (the latter added in ATT&CK release 19.1). Detection strategy for IDE extensions: **DET0561** (verify against v19.2); browser-extension DET id not confirmed here — **verify against v19.2**. (Note: T1176 was restructured from a single technique into the parent + two sub-techniques; confirm current numbering in v19.2.)
- **Status:** research (not yet a skill)

## Defensive goal
Detect persistence established through add-on extensions that run inside a trusted application. Two surfaces: (1) **browser extensions** (Chrome/Edge/Firefox) that persist, steal cookies/sessions, inject into pages, or proxy traffic — reaching the browser via malicious store listings, social engineering, or post-compromise sideloading / enterprise force-install policy; (2) **IDE extensions** (VS Code, IntelliJ, Eclipse) that execute on developer machines and CI, including abuse of benign features such as `code tunnel` / Remote-SSH for a persistent reverse tunnel (Mustang Panda; TeamPCP compromising VS Code / Open VSX extensions). The skill inventories installed extensions, flags unapproved/newly added ones, and catches IDE-tunnel process/network behaviour.

## Data sources / telemetry
- **Browser extension inventory:** osquery `chrome_extensions` and `firefox_addons` tables (join to `users`); on-disk extension dirs (`%LocalAppData%\Google\Chrome\User Data\*\Extensions`, Firefox profiles `extensions.json`); enterprise force-install policy (`ExtensionInstallForcelist`) and management source (whether an extension was installed by policy vs user vs sideload). Chrome `chrome://extensions` / Edge management, browser `Preferences`/`Secure Preferences` files.
- **IDE extension inventory & activity:** installed-extension dirs (`~/.vscode/extensions`, `%USERPROFILE%\.vscode\extensions`, JetBrains plugins dir); EDR/Sysmon process creation (Event ID 1) and network (Event ID 3); the IDE binary (`code.exe`/`code`) spawning shells/interpreters/ssh, or running with `tunnel` / `--install-extension` / `serve-web` arguments; outbound connections to marketplace and tunnel endpoints.
- **EDR fields generally:** process ancestry, command line, signer, file writes under the user profile, DNS/connection destinations.

## Detection logic / approach
**Browser (T1176.001) — inventory + reputation + anomaly:**
- Maintain a real-time inventory (osquery scheduled query on `chrome_extensions`) and diff against an approved allowlist; alert on any new/unknown extension ID and on extensions **not** installed via managed policy.
- Cross-reference IDs against known-bad advisories/blocklists; flag extensions with high-risk permissions (`<all_urls>`, `webRequest`, `cookies`, `debugger`), unpacked/`development_mode` loads, and update-URL changes (bait-and-switch).
- CrowdStrike Falcon-for-IT sample pattern: join `users` → `chrome_extensions` on `uid`, filter on a known-bad ID list. Elastic builds the same inventory via osquery + Elastic Defend.
```sql
-- osquery: enumerate browser extensions per user
SELECT u.username, e.name, e.identifier, e.version, e.permissions, e.from_webstore, e.path
FROM users u CROSS JOIN chrome_extensions e USING (uid)
WHERE e.from_webstore = '0' OR e.identifier IN (/* known-bad IDs */);
```

**IDE (T1176.002) — process chain (per DET0561):**
- Alert when the IDE binary starts on a **non-developer endpoint / server**, especially with `install`/`--install-extension`, `tunnel`, or `serve-web` flags, followed by extension files appearing under the user profile and outbound connections to marketplace or tunnel services.
- Flag IDEs spawning unexpected children: shells, interpreters, `ssh`, package managers.
- Sigma-style: execution of `code.exe`/`code-tunnel.exe` with a `tunnel` argument whose parent is not a normal developer parent process; and portable-binary abuse (`code` run with `tunnel` from a non-standard path).
- Scope rules to non-developer users / production servers to cut false positives; account for the ~2-hour VS Code extension auto-update delay when timing update-based detection.

## Response / mitigation
- Browser: enforce extension allow/deny lists via Group Policy / Chrome Enterprise / Edge policy (`ExtensionInstallBlocklist`=`*` + `ExtensionInstallForcelist`/`ExtensionInstallAllowlist`); audit installed extensions against an approved list; remove unknown extensions and revoke/rotate any sessions the extension could have stolen (cookie theft → force re-auth).
- IDE: restrict extension sources to a vetted internal gallery/Open VSX mirror; block `code tunnel`/Remote-SSH on servers and non-dev endpoints via network egress + process controls; code-review/vet extensions; monitor developer machines and CI runners specifically.
- Response: remove the extension, preserve the extension package/manifest for analysis, hunt the same ID across the fleet, revoke tunnel sessions and rotate dev credentials/tokens the extension could reach.

## Real tools
osquery (`chrome_extensions`, `firefox_addons`), CrowdStrike Falcon for IT, Elastic Security/Defend, Sysmon, Microsoft Defender; Chrome Enterprise / Edge / Firefox ADMX policies; VS Code / Open VSX, JetBrains Marketplace (vetting); Atomic Red Team T1176 (detection validation); CRXcavator-style extension-risk analysis (verify current tooling).

## Draft frontmatter mappings
- mitre_attack: [T1176, T1176.001, T1176.002]
- nist_csf: [DE.CM-09, DE.CM-01, DE.AE-02, PR.PS-01, PR.PS-05, ID.AM-02]
- suggested subdomain: endpoint-security
- nearest existing sibling (for the negative trigger): analyzing-malware-persistence-with-autoruns

## Draft description (<=1024 chars)
Detects persistence via malicious or abused add-on extensions inside trusted apps: browser extensions (Chrome/Edge/Firefox) that steal cookies/sessions, inject into pages, or proxy traffic, and IDE extensions (VS Code, IntelliJ) that execute on dev/CI hosts — including abuse of benign features like `code tunnel`/Remote-SSH for a persistent reverse tunnel. Inventories installed extensions (osquery chrome_extensions), diffs against an approved allowlist, flags non-policy/sideloaded and high-permission add-ons, and catches IDE-tunnel process and network chains. Use when hunting extension-based persistence or triaging unknown browser/IDE add-ons. Keywords: T1176, browser extension, IDE extension, VS Code tunnel, code.exe tunnel, Remote-SSH, osquery chrome_extensions, ExtensionInstallForcelist, Open VSX, DET0561. Do not use for registry/service/WMI autostart persistence (use analyzing-malware-persistence-with-autoruns) or browser history forensics (use extracting-browser-history-artifacts).

## Key references
- https://attack.mitre.org/techniques/T1176/
- https://attack.mitre.org/techniques/T1176/001/
- https://attack.mitre.org/techniques/T1176/002/
- https://attack.mitre.org/detectionstrategies/DET0561 (IDE extensions — verify id against v19.2)
- https://www.elastic.co/blog/how-to-detect-malicious-browser-extensions-using-elastic
- https://www.crowdstrike.com/tech-hub/it-automation/hunting-weaponized-chrome-extensions-with-falcon-for-it/

## Open questions / scope boundaries
- Verify the browser-extension detection-strategy id (DET id not confirmed) and DET0561 for IDE extensions against v19.2; confirm T1176.002 was introduced in release 19.1.
- Confirm current osquery `chrome_extensions` columns (e.g., `from_webstore`) and Firefox table name across platforms before writing queries.
- Author must supply the approved-extension allowlist and a maintained known-bad ID feed.
- Must NOT cover OS-level autostart persistence (autoruns/registry/WMI) or browser artifact forensics; scope is the extension layer of browsers and IDEs. Office/add-in macros are a separate technique (T1137-family) — out of scope.
