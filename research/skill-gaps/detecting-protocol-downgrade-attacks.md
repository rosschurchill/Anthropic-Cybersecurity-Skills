# Detecting Protocol & Component Downgrade Attacks — research notes

- **Proposed slug:** detecting-protocol-downgrade-attacks
- **ATT&CK:** T1689 Downgrade Attack (tactic: defense-evasion / in ATT&CK v19 the Defense Impairment tactic TA0112) — successor to the revoked sub-technique **T1562.010 Downgrade Attack**. Closely related: T1562 Impair Defenses, T1059.001 PowerShell.
- **Status:** research (not yet a skill)

> Note on scope: the proposed slug says "protocol," but T1689 is broader — it covers downgrading *any* system component (an interpreter/runtime version, a protocol, or a feature state) to a weaker variant that lacks logging or protection. The author should decide whether to keep the broad T1689 scope or split a narrower protocol-only skill. These notes cover both the component-version angle (PowerShell v2) and the protocol angle (TLS/SMB/Kerberos), because they share one detection idea: *the negotiated/selected version is older than the environment baseline.*

## Defensive goal
Detect when an adversary forces a system or protocol to fall back to an older, weaker version to evade security controls — e.g. invoking PowerShell v2 to escape v5 script-block/AMSI logging, or coercing TLS/SMB/Kerberos negotiation down to a deprecated cipher or protocol version that is weakly logged or cryptographically breakable. The skill flags version/feature mismatches against a known-good baseline and the *disappearance of expected security telemetry*.

## Data sources / telemetry
- **Windows PowerShell classic log** `Microsoft-Windows-PowerShell/Operational` and `Windows PowerShell` log — **Event ID 400** (Engine Lifecycle / EngineStart) with the `EngineVersion` and `HostVersion` fields. A `-Version 2` launch records `EngineVersion=2.0` while the host is a newer version.
- **Process creation** (Sysmon Event ID 1 / Security 4688) — command lines containing `-version 2`, `-v 2`, `-ver 2` for `powershell.exe`.
- **Sysmon Event ID 7 (Image/DLL load)** — loads of an older `System.Management.Automation.dll` / `System.Management.Automation.ni.dll` (verify exact module path per OS build).
- **Registry** (Sysmon 12/13/14) — changes to Microsoft Defender / HVCI (Hypervisor-protected Code Integrity) keys that reduce protection (per MITRE DET0350 / analytic AN0995 — verify exact key paths).
- **TLS/SMB negotiation telemetry** — Zeek `ssl.log` (`version`, `cipher`), Zeek `smb_*` logs, firewall/proxy TLS inspection records; network sensors capturing the `ServerHello`/negotiated version.
- **Kerberos** — Windows Security **Event ID 4768/4769** with the ticket-encryption-type field (watch for RC4 `0x17` where AES is expected).

## Detection logic / approach
PowerShell v2 downgrade (strongest, well-documented signal):
- **SigmaHQ rule** `posh_pc_downgrade_attack` (PowerShell Downgrade Attack): matches classic-log EID 400 where `EngineVersion` starts with `2.` while `HostVersion` does NOT start with `2.` — i.e. an engine/host version mismatch. Status: test, level: medium.
  ```
  logsource: product: windows, service: powershell-classic
  detection:
    selection: EventID: 400, EngineVersion|startswith: '2.'
    filter:    HostVersion|startswith: '2.'
    condition: selection and not filter
  ```
- Velociraptor/PowerPick research corroborates: EID 400 where `HostVersion` != `EngineVersion` (observed `HostVersion` often spoofed to `1.0`) indicates reflective/downgraded invocation.
- Process-creation complement (ManageEngine/Elastic style): `powershell.exe` with command line containing ` -version 2` (and short forms `-v 2`, `-ver 2`).

Protocol downgrade:
- **Elastic prebuilt detection** "Potential HTTP Downgrade Attack" — flag HTTPS→HTTP fallback / HSTS stripping patterns.
- **Zeek SPL/KQL** style: alert on `ssl.log` where `version` in (SSLv3, TLS1.0, TLS1.1) to a host/service that normally negotiates TLS1.2+, or `cipher` in a deny-list; alert on SMB1 dialect negotiation (`smb1`) where SMB3 is the baseline.
- **Kerberos:** alert on 4769 with `Ticket Encryption Type = 0x17` (RC4-HMAC) for accounts/services expected to use AES (0x11/0x12) — classic "RC4 downgrade."
- **Core correlation (per MITRE DET0350/AN0995 and AN0996/AN0997 inherited from T1562.010):** correlate command-line args + process metadata + version fields, AND watch for the *absence* of expected security evidence (no script-block logging where it is normally present = possible downgrade to an un-logged interpreter/protocol).

## Response / mitigation
- **M1042 Disable or Remove Feature or Program:** uninstall the PowerShell v2 engine (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2*`) and remove other legacy interpreters/runtimes not needed.
- **M1054 Software Configuration:** enforce HSTS for HTTP; disable SSLv3/TLS1.0/1.1 and SMB1; require AES Kerberos etypes; enable PowerShell script-block & module logging and Constrained Language Mode.
- Containment: isolate host, review what ran during the downgraded session (logging was weak by design — pivot to EDR/network telemetry).

## Real tools
Sysmon, Windows Event Log (PowerShell classic log, Security log), SigmaHQ, Elastic Security, Splunk, Microsoft Sentinel (KQL), Zeek, Velociraptor, `Disable-WindowsOptionalFeature` (DISM/PowerShell).

## Draft frontmatter mappings
- mitre_attack: [T1689, T1562, T1562.010, T1059.001]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, PR.PS-01, PR.IR-01]
- d3fend (optional): D3-SDM (System Daemon Monitoring), D3-NTA (Network Traffic Analysis), D3-SFA (Software/Firmware checks) — verify exact D3FEND ids
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): detecting-evasion-techniques-in-endpoint-logs

## Draft description (<=1024 chars)
Detects downgrade attacks where an adversary forces a system or protocol to a weaker legacy version to evade logging and protection — PowerShell v2 invocation that escapes v5 script-block/AMSI logging, TLS/SSL and SMB1 negotiation fallback, and RC4 Kerberos downgrades. Correlates version fields (EID 400 EngineVersion vs HostVersion), process command lines, and negotiated protocol versions against an environment baseline, and flags the absence of expected security telemetry. Use when hunting for defense-evasion via legacy-component abuse, PowerShell downgrade, or protocol/cipher downgrade. Keywords: downgrade attack, PowerShell v2, EngineVersion, HostVersion, EID 400, TLS downgrade, SMB1, RC4 Kerberos, HSTS stripping, T1689, T1562.010. Do not use for generic endpoint defense-evasion triage - use detecting-evasion-techniques-in-endpoint-logs.

## Key references
- https://attack.mitre.org/techniques/T1689/
- https://attack.mitre.org/detectionstrategies/DET0350 (Detecting Downgrade Attacks)
- https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/
- https://detection.fyi/sigmahq/sigma/windows/powershell/powershell_classic/posh_pc_downgrade_attack
- https://www.elastic.co/guide/en/security/current/potential-http-downgrade-attack.html
- https://docs.velociraptor.app/exchange/artifacts/pages/powerpickhostversion

## Open questions / scope boundaries
- Confirm the exact Defender/HVCI registry keys named in AN0995 before writing registry detections.
- Decide broad (component + protocol) vs. protocol-only scope given the slug.
- Verify the exact legacy `System.Management.Automation.dll` module path for image-load detection per Windows build.
- Must NOT cover general "Impair Defenses" (stopping EDR/logging services) beyond the downgrade angle — that is a sibling area (firewall/EDR tampering skills).
