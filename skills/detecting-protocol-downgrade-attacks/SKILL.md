---
name: detecting-protocol-downgrade-attacks
description: 'Detects downgrade attacks (MITRE T1689) where an adversary forces a system or protocol to a weaker legacy version to evade logging and protection - PowerShell v2 invocation that escapes v5 script-block/AMSI logging, TLS/SSL and SMB1 negotiation fallback, and RC4 Kerberos downgrades. Correlates version fields (PowerShell classic Event ID 400 EngineVersion vs HostVersion), process command lines (powershell -version 2), and negotiated protocol versions/ciphers against an environment baseline, and flags the absence of expected security telemetry. Use when hunting defense-evasion via legacy-component abuse, PowerShell downgrade, or protocol/cipher downgrade. Keywords: downgrade attack, PowerShell v2, EngineVersion, HostVersion, Event ID 400, TLS downgrade, SMB1, RC4 Kerberos, HSTS stripping, T1689. Do not use for generic endpoint defense-evasion triage - use detecting-evasion-techniques-in-endpoint-logs.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- downgrade-attack
- defense-evasion
- powershell
- tls
- smb1
- kerberos
- t1689
- windows
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.PS-01
- PR.IR-01
mitre_attack:
- T1689
- T1059.001
---

# Detecting Protocol & Component Downgrade Attacks

## When to Use

Use this skill to detect when an adversary **forces a system or protocol to fall
back to an older, weaker version** to evade security controls (ATT&CK T1689) —
for example invoking PowerShell v2 to escape v5 script-block/AMSI logging, or
coercing TLS/SMB/Kerberos negotiation down to a deprecated, weakly-logged, or
cryptographically breakable variant. The unifying idea: *the negotiated/selected
version is older than the environment baseline, and expected security telemetry
goes missing.* Reach for it when:

- Hunting defense-evasion via legacy-component abuse.
- A PowerShell engine/host version mismatch appears.
- TLS/SMB/Kerberos sessions negotiate a deprecated version or cipher.

For generic endpoint defense-evasion triage, use
`detecting-evasion-techniques-in-endpoint-logs`.

## Prerequisites

- **Windows PowerShell classic log** (`Windows PowerShell` / `Microsoft-Windows-
  PowerShell/Operational`) — **Event ID 400** with `EngineVersion` and
  `HostVersion` fields.
- **Process creation**: Sysmon Event ID 1 / Security 4688 (command line).
- **Network protocol telemetry**: Zeek `ssl.log` (`version`, `cipher`) and
  `smb_*` logs, or firewall/proxy TLS-inspection records capturing the negotiated
  version.
- **Kerberos**: Windows Security **Event ID 4768/4769** with the
  ticket-encryption-type field.
- A **baseline** of expected versions (PowerShell, TLS floor, SMB dialect,
  Kerberos etypes).

## Workflow

1. **PowerShell v2 downgrade (strongest signal).** Alert on classic-log Event ID
   400 where `EngineVersion` starts with `2.` while `HostVersion` does **not** —
   an engine/host version mismatch. Complement with process creation of
   `powershell.exe` with ` -version 2` (and `-v 2`, `-ver 2`).
2. **TLS/SSL downgrade.** In `ssl.log`, alert when `version` is SSLv3/TLS1.0/1.1
   to a host that normally negotiates TLS1.2+, or when `cipher` is on a deny-list.
   Watch HTTPS→HTTP fallback / HSTS stripping.
3. **SMB1 downgrade.** Alert on SMB1 dialect negotiation where SMB3 is the
   baseline.
4. **Kerberos RC4 downgrade.** Alert on 4769 with `Ticket Encryption Type = 0x17`
   (RC4-HMAC) for accounts/services expected to use AES (0x11/0x12).
5. **Watch for missing telemetry.** The *absence* of expected script-block
   logging (or other security evidence) where it is normally present is itself a
   downgrade signal — pivot to EDR/network telemetry for what ran.
6. **Respond** (see *Response*) — remove the legacy engine/protocol capability.

## Key Concepts

- **The negotiated-version mismatch is the tell.** Whether it is an interpreter
  (PowerShell v2) or a protocol (TLS1.0, SMB1, RC4 Kerberos), detection is
  "selected version older than baseline."
- **Downgrade defeats logging by design** — a v2 PowerShell session or an
  un-inspected legacy protocol produces little security telemetry, so pair
  version detection with the *absence* of expected evidence.
- **EngineVersion vs HostVersion:** a genuine v2 host logs `HostVersion` 2.x too;
  a downgrade on a modern host logs `EngineVersion` 2.x with a newer (or spoofed)
  `HostVersion`.
- **Prevention beats detection:** uninstalling the v2 engine and disabling
  legacy protocols removes the capability entirely.

## Tools & Systems

Sysmon, Windows Event Log (PowerShell classic log, Security log), SigmaHQ,
Elastic Security, Splunk, Microsoft Sentinel (KQL), Zeek, Velociraptor,
`Disable-WindowsOptionalFeature` (DISM/PowerShell).

## Detection Queries

### Sigma -- PowerShell v2 downgrade (engine/host mismatch)

```yaml
title: PowerShell Downgrade Attack (Engine/Host Version Mismatch)
status: test
logsource:
  product: windows
  service: powershell-classic
detection:
  selection:
    EventID: 400
    EngineVersion|startswith: '2.'
  filter_realv2:
    HostVersion|startswith: '2.'
  condition: selection and not filter_realv2
falsepositives:
  - Genuine legacy hosts still running PowerShell 2.0
level: medium
```

### Splunk -- powershell -version 2 command line

```spl
(`sysmon` EventCode=1 Image="*\\powershell.exe") OR (`wineventlog_security` EventCode=4688 New_Process_Name="*\\powershell.exe")
| eval cl=coalesce(CommandLine, Process_Command_Line)
| where match(cl, "(?i)\s-v(er(sion)?)?\s+2\b")
| table _time, host, user, cl, ParentImage
```

### Zeek / KQL -- TLS and SMB1 downgrade

```
# TLS: negotiated version below baseline to a normally-modern service
ssl.log | where version in ("SSLv3","TLSv10","TLSv11")
        | where server_name in (baseline_tls12_hosts)

# SMB1 dialect where SMB3 is baseline (smb mapping / Windows 4624 LogonType + smb_files)
smb_mapping.log | where dialect == "SMB1"
```

### Splunk -- RC4 Kerberos downgrade (Event 4769)

```spl
`wineventlog_security` EventCode=4769 Ticket_Encryption_Type=0x17
| search Service_Name!="krbtgt"
| stats count by Account_Name, Service_Name, Client_Address
| `comment("0x17 = RC4-HMAC; expect 0x11/0x12 (AES) for modern accounts")`
```

## Common Scenarios

- **PowerShell v2 evasion:** attacker runs `powershell -version 2 -enc ...` to
  avoid v5 script-block logging and AMSI — EID 400 mismatch + command line fire.
- **TLS stripping / downgrade:** a MitM forces TLS1.0/RC4 to weaken a channel.
- **SMB1 fallback:** lateral movement coerces SMB1 on a host where SMB3 is
  standard.
- **RC4 Kerberos:** 4769 with etype 0x17 for an AES-capable service (often paired
  with Kerberoasting).
- **False positive:** a genuine legacy appliance still on PowerShell 2.0 or TLS1.0
  — baseline it explicitly.

## Output Format

```
DOWNGRADE DETECTION
  Host/flow:       <host or src->dst>
  Verdict:         <confirmed | suspected | legacy-baseline>
  Component:       <PowerShell v2 | TLS1.0/SSLv3 | SMB1 | RC4 Kerberos>
  Evidence:        <EID400 EngineVersion vs HostVersion | -version 2 | ssl.log version | 4769 etype 0x17>
  Missing telem:   <no script-block logging in session | n/a>
  ATT&CK:          T1689[, T1059.001]
  Actions taken:   <v2 engine removed | legacy protocol disabled | host isolated>
```

## Response

- **Remove the legacy capability** (ATT&CK M1042): uninstall the PowerShell v2
  engine (`Disable-WindowsOptionalFeature -Online -FeatureName
  MicrosoftWindowsPowerShellV2*`) and remove unneeded legacy interpreters.
- **Harden configuration** (M1054): enforce HSTS; disable SSLv3/TLS1.0/1.1 and
  SMB1; require AES Kerberos etypes; enable PowerShell script-block & module
  logging and Constrained Language Mode (NIST CSF PR.PS-01).
- **Contain and review:** isolate the host and review what ran during the
  downgraded session using EDR/network telemetry, since native logging was weak
  by design.
