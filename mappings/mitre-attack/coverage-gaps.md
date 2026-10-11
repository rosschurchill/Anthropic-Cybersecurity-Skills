# MITRE ATT&CK Coverage Gaps

Companion to [`coverage-summary.md`](coverage-summary.md). This is a **content
gap review**: it diffs the `mitre_attack:` IDs declared across all skills
against the current MITRE ATT&CK Enterprise technique set, then judges which
uncovered techniques are worth a new skill and which are not.

## Headline numbers

- ATT&CK Enterprise base techniques (current, non-deprecated): **222**
- Covered by at least one skill: **139 (62%)**
- Uncovered base techniques: **83**

Coverage is measured at the **base-technique** (`Txxxx`) level — a skill that
maps a sub-technique counts its parent as covered. 806 of 818 skills declare
`mitre_attack`; the 12 that do not are AI-security skills mapped to
[MITRE ATLAS](../mitre-atlas/) instead, which is correct.

## How to read this

Not every ATT&CK technique warrants a standalone skill. Many uncovered entries
are **atomic discovery/execution primitives** an adversary runs in seconds
(e.g. *System Time Discovery*), which real detection skills already fold into
broader hunting procedures. Authoring a dedicated skill for each would add
catalogue noise and routing collisions without adding defensive capability. The
tiers below separate genuine capability gaps from primitives already covered in
spirit.

Technique IDs and names come from the authoritative ATT&CK STIX data; nothing
here is invented. Where a technique appears under a newer ATT&CK tactic grouping
(e.g. `stealth`, `defense-impairment`), the tactic name is reproduced as the
data gives it.

---

## Tier A — real capability gaps, worth a skill

High-impact techniques with no current coverage, where a focused defensive
(detection / response / hardening) skill would add genuine value.

| ATT&CK | Technique | Angle a skill would take |
|--------|-----------|--------------------------|
| T1561 | Disk Wipe | Detect/respond to destructive wiper activity (raw disk writes, `\\.\PhysicalDrive` handles) |
| T1495 | Firmware Corruption | Detect destructive firmware flashing; recovery procedure |
| T1491 | Defacement | Detect web/internal defacement; integrity monitoring + response |
| T1498 | Network Denial of Service | Detect/mitigate volumetric & protocol DoS |
| T1499 | Endpoint Denial of Service | Detect resource-exhaustion / app-layer DoS |
| T1529 | System Shutdown/Reboot | Detect mass shutdown/reboot as an impact signal |
| T1667 | Email Bombing | Detect subscription-bomb / inbox-flood social-engineering cover |
| T1111 | Multi-Factor Authentication Interception | Detect MFA-interception / token-relay / real-time phishing proxies |
| T1689 | Downgrade Attack | Detect protocol/version downgrade (TLS, SMB, PowerShell v2, Kerberos encryption) |
| T1686 | Disable or Modify System Firewall | Detect host-firewall tampering |
| T1690 | Prevent Command History Logging | Detect shell-history evasion (HISTFILE unset, PSReadLine tamper) |
| T1599 | Network Boundary Bridging | Detect dual-homed / boundary-bridging pivots |
| T1578 | Modify Cloud Compute Infrastructure | Detect malicious snapshot/instance/volume changes (cloud IR) |
| T1666 | Modify Cloud Resource Hierarchy | Detect org/folder/account hierarchy tampering |
| T1677 | Poisoned Pipeline Execution | Detect CI/CD pipeline poisoning (build-config injection) |
| T1654 | Log Enumeration | Detect adversary log reconnaissance pre-tampering |
| T1020 | Automated Exfiltration | Detect scripted/scheduled bulk exfil |
| T1563 | Remote Service Session Hijacking | Detect RDP/SSH session hijack |
| T1560 | Archive Collected Data | Detect staging/archiving before exfil (rar/7z/zip spikes) |
| T1132 | Data Encoding | Detect encoded C2 channels (base64/custom over HTTP/DNS) |
| T1104 | Multi-Stage Channels | Detect staged C2 (loader → second-stage beacon) |

## Tier B — moderate value, fold-in candidates

Legitimate techniques, but each is a narrow variant of a family the catalogue
already covers (LOLBin proxy execution, cloud exec, data-from-X collection). A
new skill is optional; the higher-leverage move is extending an existing
hunting/detection skill's scope and `mitre_attack` list.

- **Proxy / indirect execution:** T1127 Trusted Developer Utilities, T1216 System Script Proxy Execution, T1220 XSL Script Processing, T1221 Template Injection, T1202 Indirect Command Execution — all LOLBin-family, extend the existing LOLBin hunting skills.
- **Execution surfaces:** T1569 System Services, T1651 Cloud Administration Command, T1675 ESXi Administration Command, T1197 BITS Jobs, T1559 Inter-Process Communication, T1129 Shared Modules, T1072 Software Deployment Tools.
- **Collection:** T1113 Screen Capture, T1123 Audio Capture, T1125 Video Capture, T1115 Clipboard Data, T1039 Data from Network Shared Drive, T1602 Data from Configuration Repository.
- **C2 / exfil:** T1205 Traffic Signaling, T1665 Hide Infrastructure, T1092 Communication Through Removable Media, T1029 Scheduled Transfer, T1030 Data Transfer Size Limits.
- **Persistence / misc:** T1176 Software Extensions, T1671 Cloud Application Integration, T1668 Exclusive Control, T1653 Power Settings, T1080 Taint Shared Content, T1615 Group Policy Discovery, T1601 Modify System Image, T1647 Plist File Modification, T1688 Safe Mode Boot, T1535 Unused/Unsupported Cloud Regions.

## Tier C — primitives, not worth standalone skills

Atomic discovery/recon steps adversaries run inline; detection belongs inside
broader hunting skills, not a dedicated procedure. Listed for completeness.

T1007 System Service Discovery · T1010 Application Window Discovery · T1016
System Network Configuration Discovery · T1033 System Owner/User Discovery ·
T1120 Peripheral Device Discovery · T1124 System Time Discovery · T1201
Password Policy Discovery · T1518 Software Discovery · T1614 System Location
Discovery · T1622 Debugger Evasion · T1652 Device Driver Discovery · T1673
Virtual Machine Discovery · T1680 Local Storage Discovery · T1594 Search
Victim-Owned Websites · T1597 Search Closed Sources · T1681 Search Threat
Vendor Data · T1682 Query Public AI Services · T1584 Compromise Infrastructure
· T1585 Establish Accounts · T1586 Compromise Accounts · T1650 Acquire Access ·
T1683 Generate Content · T1189 Drive-by Compromise · T1205 Traffic Signaling ·
T1211 Exploitation for Stealth · T1678 Delay Execution · T1679 Selective
Exclusion · T1684 Social Engineering · T1687 Exploitation for Defense
Impairment · T1674 Input Injection.

---

## Recommended next step

Author the **Tier A** set first (≈21 focused defensive skills), each following
the catalogue's description contract (what → `Use when` → `Keywords` → negative
trigger) and body conventions (≤500 lines, depth in `references/`). Tier B is
better spent extending the `mitre_attack` lists and scope of existing skills
than minting near-duplicates. Tier C needs no action.

The ATT&CK coverage figures here are produced by diffing skill frontmatter
against the MITRE ATT&CK Enterprise STIX release current at review time
(v17-era, 222 non-deprecated base techniques). Re-run that diff after adding
skills to refresh the numbers.
