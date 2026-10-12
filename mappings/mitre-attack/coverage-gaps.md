# MITRE ATT&CK Coverage Gaps (v19.2)

Companion to [`coverage-summary.md`](coverage-summary.md). A **content gap
review**: it diffs the `mitre_attack:` IDs declared across all skills against the
current MITRE ATT&CK **Enterprise v19.2** technique set, then judges which
uncovered techniques are worth a new skill and which are not.

## Headline numbers (v19.2)

- ATT&CK Enterprise base techniques (current, non-deprecated): **222**
- Covered by at least one skill: **163 (73%)**
- Uncovered base techniques: **59**

Coverage is at the **base-technique** (`Txxxx`) level — a skill mapping a
sub-technique counts its parent as covered. Measured against ATT&CK Enterprise
v19.2; all skill IDs are validated current against v19.2 (Enterprise/ICS/Mobile),
with zero revoked/deprecated IDs. Up from 62% at the start of this review cycle
(after the first 21 Tier A skills and the v19 refresh).

## How to read this

Not every uncovered technique warrants a skill. Many are **atomic
discovery/execution primitives** adversaries run inline (e.g. *System Time
Discovery*), already folded into broader hunting skills. The tiers separate
genuine capability gaps from primitives covered in spirit. IDs and names are from
the authoritative v19.2 STIX; nothing here is invented.

---

## Tier A — real capability gaps, worth a skill (v19.2 build queue)

High-value uncovered techniques where a focused defensive (detection /
response / hardening) skill adds genuine capability.

| ATT&CK | Technique | Proposed slug | Angle |
|--------|-----------|---------------|-------|
| T1651 | Cloud Administration Command | `detecting-cloud-administration-command-abuse` | Detect SSM/RunCommand/Azure RunCommand exec on cloud VMs |
| T1675 | ESXi Administration Command | `detecting-esxi-administration-abuse` | Detect ESXi/vSphere admin abuse (ransomware pre-stage) |
| T1072 | Software Deployment Tools | `detecting-software-deployment-tool-abuse` | Detect SCCM/Intune/Ansible abuse for mass execution |
| T1176 | Software Extensions | `detecting-malicious-software-extensions` | Detect malicious browser/IDE extensions |
| T1671 | Cloud Application Integration | `detecting-malicious-cloud-app-integration` | Detect OAuth app / enterprise-app persistence |
| T1569 | System Services | `detecting-malicious-system-service-execution` | Detect service-based execution (sc/systemctl/launchd) |
| T1189 | Drive-by Compromise | `detecting-drive-by-compromise` | Detect browser drive-by / watering-hole landing |
| T1115 | Clipboard Data | `detecting-clipboard-data-theft` | Detect clipboard theft / crypto-clipper |
| T1113 | Screen Capture (+T1123 Audio, T1125 Video) | `detecting-screen-audio-video-capture` | Detect spyware screen/audio/video capture |
| T1602 | Data from Configuration Repository | `detecting-network-config-repository-theft` | Detect SNMP/network-config repository dumping |
| T1205 | Traffic Signaling | `detecting-traffic-signaling-and-port-knocking` | Detect port-knocking / magic-packet triggers |
| T1665 | Hide Infrastructure | `detecting-hidden-c2-infrastructure` | Detect fast-flux / domain-fronting / infra hiding |

## Tier B — moderate value, fold-in candidates

Legitimate but narrow variants of families the catalogue already covers; better
to extend an existing skill's `mitre_attack` list and scope than mint a
near-duplicate.

- **Proxy / indirect execution (LOLBin family):** T1127 Trusted Developer
  Utilities, T1216 System Script Proxy Execution, T1220 XSL Script Processing,
  T1221 Template Injection, T1202 Indirect Command Execution.
- **Execution surfaces:** T1129 Shared Modules, T1559 Inter-Process
  Communication, T1197 BITS Jobs, T1674 Input Injection.
- **Collection:** T1039 Data from Network Shared Drive.
- **C2 / exfil:** T1092 Communication Through Removable Media, T1030 Data
  Transfer Size Limits.
- **Persistence / misc:** T1653 Power Settings, T1668 Exclusive Control, T1535
  Unused/Unsupported Cloud Regions, T1647 Plist File Modification, T1688 Safe
  Mode Boot, T1615 Group Policy Discovery.
- **Resource development (CTI tracking):** T1584 Compromise Infrastructure,
  T1585 Establish Accounts, T1586 Compromise Accounts, T1650 Acquire Access,
  T1683 Generate Content.

## Tier C — primitives, not worth standalone skills

Atomic discovery/recon and evasion primitives adversaries run inline; detection
belongs inside broader hunting skills. Listed for completeness.

T1007 System Service Discovery · T1010 Application Window Discovery · T1016
System Network Configuration Discovery · T1033 System Owner/User Discovery ·
T1120 Peripheral Device Discovery · T1124 System Time Discovery · T1201 Password
Policy Discovery · T1518 Software Discovery · T1614 System Location Discovery ·
T1622 Debugger Evasion · T1652 Device Driver Discovery · T1673 Virtual Machine
Discovery · T1680 Local Storage Discovery · T1594 Search Victim-Owned Websites ·
T1597 Search Closed Sources · T1681 Search Threat Vendor Data · T1682 Query
Public AI Services · T1211 Exploitation for Stealth · T1687 Exploitation for
Defense Impairment · T1678 Delay Execution · T1679 Selective Exclusion · T1080
Taint Shared Content.

---

## Recommended next step

Author the **Tier A** set (12 skills) via the research → draft → gate loop in
[`../../research/skill-gaps/`](../../research/skill-gaps/). Tier B is better
spent extending existing skills' scope; Tier C needs no action. Re-run the diff
after each batch to refresh these numbers.
