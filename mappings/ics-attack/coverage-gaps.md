# MITRE ATT&CK for ICS — Coverage Gaps

Content gap review for the **ICS/OT** matrix (MITRE ATT&CK for ICS v19.2).
Diffs skill `mitre_attack:` IDs against the ICS technique set.

## Headline (current)
- ICS base techniques: **79** · covered **33** · **uncovered 46** — **42%**.

All 18 Tier-A skills below are **shipped and merged**; coverage rose from 15/79
(19%) at review time to 33/79 (42%). The remaining 46 are Tier B/C by the triage
rule below, not a backlog.

Triage follows the catalogue rule: build a skill only for a concretely
*detectable adversary behavior*. ICS **impact outcomes** (Loss of View/Control,
Damage to Property…) are consequences, not detection targets; generic techniques
with an existing Enterprise detection skill are **fold-in**.

## Tier A — OT-specific, detectable, worth a skill (all shipped)

| ICS ID | Technique | Proposed slug |
|--------|-----------|---------------|
| T0843 | Program Download | `detecting-plc-program-download` |
| T0845 | Program Upload | `detecting-plc-program-upload` |
| T0889 | Modify Program | `detecting-plc-logic-modification` |
| T0821 | Modify Controller Tasking | `detecting-controller-tasking-modification` |
| T0835 | Manipulate I/O Image | `detecting-io-image-manipulation` |
| T0806 | Brute Force I/O | `detecting-brute-force-io-on-plc` |
| T0858 | Change Operating Mode | `detecting-plc-operating-mode-change` |
| T0868 | Detect Operating Mode | `detecting-operating-mode-enumeration` |
| T0800 | Activate Firmware Update Mode | `detecting-firmware-update-mode-activation` |
| T1693 | Modify Firmware | `detecting-ot-firmware-modification` |
| T0838 | Modify Alarm Settings | `detecting-alarm-setting-tampering` |
| T0878 | Alarm Suppression | `detecting-alarm-suppression` |
| T0848 | Rogue Master | `detecting-rogue-master-on-ics-network` |
| T1692 | Unauthorized Message | `detecting-unauthorized-ics-command-messages` |
| T1691 | Block Operational Technology Message | `detecting-blocked-ot-messages` |
| T1695 | Block Communications | `detecting-ics-communication-blocking` |
| T0861 | Point & Tag Identification | `detecting-point-and-tag-enumeration` |
| T0881 | Service Stop | `detecting-ics-service-stop` |

## Tier B — fold into existing / Enterprise-overlap (note ICS context, don't duplicate)
T0817 Drive-by Compromise · T0819 Exploit Public-Facing Application · T0820
Exploitation for Evasion · T0866 Exploitation of Remote Services · T0890
Exploitation for Privilege Escalation · T0822 External Remote Services · T0886
Remote Services · T0834 Native API · T0871 Execution through API · T0894 System
Binary Proxy Execution · T0863 User Execution · T0865 Spearphishing Attachment ·
T0862 Supply Chain Compromise · T0847 Replication Through Removable Media · T0849
Masquerading · T0851 Rootkit · T0874 Hooking · T0872 Indicator Removal on Host ·
T0842 Network Sniffing · T0887 Wireless Sniffing · T0860 Wireless Compromise ·
T0840 Network Connection Enumeration · T0846 Remote System Discovery (covered) ·
T0852 Screen Capture · T0802 Automated Collection · T0893 Data from Local System ·
T0823 Graphical User Interface · T0869 Standard Application Layer Protocol · T0885
Commonly Used Port · T0884 Connection Proxy · T0883 Internet Accessible Device ·
T0864 Transient Cyber Asset · T0873 Project File Infection · T0895 Autorun Image ·
T0892 Change Credential · T0694 Insecure Credentials (T1694).

## Tier C — impact outcomes / not detection-skill-worthy (consequences, covered by their cause)
T0813 Denial of Control · T0815 Denial of View · T0826 Loss of Availability ·
T0827 Loss of Control · T0828 Loss of Productivity and Revenue · T0829 Loss of
View · T0837 Loss of Protection · T0880 Loss of Safety · T0879 Damage to Property.

## Build plan
Author the 18 Tier-A OT detection skills via the research → draft → gate loop.
Tier B is covered by existing Enterprise detection skills (same telemetry, note
ICS context) — extend their mappings rather than duplicate. Tier C needs no
skill.
