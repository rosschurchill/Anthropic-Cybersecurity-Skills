# Skill gaps — research working area

Working area for turning the ATT&CK **content gap review**
([`../../mappings/mitre-attack/coverage-gaps.md`](../../mappings/mitre-attack/coverage-gaps.md))
into new skills. **These are research notes, not skills.** Nothing here is
discovered by the validator or the index; a file graduates only when its
content is authored into a real `skills/<slug>/SKILL.md` that passes all five
gates.

## Catalogue coverage at review time

- ATT&CK Enterprise base techniques (non-deprecated): **222**
- Covered by ≥1 skill: **139 (62%)** · uncovered: **83**
- Triaged in the gap review into Tier A (worth a skill), Tier B (fold into
  existing skills), Tier C (atomic primitives, skip).

This working area covers **Tier A** — the 21 real defensive capability gaps.
Tier B/C are not researched here (see the gap review for why).

## Build queue (Tier A → 21 proposed defensive skills)

Each is a **detection / response** skill (blue-team), following the catalogue's
description contract and ≤500-line body convention. Status: `research` =
sub-research file written; `drafted` = SKILL.md authored; `shipped` = merged
and passing gates.

| ATT&CK | Technique | Proposed slug | Tactic | Status |
|--------|-----------|---------------|--------|:------:|
| T1561 | Disk Wipe | `detecting-disk-wipe-and-destruction` | impact | shipped |
| T1495 | Firmware Corruption | `detecting-firmware-corruption-attacks` | impact | shipped |
| T1491 | Defacement | `detecting-website-defacement` | impact | shipped |
| T1498 | Network Denial of Service | `detecting-network-denial-of-service` | impact | shipped |
| T1499 | Endpoint Denial of Service | `detecting-endpoint-denial-of-service` | impact | shipped |
| T1529 | System Shutdown/Reboot | `detecting-malicious-system-shutdown` | impact | shipped |
| T1667 | Email Bombing | `detecting-email-bombing-attacks` | impact | shipped |
| T1111 | MFA Interception | `detecting-mfa-interception-and-bypass` | credential-access | shipped |
| T1689 | Downgrade Attack | `detecting-protocol-downgrade-attacks` | defense-evasion | shipped |
| T1686 | Disable or Modify System Firewall | `detecting-host-firewall-tampering` | defense-evasion | shipped |
| T1690 | Prevent Command History Logging | `detecting-command-history-tampering` | defense-evasion | shipped |
| T1599 | Network Boundary Bridging | `detecting-network-boundary-bridging` | defense-evasion | shipped |
| T1578 | Modify Cloud Compute Infrastructure | `detecting-cloud-compute-infrastructure-tampering` | defense-evasion | shipped |
| T1666 | Modify Cloud Resource Hierarchy | `detecting-cloud-resource-hierarchy-tampering` | defense-evasion | shipped |
| T1677 | Poisoned Pipeline Execution | `detecting-poisoned-pipeline-execution` | execution | shipped |
| T1654 | Log Enumeration | `detecting-adversary-log-enumeration` | discovery | shipped |
| T1020 | Automated Exfiltration | `detecting-automated-data-exfiltration` | exfiltration | shipped |
| T1563 | Remote Service Session Hijacking | `detecting-remote-service-session-hijacking` | lateral-movement | shipped |
| T1560 | Archive Collected Data | `detecting-data-staging-and-archiving` | collection | shipped |
| T1132 | Data Encoding | `detecting-encoded-c2-channels` | command-and-control | shipped |
| T1104 | Multi-Stage Channels | `detecting-multi-stage-c2-channels` | command-and-control | shipped |

## How a research file becomes a skill

Each `<slug>.md` here captures what an author needs to write the skill without
re-researching: the technique, the defensive angle, data sources, concrete
detection logic, real tools, authoritative references, and draft frontmatter
mappings. To graduate one:

1. Create `skills/<slug>/SKILL.md` from the research file — frontmatter
   (name, description with `Use when` + `Keywords` + a negative trigger to the
   nearest existing sibling, domain `cybersecurity`, a valid subdomain, ≥2
   tags, `mitre_attack` from the research) plus the procedure body.
2. Keep the body ≤500 lines; put depth (full scripts, rule sets) in
   `references/`.
3. Scripts must run; no invented API endpoints or CVE numbers; framework IDs
   real and current.
4. Run the five gates (`validate-skill`, `validate-agentskills --strict`,
   `generate-index`, `lint-descriptions`, `detect-collisions`), then flip the
   row above to `drafted` and open a PR.

Authoring the skills is a separate step from this research pass and is not done
automatically.

## v19.2 Tier A build queue (round 2)

Refreshed against ATT&CK Enterprise v19.2 (coverage 163/222 = 73%). Same
research -> draft -> gate loop. Status: `research` = sub-research file written;
`drafted` = SKILL.md authored; `shipped` = merged and passing gates.

| ATT&CK | Technique | Proposed slug | Tactic | Status |
|--------|-----------|---------------|--------|:------:|
| T1651 | Cloud Administration Command | `detecting-cloud-administration-command-abuse` | execution | shipped |
| T1675 | ESXi Administration Command | `detecting-esxi-administration-abuse` | execution | shipped |
| T1072 | Software Deployment Tools | `detecting-software-deployment-tool-abuse` | execution | shipped |
| T1176 | Software Extensions | `detecting-malicious-software-extensions` | persistence | shipped |
| T1671 | Cloud Application Integration | `detecting-malicious-cloud-app-integration` | persistence | shipped |
| T1569 | System Services | `detecting-malicious-system-service-execution` | execution | shipped |
| T1189 | Drive-by Compromise | `detecting-drive-by-compromise` | initial-access | shipped |
| T1115 | Clipboard Data | `detecting-clipboard-data-theft` | collection | shipped |
| T1113/.123/.125 | Screen/Audio/Video Capture | `detecting-screen-audio-video-capture` | collection | shipped |
| T1602 | Data from Configuration Repository | `detecting-network-config-repository-theft` | collection | shipped |
| T1205 | Traffic Signaling | `detecting-traffic-signaling-and-port-knocking` | command-and-control | shipped |
| T1665 | Hide Infrastructure | `detecting-hidden-c2-infrastructure` | command-and-control | shipped |

## Round 3 — ICS/OT Tier A (18 skills, shipped)

Triage: [`../../mappings/ics-attack/coverage-gaps.md`](../../mappings/ics-attack/coverage-gaps.md).
ATT&CK for ICS v19.2. Coverage went 15/79 (19%) → 33/79 (42%).

| ICS ID | Technique | Slug | Status |
|---|---|---|:--:|
| T0843 | Program Download | `detecting-plc-program-download` | shipped |
| T0845 | Program Upload | `detecting-plc-program-upload` | shipped |
| T0889 | Modify Program | `detecting-plc-logic-modification` | shipped |
| T0821 | Modify Controller Tasking | `detecting-controller-tasking-modification` | shipped |
| T0835 | Manipulate I/O Image | `detecting-io-image-manipulation` | shipped |
| T0806 | Brute Force I/O | `detecting-brute-force-io-on-plc` | shipped |
| T0858 | Change Operating Mode | `detecting-plc-operating-mode-change` | shipped |
| T0868 | Detect Operating Mode | `detecting-operating-mode-enumeration` | shipped |
| T0800 | Activate Firmware Update Mode | `detecting-firmware-update-mode-activation` | shipped |
| T1693 | Modify Firmware | `detecting-ot-firmware-modification` | shipped |
| T0838 | Modify Alarm Settings | `detecting-alarm-setting-tampering` | shipped |
| T0878 | Alarm Suppression | `detecting-alarm-suppression` | shipped |
| T0848 | Rogue Master | `detecting-rogue-master-on-ics-network` | shipped |
| T1692 | Unauthorized Message | `detecting-unauthorized-ics-command-messages` | shipped |
| T1691 | Block OT Message | `detecting-blocked-ot-messages` | shipped |
| T1695 | Block Communications | `detecting-ics-communication-blocking` | shipped |
| T0861 | Point & Tag Identification | `detecting-point-and-tag-enumeration` | shipped |
| T0881 | Service Stop | `detecting-ics-service-stop` | shipped |

Legacy IDs T0803/T0804/T0855/T0856 are revoked and fold into T1691/T1692 — the
new IDs are used throughout.

## Round 4 — Mobile Tier A (14 skills, shipped)

Triage: [`../../mappings/mobile-attack/coverage-gaps.md`](../../mappings/mobile-attack/coverage-gaps.md).
ATT&CK for Mobile v19.2. Coverage went 12/77 (16%) → 47/77 (61%).

| Mobile ID | Technique | Slug | Status |
|---|---|---|:--:|
| T1453 | Abuse Accessibility Features | `detecting-android-accessibility-service-abuse` | shipped |
| T1517 | Access Notifications | `detecting-mobile-otp-and-notification-theft` | shipped |
| T1451 | SIM Card Swap | `detecting-sim-swap-attacks` | shipped |
| T1404 | Exploitation for Privilege Escalation | `detecting-mobile-device-rooting-and-jailbreak` | shipped |
| T1617 | Hooking | `detecting-mobile-runtime-hooking-and-instrumentation` | shipped |
| T1632 | Subvert Trust Controls | `detecting-malicious-mobile-configuration-profiles` | shipped |
| T1577 | Compromise Application Executable | `detecting-repackaged-mobile-apps` | shipped |
| T1429 | Audio Capture (+video/screen/location) | `detecting-mobile-surveillanceware` | shipped |
| T1664 | Exploitation for Initial Access | `detecting-mercenary-mobile-spyware-with-mvt` | shipped |
| T1676 | Linked Devices | `detecting-malicious-device-linking` | shipped |
| T1398 | Boot or Logon Initialization Scripts | `detecting-mobile-malware-persistence` | shipped |
| T1663 | Remote Access Software | `detecting-mobile-remote-access-and-proxyware` | shipped |
| T1629 | Impair Defenses | `detecting-mobile-security-control-tampering` | shipped |
| T1582 | SMS Control | `detecting-mobile-sms-and-call-fraud` | shipped |

Detection is routed through MDM/UEM, Mobile Threat Defense, device attestation,
Play Protect, carrier/IAM signals and MVT forensics — stock mobile rarely
exposes host syscall telemetry.

## Round 5 — MITRE ATLAS Tier A (12 skills, shipped)

Triage: [`../../mappings/atlas/coverage-gaps.md`](../../mappings/atlas/coverage-gaps.md).
ATLAS v5.6.0. Honest coverage is 41/101 (41%) after 200 spurious ATLAS tags were
stripped from 78 skills with no AI dimension.

| ATLAS ID | Technique | Slug | Status |
|---|---|---|:--:|
| AML.T0015 | Evade AI Model | `detecting-adversarial-evasion-attacks` | shipped |
| AML.T0029 | Denial of AI Service | `detecting-ai-service-denial-and-cost-harvesting` | shipped |
| AML.T0061 | LLM Prompt Self-Replication | `detecting-llm-prompt-self-replication` | shipped |
| AML.T0060 | Publish Hallucinated Entities | `detecting-package-hallucination-and-slopsquatting` | shipped |
| AML.T0077 | LLM Response Rendering | `detecting-llm-output-rendering-exfiltration` | shipped |
| AML.T0080 | AI Agent Context Poisoning | `detecting-ai-agent-memory-poisoning` | shipped |
| AML.T0081 | Modify AI Agent Configuration | `detecting-ai-agent-configuration-tampering` | shipped |
| AML.T0105 | Escape to Host | `detecting-ai-agent-sandbox-escape` | shipped |
| AML.T0109 | AI Supply Chain Rug Pull | `detecting-ai-model-supply-chain-rug-pull` | shipped |
| AML.T0102 | Generate Malicious Commands | `detecting-malicious-ai-generated-code` | shipped |
| AML.T0092 | Manipulate User LLM Chat History | `detecting-llm-chat-history-manipulation` | shipped |
| AML.T0070 | RAG Poisoning | `detecting-rag-knowledge-base-poisoning` | shipped |

AI-security skills use the `nist_ai_rmf` + `atlas_techniques` frontmatter keys,
not `nist_csf` + `mitre_attack`.

## Post-ship quality review (rounds 3-5)

All 44 skills above passed the five gates on first submission, and a content
review then found **11 HIGH and ~68 MEDIUM** defects the gates cannot see —
mostly detections that silently could never fire (`stats count` with no
zero-fill, inner joins discarding the negative case, SPL `IN` against a lookup
name, SQL `<>` dropping NULLs), plus fabricated identifiers
(`DeviceTvmThreatEvents`, `SetSettingGroupValues`). Fixed in a follow-up pass;
rewritten detectors were executed against positive and negative cases.

**Lesson for future rounds: gates verify structure, not truth.** Budget a
content-accuracy review that checks claims against primary sources, and do not
hedge settled constants — a blanket hedge teaches readers to distrust the
reliable parts.
