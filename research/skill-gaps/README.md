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
| T1602 | Data from Configuration Repository | `detecting-network-config-repository-theft` | collection | research |
| T1205 | Traffic Signaling | `detecting-traffic-signaling-and-port-knocking` | command-and-control | research |
| T1665 | Hide Infrastructure | `detecting-hidden-c2-infrastructure` | command-and-control | research |
