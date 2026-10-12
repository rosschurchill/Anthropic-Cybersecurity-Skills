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
| T1578 | Modify Cloud Compute Infrastructure | `detecting-cloud-compute-infrastructure-tampering` | defense-evasion | research |
| T1666 | Modify Cloud Resource Hierarchy | `detecting-cloud-resource-hierarchy-tampering` | defense-evasion | research |
| T1677 | Poisoned Pipeline Execution | `detecting-poisoned-pipeline-execution` | execution | research |
| T1654 | Log Enumeration | `detecting-adversary-log-enumeration` | discovery | research |
| T1020 | Automated Exfiltration | `detecting-automated-data-exfiltration` | exfiltration | research |
| T1563 | Remote Service Session Hijacking | `detecting-remote-service-session-hijacking` | lateral-movement | research |
| T1560 | Archive Collected Data | `detecting-data-staging-and-archiving` | collection | research |
| T1132 | Data Encoding | `detecting-encoded-c2-channels` | command-and-control | research |
| T1104 | Multi-Stage Channels | `detecting-multi-stage-c2-channels` | command-and-control | research |

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
