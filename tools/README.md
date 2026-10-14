# Skill Validation Tools

## validate-skill.py

Validate SKILL.md metadata before submitting a PR.

### Usage

```bash
# Validate a single skill
python tools/validate-skill.py skills/my-new-skill/

# Validate all skills
python tools/validate-skill.py --all
```

### What it checks

- SKILL.md exists in the skill directory
- Valid YAML frontmatter (between `---` markers)
- Required fields present: `name`, `description`, `domain`, `subdomain`, `tags`, `version`, `author`, `license`
- Name is kebab-case, 1–64 characters
- Description is at least 50 characters (agentskills.io caps it at 1024; `tools/validate-agentskills.py` enforces that)
- Domain is `cybersecurity`
- Subdomain is from the allowed list
- Tags is a list with at least 2 items

### Generated documents, and the gates that keep them honest

Two documents are derived from the catalogue. Both are generated, neither is
hand-edited, and CI checks both:

| Tool | Owns | Check |
|---|---|---|
| `generate-attack-coverage.py` | `ATTACK_COVERAGE.md` | `--check` fails if stale |
| `check-doc-counts.py` | the skill total wherever it is quoted | fails on any mismatch |

`generate-attack-coverage.py` reads `attack-technique-tactics.json`, a cached
technique-to-tactic map extracted from the MITRE ATT&CK STIX bundles, so it runs
offline. Refresh that cache only on a deliberate version bump — the catalogue is
pinned to **v19.2** and every technique ID in it was verified against that
release. v20.0 exists upstream; moving to it means revalidating all 437 IDs for
revocations, not editing a badge.

Both exist because the alternative was tried. `ATTACK_COVERAGE.md` told readers
to regenerate it with `python3 extract_attack.py`, a script that was never in
this repository, and it drifted until every number in it was wrong: 291
techniques across a claimed 817 when the catalogue held 437 across 872, ATLAS
v5.5.0 after v5.6.0 landed, and 85 NIST AI RMF skills after 460 spurious
mappings had been stripped. The total was likewise corrected in `README.md` and
left at 817 in `README.fr.md`, `SCOPE.md`, `CITATION.cff`, `mappings/README.md`
and `.github/copilot-instructions.md`, so the repository advertised a total of 817
while shipping 872 — which reads as "the new skills were never merged".

`check-doc-counts.py` matches a number only where it touches the word it counts,
and strips URLs first: this repository's own links contain the owner name
`mukul975`, and a loose proximity window read that owner name as a count thirty times.
Legitimate subsets (846 ATT&CK-mapped, 795 with `references/`, 734 at v1.0.0)
are declared in `SUBSETS` with a reason; sentences about the past are exempted
by line in `ALLOW`. Do not add the previous total to `SUBSETS` — that was tried,
and it silenced the one number that had actually drifted.

### Requirements

Python 3.8+ and PyYAML (`pip install pyyaml`).

All frontmatter is parsed by `skill_frontmatter.py`, the single PyYAML-backed loader. It replaced three hand-rolled regex parsers that silently truncated multi-line descriptions to their first line — that bug shipped 604 of 817 descriptions broken in `index.json`. Do not reintroduce regex frontmatter parsing; CI fails the build if it detects any.
