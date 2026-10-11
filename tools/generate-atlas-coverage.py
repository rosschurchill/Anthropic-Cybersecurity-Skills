#!/usr/bin/env python3
"""Generate the MITRE ATLAS coverage summary from skill frontmatter.

Reads the `atlas_techniques:` list from every skills/*/SKILL.md and cross-
references it with the official ATLAS technique names in
tools/atlas-technique-names.json (sourced from MITRE ATLAS, see that file's
`_version`). Writes mappings/mitre-atlas/coverage-summary.md.

Like index.json, the coverage summary is GENERATED — never hand-edited. Run
after changing any skill's atlas_techniques frontmatter:

    python tools/generate-atlas-coverage.py

Technique IDs come only from the skills' own frontmatter; names come only from
the committed ATLAS data file. Nothing is invented here — an ID with no name in
the data file is reported as UNKNOWN rather than guessed.
"""
import glob
import json
import os
import sys
from collections import defaultdict

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAMES_FILE = os.path.join(ROOT, "tools", "atlas-technique-names.json")
OUT_FILE = os.path.join(ROOT, "mappings", "mitre-atlas", "coverage-summary.md")


def load_names():
    with open(NAMES_FILE, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("techniques", {}), data.get("_version", "unknown")


def load_frontmatter(path):
    text = open(path, encoding="utf-8").read()
    parts = text.split("---")
    if len(parts) < 3:
        return {}
    try:
        return yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return {}


def main():
    names, version = load_names()
    tech_to_skills = defaultdict(list)
    skills_with = 0

    for path in sorted(glob.glob(os.path.join(ROOT, "skills", "*", "SKILL.md"))):
        fm = load_frontmatter(path)
        techs = fm.get("atlas_techniques")
        if not techs:
            continue
        skills_with += 1
        slug = os.path.basename(os.path.dirname(path))
        for tid in techs:
            tech_to_skills[tid].append(slug)

    lines = []
    lines.append("# MITRE ATLAS Coverage Summary")
    lines.append("")
    lines.append(
        "**GENERATED FILE — do not edit by hand.** "
        "Run `python tools/generate-atlas-coverage.py` to regenerate."
    )
    lines.append("")
    lines.append(
        "Maps this repository's AI/LLM-security skills to "
        "[MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape "
        "for AI Systems) techniques. ATLAS — not ATT&CK or NIST CSF — is the "
        "framework that models adversary behavior against AI systems, so the "
        "catalogue's AI-security skills carry `atlas_techniques:` in their "
        "frontmatter alongside their ATT&CK and CSF mappings."
    )
    lines.append("")
    lines.append(f"- ATLAS data version: **{version}**")
    lines.append(f"- Skills mapped to ATLAS: **{skills_with}**")
    lines.append(f"- Distinct ATLAS techniques covered: **{len(tech_to_skills)}**")
    lines.append("")
    lines.append("## Technique coverage")
    lines.append("")
    lines.append("| ATLAS ID | Technique | Skills |")
    lines.append("|----------|-----------|-------:|")

    def sort_key(item):
        tid, skills = item
        return (-len(skills), tid)

    for tid, skills in sorted(tech_to_skills.items(), key=sort_key):
        name = names.get(tid, "UNKNOWN — not in ATLAS data file")
        lines.append(f"| `{tid}` | {name} | {len(skills)} |")

    lines.append("")
    lines.append("## Skills by technique")
    lines.append("")
    for tid, skills in sorted(tech_to_skills.items(), key=sort_key):
        name = names.get(tid, "UNKNOWN")
        lines.append(f"### `{tid}` — {name}")
        lines.append("")
        for slug in sorted(skills):
            lines.append(f"- `{slug}`")
        lines.append("")

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")

    print(
        f"Wrote {os.path.relpath(OUT_FILE, ROOT)}: "
        f"{skills_with} skills, {len(tech_to_skills)} techniques, "
        f"ATLAS {version}"
    )
    unknown = [t for t in tech_to_skills if t not in names]
    if unknown:
        print("WARNING: technique IDs with no name in the ATLAS data file:")
        for t in sorted(unknown):
            print(f"  {t}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
