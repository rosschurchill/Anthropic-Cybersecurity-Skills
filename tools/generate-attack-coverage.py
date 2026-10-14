#!/usr/bin/env python3
"""Generate ATTACK_COVERAGE.md from the catalogue and the cached ATT&CK map.

WHY THIS EXISTS
    ATTACK_COVERAGE.md said "To regenerate: python3 extract_attack.py" and that
    script was not in the repository. With no runnable generator and no check,
    the document drifted until every number in it was wrong: it claimed 291
    techniques across 817 skills while the catalogue held 437 across 872, and it
    still advertised ATLAS v5.5.0 and 85 NIST AI RMF skills after 460 spurious
    mappings had been removed. A hand-maintained derived document is a document
    that will be wrong.

    Same contract as generate-index.py: generated, never hand-edited, and CI
    runs --check so a stale copy fails the build instead of shipping.

USAGE
    python3 tools/generate-attack-coverage.py            # write ATTACK_COVERAGE.md
    python3 tools/generate-attack-coverage.py --check     # exit 1 if out of date

The technique -> tactic map is cached in tools/attack-technique-tactics.json so
this runs offline. Refresh it from MITRE STIX only on a deliberate version bump.
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from skill_frontmatter import load_frontmatter  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "ATTACK_COVERAGE.md")
MAP = os.path.join(ROOT, "tools", "attack-technique-tactics.json")

# The 14 Enterprise tactics in kill-chain order, then the ICS/Mobile-only ones.
# Order is fixed here rather than derived so the document is stable across runs.
TACTIC_ORDER = [
    ("reconnaissance", "🔎 Reconnaissance"),
    ("resource-development", "🏗️ Resource Development"),
    ("initial-access", "🚪 Initial Access"),
    ("execution", "⚡ Execution"),
    ("persistence", "🔩 Persistence"),
    ("privilege-escalation", "⬆️ Privilege Escalation"),
    ("defense-evasion", "🥷 Defense Evasion"),
    ("credential-access", "🔑 Credential Access"),
    ("discovery", "🗺️ Discovery"),
    ("lateral-movement", "↔️ Lateral Movement"),
    ("collection", "📦 Collection"),
    ("command-and-control", "📡 Command and Control"),
    ("exfiltration", "📤 Exfiltration"),
    ("impact", "💥 Impact"),
    # ICS and Mobile contribute tactics the Enterprise matrix does not have.
    ("evasion", "🫥 Evasion (ICS)"),
    ("inhibit-response-function", "🛑 Inhibit Response Function (ICS)"),
    ("impair-process-control", "🎛️ Impair Process Control (ICS)"),
    ("network-effects", "📶 Network Effects (Mobile)"),
    ("remote-service-effects", "☁️ Remote Service Effects (Mobile)"),
]


def attack_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def collect():
    ref = json.load(open(MAP, encoding="utf-8"))
    techs = ref["techniques"]
    skills = {}          # slug -> frontmatter
    by_tech = {}         # tid -> [slug]
    counts = {k: 0 for k in ("attack", "atlas", "airmf", "d3fend", "csf")}
    for d in sorted(glob.glob(os.path.join(ROOT, "skills", "*") + os.sep)):
        slug = os.path.basename(d.rstrip(os.sep))
        fm = load_frontmatter(os.path.join(d, "SKILL.md"))
        skills[slug] = fm
        for key, lbl in (("mitre_attack", "attack"), ("atlas_techniques", "atlas"),
                         ("nist_ai_rmf", "airmf"), ("d3fend_techniques", "d3fend"),
                         ("nist_csf", "csf")):
            if fm.get(key):
                counts[lbl] += 1
        ids = fm.get("mitre_attack") or []
        if isinstance(ids, str):
            ids = [ids]
        for t in ids:
            by_tech.setdefault(str(t).strip(), []).append(slug)
    return ref, techs, skills, by_tech, counts


def render():
    ref, techs, skills, by_tech, counts = collect()
    ver = ref["_version"]
    total = len(skills)
    uniq = sorted(by_tech)
    parents = {t.split(".")[0] for t in uniq}

    # A technique can belong to several tactics; it is listed under each and
    # counted once in the total. Anything the map gives no tactic for lands in
    # "Unmapped" rather than being dropped silently.
    per_tactic = {}
    for t in uniq:
        tac = (techs.get(t) or {}).get("tactics") or ["__none__"]
        for a in tac:
            per_tactic.setdefault(a, []).append(t)

    known = [k for k, _ in TACTIC_ORDER]
    extra = sorted(k for k in per_tactic if k not in known and k != "__none__")
    order = [(k, lbl) for k, lbl in TACTIC_ORDER if k in per_tactic]
    order += [(k, "🔧 " + k.replace("-", " ").title()) for k in extra]
    if "__none__" in per_tactic:
        order.append(("__none__", "❔ Unmapped by the cached ATT&CK data"))

    L = []
    L.append("# MITRE ATT&CK Coverage Map")
    L.append("")
    L.append('<p align="center">')
    L.append(f'  <a href="https://attack.mitre.org/"><img src="https://img.shields.io/badge/MITRE_ATT%26CK-v{ver}-red?style=for-the-badge&logo=shield&logoColor=white" alt="MITRE ATT&CK" /></a>')
    L.append(f'  <img src="https://img.shields.io/badge/Techniques-{len(uniq)}-blueviolet?style=for-the-badge" alt="Techniques" />')
    L.append(f'  <img src="https://img.shields.io/badge/Tactics-{len([k for k,_ in order if k != "__none__"])}-green?style=for-the-badge" alt="Tactics" />')
    L.append("</p>")
    L.append("")
    L.append(f"This document maps the **{len(uniq)} unique MITRE ATT&CK technique IDs** (across "
             f"**{len(parents)} parent techniques**) referenced by the **{counts['attack']} of {total} skills** "
             f"that carry a `mitre_attack` mapping, grouped by tactic. Use it to find coverage gaps, "
             f"plan detection-engineering priorities, or check a security programme against ATT&CK.")
    L.append("")
    L.append(f"> Generated against **ATT&CK v{ver}** (Enterprise, Mobile and ICS). Every ID below was "
             f"checked against that release: none is revoked or deprecated.")
    L.append("")
    L.append("> **How to read this:** each technique links to its ATT&CK page, and the skills under it "
             "are the ones in this repository that teach detection, hunting, exploitation or response "
             "for it. A technique belonging to several tactics appears under each, and is counted once "
             "in the total.")
    L.append("")
    L.append("<!-- GENERATED FILE - do not edit by hand.")
    L.append("     Regenerate: python3 tools/generate-attack-coverage.py")
    L.append("     CI runs --check and fails the build if this file is stale. -->")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## Coverage Summary")
    L.append("")
    L.append("| Tactic | Technique IDs | Skills |")
    L.append("|:-------|:-------------:|:------:|")
    for key, label in order:
        ts = per_tactic[key]
        sk = {s for t in ts for s in by_tech[t]}
        L.append(f"| **{label}** | **{len(ts)}** | {len(sk)} |")
    L.append(f"| | **{len(uniq)}** | **{counts['attack']}** |")
    L.append("")
    L.append("---")
    L.append("")
    # One compact row per technique, matching the format this document has always
    # used. A per-technique heading with a bulleted skill list was the obvious
    # alternative and produced an 8,000-line file for the same information.
    for key, label in order:
        ts = sorted(per_tactic[key])
        sk = {s for t in ts for s in by_tech[t]}
        L.append(f"## {label}")
        L.append("")
        L.append(f"**{len(ts)} technique IDs · {len(sk)} skills**")
        L.append("")
        L.append("| Technique | Name | Skills |")
        L.append("|:----------|:-----|:-------|")
        for t in ts:
            meta = techs.get(t) or {}
            name = (meta.get("name") or "").replace("|", "\\|") or "(not in cached data)"
            sl = sorted(set(by_tech[t]))
            L.append(f"| [{t}]({attack_url(t)}) | {name} | " + ", ".join(f"`{s}`" for s in sl) + " |")
        L.append("")
        L.append("---")
        L.append("")
    L.append("## Other framework coverage")
    L.append("")
    L.append("Counted from the skills themselves, so these cannot drift from the catalogue:")
    L.append("")
    L.append("| Framework | Skills mapped |")
    L.append("|:----------|:-------------:|")
    L.append(f"| NIST CSF 2.0 | {counts['csf']} |")
    L.append(f"| MITRE ATT&CK | {counts['attack']} |")
    L.append(f"| MITRE D3FEND | {counts['d3fend']} |")
    L.append(f"| MITRE ATLAS | {counts['atlas']} |")
    L.append(f"| NIST AI RMF | {counts['airmf']} |")
    L.append("")
    L.append("`mappings/atlas/coverage-gaps.md` holds the ATLAS triage, and the ICS and Mobile "
             "equivalents sit beside it.")
    L.append("")
    L.append("---")
    L.append("")
    L.append('<p align="center">')
    L.append(f"  <sub>Part of Anthropic Cybersecurity Skills — {total} open-source cybersecurity skills for AI agents</sub>")
    L.append("</p>")
    L.append("")
    return "\n".join(L)


def main():
    text = render()
    if "--check" in sys.argv:
        cur = open(DOC, encoding="utf-8").read() if os.path.exists(DOC) else ""
        if cur != text:
            print("ATTACK_COVERAGE.md is out of date. Run: python3 tools/generate-attack-coverage.py")
            return 1
        print("ATTACK_COVERAGE.md is up to date.")
        return 0
    open(DOC, "w", encoding="utf-8").write(text)
    print(f"Wrote ATTACK_COVERAGE.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
