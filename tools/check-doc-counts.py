#!/usr/bin/env python3
"""Fail the build when a document claims a skill count the catalogue does not have.

WHY THIS EXISTS
    The catalogue grew from 817 to 872 skills. The number was corrected in
    README.md and left stale in README.fr.md (8 places), SCOPE.md, CITATION.cff,
    ATTACK_COVERAGE.md, mappings/README.md and .github/copilot-instructions.md.
    The repository therefore advertised 817 skills while shipping 872, which
    reads exactly like "the new skills were never merged" - which is how it was
    eventually reported. Counting is not the hard part; noticing is.

HOW IT WORKS - and why it is boring on purpose
    It looks only at a number DIRECTLY against the word it counts: "872 skills",
    "872 compétences", "skills-872" in a badge. URLs are stripped first, because
    the owner name in this repository's own links is "mukul975" and a 40-character
    proximity window duly reported "975 skills" 30 times. A gate with false
    positives gets switched off, so this one stays literal.

    Numbers that legitimately are not the total live in SUBSETS with a reason.
    Add to it rather than loosening the match.

USAGE
    python3 tools/check-doc-counts.py          # exit 1 on any mismatch
    python3 tools/check-doc-counts.py --list    # show every count it checked
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ATTACK_COVERAGE.md is deliberately absent: it is generated, and every number
# in it - including per-tactic subtotals like "20 technique IDs / 104 skills" -
# is owned and verified by generate-attack-coverage.py --check. A second checker
# re-deriving those subtotals would be redundant and would break on every tactic
# whose coverage shifts.
FILES = [
    "README.md", "README.fr.md", "SCOPE.md", "CITATION.cff", "CONTRIBUTING.md",
    "AGENTS.md", "mappings/README.md", "tools/README.md",
    ".github/copilot-instructions.md",
]

# Numbers next to "skills" that are deliberately NOT the catalogue total.
# Keep each one justified; an unexplained entry here is a silenced bug.
SUBSETS = {
    846: "skills carrying a mitre_attack mapping",
    795: "skills carrying references/ and scripts/",
    794: "skills carrying a LICENSE",
    788: "skills carrying references/api-reference.md",
    786: "skills carrying scripts/agent.py",
    283: "skills carrying assets/",
    734: "the v1.0.0 release count, a historical fact",
}
# 817 (the pre-872 total) and 604 are deliberately NOT here. Listing them looked
# harmless - they only ever appear in historical sentences - but it tolerated the
# exact number that drifted, in every file, and a sabotage test proved the gate
# then passed with "817 of them today" in SCOPE.md. Historical sentences are
# already exempt via ALLOW, which is line-scoped; a SUBSETS entry is not.

# Sentences about the PAST. Correcting these would make a true note false.
ALLOW = ["previously truncated", "that bug shipped", "used to be justified by"]

URL = re.compile(r"https?://\S+|\]\([^)]*\)|src=\"[^\"]*\"|srcset=\"[^\"]*\"")

# Matched on the RAW line, before URLs are stripped. The shields.io count badge
# lives inside a URL, so stripping first hid it - and the badge is exactly where
# the French README sat stale at 817. A sabotage test caught this.
RAW_PATS = [re.compile(r"badge/skills-(\d{3})\b", re.I)]

# A count must touch the noun: "872 skills", "872 compétences", "skills-872".
PATS = [
    # Up to 3 plain words may sit between the number and the noun, so
    # "817 cybersecurity skills" and "872 production-grade skills" are caught -
    # strict adjacency missed both, which a sabotage test on CITATION.cff proved.
    # Only [A-Za-z-] words qualify, so a path or a version cannot bridge the gap.
    re.compile(r"\*{0,2}(\d{3})\*{0,2}(?:\s+[A-Za-z][A-Za-z-]*){0,3}\s+(?:skills?|compétences?|procedures)\b", re.I),
    re.compile(r"(?:skills?|compétences?)\s*[-|]\s*(\d{3})\b", re.I),
    # A table cell: "| Total skills scanned | 872 |" in mappings/README.md.
    re.compile(r"(?:skills?|compétences?)[^|\n]{0,24}\|\s*\*{0,2}(\d{3})\b", re.I),
    re.compile(r"\bof the\s+\*{0,2}(\d{3})\*{0,2}\s+(?:current\s+)?names\b", re.I),
    re.compile(r"\bof the\s+\*{0,2}(\d{3})\*{0,2}\s+skills\b", re.I),
    re.compile(r"(\d{3})\s+of them today", re.I),
]


def real_total():
    return len([d for d in glob.glob(os.path.join(ROOT, "skills", "*") + os.sep)
                if os.path.exists(os.path.join(d, "SKILL.md"))])


def main():
    total = real_total()
    show = "--list" in sys.argv
    bad, checked, seen_files = [], 0, 0
    for rel in FILES:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            continue
        seen_files += 1
        for i, raw in enumerate(open(p, encoding="utf-8"), 1):
            if any(a in raw for a in ALLOW):
                continue
            stripped = URL.sub(" ", raw)
            for pat, target in [(x, raw) for x in RAW_PATS] + [(x, stripped) for x in PATS]:
                for m in pat.finditer(target):
                    n = int(m.group(1))
                    checked += 1
                    if n == total:
                        if show:
                            print(f"ok  {rel}:{i} -> {n}")
                    elif n in SUBSETS:
                        if show:
                            print(f"sub {rel}:{i} -> {n} ({SUBSETS[n]})")
                    else:
                        bad.append((rel, i, n, raw.strip()[:110]))
    if bad:
        print(f"The catalogue holds {total} skills. These say otherwise:\n")
        for rel, i, n, txt in bad:
            print(f"  {rel}:{i}  says {n}\n      {txt}")
        print("\nFix the number. If it is a real subset, add it to SUBSETS with a"
              " reason; if the sentence is about the past, add a marker to ALLOW.")
        return 1
    print(f"OK: {checked} skill-count mentions in {seen_files} documents are consistent with {total}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
