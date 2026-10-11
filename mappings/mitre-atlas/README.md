# MITRE ATLAS Mapping

This directory maps the AI/LLM-security skills in this repository to the
[MITRE ATLAS](https://atlas.mitre.org/) framework (Adversarial Threat Landscape
for AI Systems).

## Overview

MITRE ATT&CK and NIST CSF model adversary behavior against conventional IT
systems; neither describes attacks that target machine-learning and
LLM-powered systems — prompt injection, jailbreaks, training-data poisoning,
model exfiltration, RAG poisoning, deepfake generation, and agentic tool
abuse. **MITRE ATLAS is the framework that does.** Skills in this catalogue
that address AI-specific threats therefore carry an `atlas_techniques:` list in
their frontmatter, alongside their `mitre_attack:` and `nist_csf:` mappings,
rather than being forced into an ATT&CK technique that cannot describe them.

This mapping enables:

- **AI threat-informed defense** — prioritize AI-security skills against real
  adversary behavior catalogued by ATLAS.
- **Gap analysis** — see which ATLAS techniques the catalogue covers and which
  it does not.
- **Agent-driven discovery** — AI agents can query skills by ATLAS ID
  (`AML.Txxxx`) for automated AI-security workflows.

## Mapping methodology

ATLAS technique IDs live in each skill's frontmatter, authored per skill. The
[`coverage-summary.md`](coverage-summary.md) in this directory is **generated**
from that frontmatter — it is never hand-edited. It cross-references the IDs
against the official ATLAS technique names committed in
[`tools/atlas-technique-names.json`](../../tools/atlas-technique-names.json)
(sourced from MITRE ATLAS; see that file's `_version`).

Technique IDs come only from the skills' own frontmatter and names come only
from the committed ATLAS data file — nothing in the summary is invented. An ID
with no entry in the data file is reported as `UNKNOWN`, never guessed, in
keeping with the repository rule that framework IDs must be real and current.

## Regenerating

After changing any skill's `atlas_techniques:` frontmatter:

```bash
python tools/generate-atlas-coverage.py
```

This rewrites `coverage-summary.md`. Commit the regenerated file alongside the
frontmatter change, exactly as `index.json` is regenerated and committed.
