---
name: detecting-package-hallucination-and-slopsquatting
description: 'Detects slopsquatting and AI package hallucination: LLM coding assistants recommending non-existent package names that attackers pre-register on PyPI or npm so developers install malware. Uses coding-assistant and LLM output logs, dependency-resolution and private-registry proxy logs (Artifactory, Nexus, Artifact Registry), registry age and reputation metadata, and CI/CD plus SCA tooling (Socket, OSV-Scanner, pip-audit) to flag AI-suggested dependencies that do not resolve to a known-good pre-existing package or that match typosquat or hallucination shapes, before install. Use when securing an AI-assisted dev or CI workflow against hallucinated or pre-registered package names. Keywords: slopsquatting, package hallucination, AML.T0060, dependency confusion, typosquat, private registry allowlist, dependency pinning, SCA, PyPI, npm, OWASP LLM09. Do not use for reverse-engineering an already-obtained malicious package - use analyzing-supply-chain-malware-artifacts.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm
- slopsquatting
- package-hallucination
- supply-chain
- dependency-pinning
- sca
- private-registry
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0060
---
# Detecting Package Hallucination and Slopsquatting

## Overview

**Slopsquatting** is a supply-chain attack that exploits a reliable failure mode of LLM coding assistants: they confidently recommend **non-existent** packages (or commands, URLs, or dependencies). An attacker who observes which names a model hallucinates can **pre-register** those names on a public registry (PyPI, npm) with malware attached, so any developer who follows the suggestion and runs `pip install` or `npm install` pulls attacker-controlled code. MITRE ATLAS catalogs the attacker side as **AML.T0060 (Publish Hallucinated Entities)**, a resource-development technique.

Two properties make the attack viable: a meaningful fraction of LLM-suggested packages do not exist, and the *same* hallucinated names tend to recur across re-runs — recurrence is what makes pre-registration profitable (slopsquatting; Spracklen et al., "We Have a Package for You!"). The defensive goal is to catch, inside the dev/CI/coding-assistant workflow and **before install**, (a) AI-suggested dependencies that do not resolve to a known-good, pre-existing package, and (b) installs of newly-registered names that match the shape of hallucinated or typo'd popular libraries. This maps to OWASP LLM Top 10 **LLM09 (Misinformation/overreliance)** plus supply-chain guidance. Deep reverse-engineering of a package you have already captured belongs to analyzing-supply-chain-malware-artifacts.

## When to Use

- Securing an AI-assisted development or CI workflow where coding assistants suggest dependencies.
- A `pip install`, `npm install`, `import`, or manifest edit introduces a name you do not recognize.
- Reviewing lockfile diffs that add new or unpinned dependencies.
- Standing up a resolve-before-install gate or a private-registry allowlist.
- Investigating whether a recently added dependency was an AI hallucination pre-registered by an attacker.

## Prerequisites

- Access to coding-assistant / LLM I/O logs (completions that emit install commands, imports, or manifest edits) — Langfuse or assistant audit logs.
- Dependency-resolution and private-registry proxy logs (JFrog Artifactory, Sonatype Nexus, Google Artifact Registry, Azure Artifacts, GitHub Packages, Verdaccio): package name, version, first-seen-in-org, upstream source.
- Ability to query public-registry metadata. The official index endpoints are real, and serve **existence, age and maintainer history**: PyPI `https://pypi.org/pypi/<name>/json` (age = earliest release `upload_time`) and npm `https://registry.npmjs.org/<name>` (age = `time.created`). Neither serves download counts — PyPI's `info.downloads` is deprecated and always returns `-1`, and the npm registry document has no `downloads` key at all. **Download counts come from separate sources:** pypistats.org (or the PyPI download-statistics BigQuery dataset) for PyPI, and `https://api.npmjs.org/downloads/point/last-month/<name>` for npm.
- CI/CD with SCA tooling (Socket, OSV-Scanner, Snyk, Semgrep Supply Chain, Dependabot, pip-audit, npm audit) and lockfile-diff access.
- Python 3.9+ for the gate helpers below.

## Workflow

### 1. Extract AI-suggested package names
From coding-assistant output and manifest/lockfile diffs, pull every proposed dependency name. Keep the provenance: which names came only from assistant output versus a first-party manifest.

### 2. Resolve-before-install gate
For every AI-suggested or newly-added dependency, check it against an org allowlist and registry metadata. Block names that are new, low-reputation, and shaped like a popular library.

```python
import datetime, difflib

def slopsquat_flags(pkg, org_allowlist, popular_libs, age_days, downloads,
                    exists_upstream, provenance, first_suggested_at, created_at,
                    min_age=90, dl_floor=1000, sim_hi=0.85):
    """age_days/created_at come from the index endpoint (npm time.created, PyPI
    earliest release upload_time). `downloads` must be fetched from a download-stats
    source (pypistats / PyPI BigQuery, api.npmjs.org/downloads/point/...) - the index
    endpoints do not serve it. provenance: "assistant_only" | "manifest" | ...;
    first_suggested_at: when the assistant first emitted this name.
    Tune min_age/dl_floor/sim_hi per ecosystem and org risk appetite."""
    if not exists_upstream:
        return {"verdict": "BLOCK", "reason": "name does not resolve upstream (hallucinated)"}
    if pkg in org_allowlist:
        return {"verdict": "ALLOW", "reason": "vetted allowlist entry"}
    # Pre-registered hallucination: the assistant invented the name, and the upstream
    # package was created at or after that suggestion. Usually NOT typosquat-shaped,
    # so it must be caught here rather than falling through to REVIEW.
    if (provenance == "assistant_only" and first_suggested_at and created_at
            and created_at >= first_suggested_at):
        return {"verdict": "BLOCK",
                "reason": "assistant-invented name registered upstream at/after first suggestion"}
    typo_shape = max((difflib.SequenceMatcher(None, pkg, p).ratio() for p in popular_libs),
                     default=0.0)
    young_and_obscure = age_days < min_age and downloads < dl_floor
    if young_and_obscure and typo_shape > sim_hi and typo_shape < 1.0:
        return {"verdict": "BLOCK", "reason": "young, low-download, typosquat-shaped vs popular lib"}
    if young_and_obscure:
        return {"verdict": "REVIEW", "reason": "new low-reputation dependency"}
    return {"verdict": "ALLOW", "reason": "established package"}
```

### 3. Hallucination corroboration
Flag names that appear only in assistant output and in no first-party dependency manifest nor the upstream index. A name the assistant invented that *now resolves* to a recently created, unrelated package is the high-signal slopsquat case: the name did not exist before the model suggested it, yet an install candidate appeared.

### 4. New-dependency malware scan
Route every first-seen dependency through SCA / malware scanning for install-script execution, typosquat heuristics, and known-bad indicators before it enters a lockfile or image (Socket, OSV-Scanner, Snyk, Semgrep Supply Chain, pip-audit/npm audit).

### 5. Enforce in CI and at resolve time
Wire the gate into a pre-commit or resolver hook and a CI job so a hallucinated or low-reputation name fails the build rather than reaching a developer's machine or a production image.

### 6. Report and contain
On a hit, remove the dependency, scan for install-time execution, and rotate any secrets that may have been exposed (see Response).

## Key Concepts

- **Slopsquatting vs typosquatting.** Typosquatting banks on a human mistyping a name; slopsquatting banks on an LLM *hallucinating* a plausible-but-nonexistent name that recurs predictably, which the attacker pre-registers.
- **Recurrence.** Hallucinated names are not random — the same model tends to invent the same names, making pre-registration a repeatable payoff.
- **Org-first-seen.** A name never before seen in your org is the primary trigger; combine with upstream age and download reputation to cut false positives on legitimate new internal packages.
- **Pre-install vs post-capture.** This skill is detection in the coding/CI workflow before install; analyzing a captured malicious package is the sibling skill.
- **Dependency confusion overlap.** A private name shadowed by a public one is a related supply-chain risk; the allowlist and scoped/internal resolution mitigate both.

## Tools & Systems

| Tool / system | Role |
|---------------|------|
| JFrog Artifactory, Sonatype Nexus (Firewall), Google Artifact Registry, Azure Artifacts, Verdaccio | Private-registry allowlist, resolve/install logs, first-seen tracking |
| Socket, OSV-Scanner, Snyk, Semgrep Supply Chain, Dependabot | SCA and malicious-package detection on new dependencies |
| pip-audit, npm audit | Ecosystem vulnerability/advisory checks |
| Sigstore / SLSA provenance | Verify package provenance and integrity |
| Langfuse / assistant audit logs | Capture AI-suggested package names for resolution |
| PyPI and npm registry metadata APIs (`pypi.org/pypi/<name>/json`, `registry.npmjs.org/<name>`) | Package existence, age, maintainer history (no download counts) |
| pypistats.org or the PyPI BigQuery download dataset; `api.npmjs.org/downloads/point/last-month/<name>` | Download counts for the reputation floor |

## Detection Queries

```bash
# 1. Existence and age (index endpoints). 404 => does not exist (likely hallucinated).
#    Treat a brand-new resolving name as suspect.
# PyPI resolves PEP 503 NORMALISED names (case, '-' vs '_' vs '.' all collapse), so a 200
# is not proof the name existed as suggested: compare info.name to the requested string.
PY=$(curl -fsS "https://pypi.org/pypi/${PKG}/json") \
  && echo "pypi: exists; name=$(jq -r .info.name <<<"$PY"); created=$(jq -r '[.releases[][].upload_time] | sort | first' <<<"$PY")" \
  || echo "pypi: MISSING"
[ -n "$PY" ] && [ "$(jq -r .info.name <<<"$PY")" != "${PKG}" ] \
  && echo "pypi: NORMALISATION-ONLY match - did not exist as suggested"
# npm equivalent (age from time.created):
curl -fsS "https://registry.npmjs.org/${PKG}" \
  | jq -r '"npm: exists; created=" + .time.created' || echo "npm: MISSING"

# 2. Download counts come from SEPARATE endpoints - the index documents above carry none
#    (PyPI info.downloads is deprecated and always -1; npm has no downloads key).
curl -fsS "https://api.npmjs.org/downloads/point/last-month/${PKG}" | jq -r '.downloads'
# PyPI: query pypistats.org or the PyPI download-statistics BigQuery dataset (verify the
# current request path for whichever you adopt).
```

```kusto
// First-seen dependencies resolved through the registry proxy in the last 24h
RegistryProxyLogs
| where Timestamp > ago(24h) and FirstSeenInOrg == true
// Downloads must be enriched from a download-stats source (pypistats / PyPI BigQuery,
// api.npmjs.org/downloads) - the registry index documents carry no download count.
| project Timestamp, Actor, Package, Version, UpstreamSource, UpstreamAgeDays, Downloads
| where UpstreamAgeDays < 90 or Downloads < 1000
```

```kusto
// Lockfile diffs adding new/unpinned deps that trace back to assistant output
CiPipelineEvents
| where Event == "lockfile_diff" and ChangeType == "add"
| join kind=inner (AssistantLogs | where Action == "suggest_dependency") on Package
| project Timestamp, Repo, Package, Pinned, SuggestedByAssistant=true
```

## Common Scenarios

- **Hallucinated import pre-registered:** an assistant suggests `import <plausible-name>`; the name did not exist last week but now resolves to a 3-day-old package with a postinstall script. Resolve-before-install blocks it.
- **Typosquat-shaped suggestion:** the assistant recommends a name one character off a popular library; name-similarity plus young/low-download metadata trips the gate.
- **Unpinned CI add:** a lockfile diff adds an unpinned dependency sourced from assistant output; the CI gate fails pending review and SCA scan.

## Output Format

Report per finding:
- Package name, ecosystem (PyPI/npm), version, and whether it resolves upstream.
- Provenance: assistant-suggested vs manifest, org-first-seen flag.
- Registry metadata: creation date/age, download count, maintainer history, similarity to a named popular library.
- Gate verdict (ALLOW / REVIEW / BLOCK) and SCA/malware-scan result.
- ATLAS mapping: AML.T0060 (Publish Hallucinated Entities); OWASP LLM09.

## Response

- Enforce a private-registry allowlist (resolve only vetted, pre-existing packages; block direct public-index pulls) and dependency pinning with hashes (lockfiles, `pip install --require-hashes`, `npm ci`).
- Add a CI gate that fails on new dependencies below an age/reputation floor or matching typosquat heuristics, and quarantine plus SCA-scan every first-seen package.
- Instruct coding assistants and developers to verify each AI-suggested package against the official index before install.
- On a confirmed hit: remove the dependency, scan for install-time code execution, rotate any exposed secrets, and hand the captured artifact to analyzing-supply-chain-malware-artifacts for deep analysis.
