---
name: detecting-ai-model-supply-chain-rug-pull
description: 'Detects AI supply-chain rug pulls and poisoned published models or datasets from the consumer and registry side: a trusted Hugging Face or package-registry artifact that turns malicious in a later version, fake reputation or download and star inflation used to clear new-artifact scrutiny, and unexplained executable surface (pickle, Keras Lambda, trust_remote_code custom code) appearing between revisions. Uses hub version history, download and star velocity, model-scan verdicts from picklescan, ModelScan and Fickling, weight-hash pinning, and model-registry promotion logs. Use when vetting or monitoring third-party models, datasets, or model-loader packages you depend on, or when a pinned artifact changes unexpectedly. Keywords: rug pull, model supply chain, Hugging Face provenance, picklescan, ModelScan, safetensors, reputation inflation, trust_remote_code, AML.T0109, OWASP LLM03. Do not use for detecting the poisoning effect on an in-house trained model - use detecting-data-and-model-poisoning.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- ml-supply-chain
- model-provenance
- rug-pull
- hugging-face
- picklescan
- modelscan
- safetensors
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0109
- AML.T0111
- AML.T0058
- AML.T0019
---
# Detecting AI Model Supply Chain Rug Pulls

## When to Use

- You depend on third-party models, datasets, or model-loader packages pulled from Hugging Face Hub, npm, or PyPI, and need to vet them before adoption or continuously monitor them afterward.
- A pinned artifact changed unexpectedly: the resolved hash no longer matches the recorded one, or a new revision landed on a tag you track.
- A previously benign, widely adopted artifact shipped a later version (the classic rug-pull shape: benign release, trust-building, malicious update).
- You are triaging an artifact whose reputation (downloads, stars, likes) looks inconsistent with its real-world references or citations.
- You run a model registry and want a promotion gate that re-scans and diffs every new revision.

This is a hub/registry/provenance skill. It watches what you pull in, not the downstream poisoning effect on an in-house trained model. For activation-clustering, spectral-signature, and trigger-reconstruction analysis of a model you trained, use detecting-data-and-model-poisoning.

## Prerequisites

- Python 3.9+ and access to the registries you consume (Hugging Face Hub token for private repos, internal npm/PyPI mirror logs).
- Read access to your internal model-registry promotion and approval logs (MLflow, SageMaker Model Registry, Vertex Model Registry).
- Model-scanning tooling installed:

```bash
pip install picklescan modelscan huggingface_hub safetensors
# Fickling (Trail of Bits) for pickle opcode disassembly
pip install fickling
```

- A record of last-known-good commit SHAs / content hashes for every pinned artifact.

## Workflow

1. **Inventory and pin.** Enumerate every external model, dataset, and loader package you depend on. Record the exact commit SHA (not a mutable tag like `main`) and a content hash for each. An artifact pinned only by tag can be swapped in place silently.
2. **Diff the file manifest on every new revision.** Pull the commit history and compare the file list and hashes between the last-reviewed revision and the new one. The core rug-pull signal is a trusted artifact that gains unexplained executable surface.
3. **Re-scan the new revision.** Run picklescan / ModelScan / Fickling over all weight and config files. Flag any pickle-based artifact (`.bin`, `.pt`, `.ckpt`, `.pkl`) added to a repo that was previously safetensors-only, any Keras Lambda layer, and any newly added `.py` file at all — the custom-code convention is `modeling_<arch>.py`, `configuration_<arch>.py`, `tokenization_<arch>.py` plus arbitrarily named helpers they import, so treat every added `.py` as `trust_remote_code=True` surface.
4. **Check reputation plausibility.** Compare download/star/like velocity against the artifact cohort and against inbound references. A spike decoupled from citations, stars from freshly created accounts in a narrow window, or high adoption on a brand-new maintainer is a reputation-inflation signal.
5. **Verify provenance.** Confirm signature/attestation where available, flag recent maintainer or owner-email changes, and detect re-uploads under a renamed repo that typosquats a trusted name.
6. **Gate `trust_remote_code`.** Inventory every load path that sets `trust_remote_code=True` and alert on any such load from a non-allowlisted org.
7. **Freeze and review on any flag.** Hold the pin at the last-known-good SHA, require human review before promotion, and mirror only approved revisions into your internal registry.

## Key Concepts

- **Rug pull (AML.T0109):** a benign artifact earns adoption, then a later malicious version is pushed to the installed base. Detection is version-delta integrity, not point-in-time scanning.
- **Reputation inflation (AML.T0111):** fake stars, likes, or downloads inflate trust so a malicious artifact clears the extra scrutiny new uploads receive. High reputation plus new maintainer plus new pickle file is high severity.
- **Publish poisoned models / datasets (AML.T0058 / AML.T0019):** the artifact is malicious from first publish rather than turned later; the provenance and scan controls are the same.
- **Executable surface:** pickle deserialization (opcodes `GLOBAL`, `REDUCE`, `STACK_GLOBAL` referencing `os`, `posix`, `subprocess`, or `builtins.eval`), Keras Lambda layers, and TensorFlow SavedModel custom ops all run code on load. safetensors cannot.
- **Hub scan caveat:** Hugging Face marks flagged files but does not block them, and the Hub scanner is picklescan itself — so a green hub badge is not an allow decision, and your own re-scan with the same tool is not an independent control either.
- **Scanners are blocklist-based:** picklescan and ModelScan match known-dangerous opcodes and imports, and both have documented public bypasses (malformed/mis-dispatched archives, scanner-crash cases, alternative gadget chains). A clean scan is evidence, never an allow decision. The durable control is requiring safetensors and quarantining pickle on ingest.
- **Named reference:** the `postmark-mcp` npm rug pull — an impersonating third-party clone of Postmark's MCP server, not Postmark's own package, which ran benign for many releases before a version began BCCing outbound mail to an attacker — is the canonical consumer-side pattern. For rug pulls in the MCP tool surface itself (tool definitions and descriptions changing after approval), use auditing-mcp-servers-for-tool-poisoning.

## Tools & Systems

| Layer | Tool | Signal |
|-------|------|--------|
| Pickle scan | picklescan, ModelScan, Fickling | Dangerous opcodes / imports on load |
| Format | safetensors | Non-executable weight format (preferred) |
| Hub provenance | huggingface_hub API | Commit/version history, file-add events, download/star history |
| Packaging | OSV, Syft, Grype | Known-vuln and manifest drift on loader packages |
| Registry | MLflow / SageMaker / Vertex | Promotion, approval, and artifact-hash records |

Treat research-prototype pickle scanners as unverified; the production tools above are the baseline. Note the baseline is a detective control only: all three pickle scanners are blocklist-based and bypassable, so a clean verdict must not be promoted to an allow decision.

## Detection Queries

Diff the file manifest between two Hugging Face revisions and flag newly added executable surface:

```python
# verify field names against the installed huggingface_hub version
from huggingface_hub import HfApi
api = HfApi()

RISKY = (".bin", ".pt", ".ckpt", ".pkl", ".pth", ".h5")

def new_executable_surface(repo_id, old_sha, new_sha, repo_type="model"):
    # list_repo_files returns a list[str] of paths (it unwraps rfilename internally)
    old = set(api.list_repo_files(repo_id, revision=old_sha, repo_type=repo_type))
    new = set(api.list_repo_files(repo_id, revision=new_sha, repo_type=repo_type))
    added = new - old
    # any newly added .py in a model repo is remote-code surface; the modeling_/configuration_/
    # tokenization_/image_processing_ prefixes are the Transformers custom-code convention
    flagged = [f for f in added if f.lower().endswith(RISKY) or f.endswith(".py")]
    had_only_safetensors = all(not o.lower().endswith(RISKY) for o in old)
    return {"added": sorted(added), "executable_added": sorted(flagged),
            "regressed_from_safetensors": bool(flagged and had_only_safetensors)}
```

Pin-drift check in CI (alert when a resolved pin no longer matches the recorded hash):

```python
import hashlib

def verify_pin(local_path, expected_sha256):
    h = hashlib.sha256(open(local_path, "rb").read()).hexdigest()
    if h != expected_sha256:
        raise SystemExit(f"PIN DRIFT: {local_path} is {h}, expected {expected_sha256}")
```

Reputation-inflation heuristic over registry telemetry (tune thresholds to your cohort):

```sql
-- pseudo-SQL over an internal mirror of hub telemetry; verify column names
SELECT repo_id, downloads_7d, stars_7d, inbound_refs, maintainer_age_days
FROM artifact_reputation
WHERE downloads_7d > 10 * cohort_median_downloads_7d   -- velocity far above cohort
  AND inbound_refs < 2                                  -- adoption decoupled from citations
  AND maintainer_age_days < 30;                         -- brand-new maintainer
```

Pickle scan as an ingest gate (fail closed on finding):

```bash
picklescan --path ./incoming_model && modelscan -p ./incoming_model
# non-zero exit or any flagged opcode => quarantine, do not promote
# a clean exit is NOT an allow decision: both tools are blocklist-based with documented
# bypasses, so gate on format (safetensors required, pickle quarantined) as the real control
```

## Common Scenarios

- **Silent weight swap:** a repo pinned by tag resolves to a new hash with no model-card or changelog update. Pin drift fires; freeze at last-known-good SHA.
- **safetensors-to-pickle regression:** a trusted, previously safetensors-only model adds a `.bin` with `REDUCE` opcodes referencing `subprocess`. Manifest diff plus scan fires; quarantine.
- **Inflated newcomer:** a two-week-old dataset shows download velocity 20x its cohort and stars from newly created accounts. Reputation heuristic fires; require human review before any ingest.
- **trust_remote_code smuggling:** a new revision adds `modeling_<arch>.py` and a helper module, and the load path sets `trust_remote_code=True`. Load-path inventory fires; block unless the org is allowlisted.
- **Typosquat re-upload:** a renamed repo mimics a trusted name. Provenance check fires on absent attestation and name similarity.

## Output Format

Report each finding with:

- Artifact id, old SHA, new SHA (or publish SHA for poisoned-at-publish).
- Signal class: version-delta executable surface, pin drift, reputation inflation, provenance gap, or trust_remote_code.
- Evidence: added files, scan opcodes/imports, velocity vs cohort, maintainer/owner change.
- Severity: high when high reputation combines with a new maintainer and new executable surface.
- ATLAS mapping: AML.T0109 (rug pull), AML.T0111 (reputation inflation), AML.T0058 / AML.T0019 (poisoned-at-publish).
- Recommended action and the last-known-good SHA to freeze to.

## Response

- Freeze the pin at the last-known-good SHA and block promotion pending human review.
- Require safetensors; quarantine pickle on ingest; gate `trust_remote_code` to an allowlist of trusted orgs.
- Mirror only approved revisions into an internal registry and serve builds only from it.
- On a confirmed rug pull: pull the artifact from the internal mirror, rotate any secrets the artifact or its tool could have touched, and audit every downstream model and service built on the bad revision.
- Pair this with detecting-data-and-model-poisoning to check whether a bad revision already influenced a trained model.
