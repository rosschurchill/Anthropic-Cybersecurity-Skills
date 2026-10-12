# Detecting AI Model Supply Chain Rug Pull — research notes

- **Proposed slug:** detecting-ai-model-supply-chain-rug-pull
- **ATLAS:** AML.T0109 AI Supply Chain Rug Pull — plus folded-in AML.T0111 AI Supply Chain Reputation Inflation, AML.T0058 Publish Poisoned Models, AML.T0019 Publish Poisoned Datasets
- **Status:** research (not yet a skill)

## Defensive goal
Detect, from the *consumer/registry/provenance* side, when a third-party AI model or dataset that an organization depends on turns malicious after trust was established. Two shapes: (1) **rug pull** — a popular, benign model/dataset/agent-tool gets a later malicious version pushed once it has a critical mass of adopters (classic pattern: benign release, trust-building, malicious update); (2) **poisoned-at-publish** — a model or dataset is shipped malicious from the start, often with **inflated reputation** (fake stars/downloads/likes) to clear the extra scrutiny new artifacts receive. Real-world anchor: the Postmark MCP npm rug pull (AML.CS0053 — verify id) where a trusted package later BCC'd all outbound mail to the attacker. This is a **hub/provenance** skill: it watches what you *pull in*, not the downstream poisoning *effect* on a trained model (that is detecting-data-and-model-poisoning).

## Data sources / telemetry
- **Hugging Face Hub provenance:** model/dataset card metadata, commit/version history (`git` refs on the repo), file-add/replace events between revisions, download-count and like/star history, contributor identity, maintainer changes, `safetensors` vs pickle (`.bin`/`.pt`/`.ckpt`/`.pkl`) file inventory, HF's own "unsafe" / pickle-scan verdicts (note: HF marks but does **not** block flagged files).
- **Registry/dependency telemetry for AI artifacts:** npm/PyPI package version timelines for MCP servers and model-loader packages, publish timestamps, maintainer-token changes, lockfile pin drift (internal mirror logs).
- **Reputation signals:** sudden download/star/like spikes decoupled from references/citations (inflation); account age vs download volume; many low-signal accounts starring in a narrow window.
- **Model-scanning output:** picklescan, ModelScan, Fickling findings (opcodes `GLOBAL`/`REDUCE`/`STACK_GLOBAL` referencing `os`/`posix`/`subprocess`/`builtins.eval`), Keras Lambda-layer code, TensorFlow SavedModel custom ops.
- **Internal model-registry logs:** MLflow / Vertex / SageMaker Model Registry version promotions, approval events, artifact hash records.

## Detection logic / approach
- **Version-delta integrity:** on every new revision of a pinned model/dataset, diff the file manifest and **re-scan**. Alert when a previously-safetensors repo adds a pickle/Keras-Lambda/`__reduce__`-bearing artifact, when an inference/config file gains executable payloads (`trust_remote_code=True` custom `modeling_*.py`), or when the weight hash changes without a corresponding model-card/changelog update. This is the core rug-pull signal: *trusted artifact, later unexplained executable surface*.
- **Pin + hash enforcement:** require consumers to pin by immutable commit SHA / content hash, not by mutable tag like `main`. Alert when a build resolves a pin that no longer matches the recorded hash (silent in-place swap).
- **Reputation-inflation heuristic:** flag artifacts whose adoption curve is anomalous — download/star velocity far above cohort, stars from freshly-created accounts, or downloads with near-zero inbound references. Treat high reputation + new maintainer + new pickle file as high severity.
- **Provenance gap:** flag dependence on artifacts lacking signature/attestation, published by an account with a recent email/owner change, or re-uploaded under a renamed repo (typosquat of a trusted name).
- **trust_remote_code gate:** inventory every load path that sets `trust_remote_code=True`; alert on any such load from a non-allowlisted org.

## Response / mitigation
- Pin by SHA/hash; maintain an **allowlist of trusted orgs/repos**; mirror approved artifacts into an internal registry and serve only from it. Require `safetensors` and block/quarantine pickle on ingest. Gate `trust_remote_code`. On a flagged new revision: freeze the pin at the last-known-good SHA, re-scan, require human review before promotion. On confirmed rug pull: pull the artifact from the internal mirror, rotate any secrets the artifact (or its MCP tool) could have touched, and audit all downstream models/services built on the bad revision.

## Real tools
picklescan, ModelScan (Protect AI), Fickling (Trail of Bits), `safetensors` (format + conversion), Hugging Face Hub scan verdicts, `huggingface_hub` API for commit/version history, Sigstore / model-signing (verify current HF model-signing status), MLflow / SageMaker / Vertex Model Registry, Syft/Grype or OSV for the packaging layer. SafePickle (arXiv 2602.19818 — verify id/date) is an ML-based pickle scanner reporting higher F1 than ModelScan/Fickling/ClamAV/VirusTotal on a 727-file HF corpus; treat as authors' numbers.

## Draft frontmatter mappings
- atlas: [AML.T0109, AML.T0111, AML.T0058, AML.T0019]
- nist_csf: [ID.AM-02, PR.PS-01, PR.PS-02, DE.CM-09, DE.AE-02, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-data-and-model-poisoning (and auditing-mcp-servers-for-tool-poisoning for the MCP-tool variant)

## Draft description (<=1024 chars)
Detects AI supply-chain rug pulls and poisoned published models/datasets from the consumer and registry side: a trusted Hugging Face or package-registry artifact that turns malicious in a later version, fake reputation or download/star inflation used to clear new-artifact scrutiny, and unexplained executable surface (pickle, Keras Lambda, trust_remote_code custom code) appearing between revisions. Uses hub version history, download/star velocity, model-scan verdicts (picklescan, ModelScan, Fickling), weight-hash pinning, and internal model-registry promotion logs. Use when vetting or continuously monitoring third-party models, datasets, or model-loader packages you depend on, or when a pinned artifact changes unexpectedly. Keywords: rug pull, model supply chain, Hugging Face provenance, picklescan, ModelScan, safetensors, reputation inflation, poisoned model, trust_remote_code, AML.T0109. Do not use for detecting the poisoning effect on an in-house trained model - use detecting-data-and-model-poisoning. Do not use for MCP tool rug pulls - use auditing-mcp-servers-for-tool-poisoning.

## Key references
- https://atlas.mitre.org/techniques/AML.T0109 (verify path) ; AML.T0111, AML.T0058, AML.T0019
- https://d3fend.mitre.org/offensive-technique/attack/AML.T0109/
- AML.CS0053 Postmark MCP rug pull case study (verify id)
- JFrog: "Data Scientists Targeted by Malicious Hugging Face ML Models with Silent Backdoor"
- OWASP LLM Top 10 — LLM03:2025 Supply Chain, LLM04:2025 Data and Model Poisoning
- SafePickle, arXiv 2602.19818 (verify id/date)
- Hugging Face Hub security docs (pickle scanning, malware scanning, safetensors)

## Open questions / scope boundaries
- Confirm AML.T0058 / AML.T0019 exact current names and the Postmark case-study id against atlas.mitre.org (v5.6.0).
- Confirm current state of Hugging Face model signing / Sigstore attestation support.
- Reputation-inflation detection needs a baseline cohort; decide whether the skill ships heuristics or only telemetry guidance.
- Boundary: stays at hub/registry/provenance layer. In-house poisoning-effect detection → detecting-data-and-model-poisoning; MCP tool poisoning/rug pull → auditing-mcp-servers-for-tool-poisoning; generic package malware triage → analyzing-supply-chain-malware-artifacts.
