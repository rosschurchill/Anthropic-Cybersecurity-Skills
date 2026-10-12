# MITRE ATLAS — coverage-gap triage

Computed against the local MITRE ATLAS v5.6.0 technique set (`tools/atlas-technique-names.json`).

- **Base techniques:** 101
- **Covered by ≥1 skill (frontmatter `atlas`):** 21 (21%)
- **Uncovered:** 80

## Two caveats before reading the gap list

1. **ATLAS deliberately reuses ATT&CK techniques.** Many uncovered IDs are generic enterprise
   behaviours re-listed in the ATLAS matrix (Active Scanning, Valid Accounts, User Execution,
   Command and Scripting Interpreter, OS Credential Dumping, Reverse Shell, Masquerading, Process
   Discovery, Exploit Public-Facing Application, Drive-by Compromise, Cloud Service Discovery,
   Exfiltration via Cyber Means, Data from Local System/Information Repositories). These are **Tier B**
   — the detection is not AI-specific and is already owned by existing enterprise skills. Resource-
   development and reconnaissance primitives (Search Open *, Acquire/Develop/Obtain/Stage/Establish
   capabilities, Discover AI Model Ontology/Family, AI-Enabled Product, Deploy AI Agent) and pure
   outcomes (External Harms) are **Tier C** — adversary-side capability or an outcome, not a thing you
   detect on your own systems.

2. **The existing ATLAS mappings are polluted.** Several AI techniques are tagged on dozens of
   unrelated skills — e.g. `AML.T0070 RAG Poisoning`, `AML.T0082 RAG Credential Harvesting` and
   `AML.T0066 Retrieval Content Crafting` each appear on ~45 skills including `recovering-deleted-files-with-photorec`,
   `detecting-modbus-protocol-anomalies` and `configuring-hsm-for-key-storage`; `AML.T0051/T0054/T0056`
   are tagged on FIDO2/passwordless-auth skills. So the "21 covered" figure overstates genuine AI
   coverage. Cleaning these spurious tags is a **separate data-quality task** (noted for follow-up);
   it does not block authoring the real gaps below.

## What the catalogue genuinely already covers (do not duplicate)

`detecting-ai-model-prompt-injection-attacks` (direct), `detecting-indirect-prompt-injection`,
`detecting-data-and-model-poisoning` (training-data + backdoored-model detection via ART/Cleanlab/
weight-hash), `detecting-model-extraction-attacks` (stealing/inversion/membership via inference API),
`auditing-mcp-servers-for-tool-poisoning` (MCP tool poisoning/shadowing/rug-pull of *tools*),
`securing-agentic-ai-tool-invocation` (tool-boundary hardening), `defending-llms-with-guardrails` /
`implementing-llm-guardrails-for-security`, `testing-for-system-prompt-leakage`,
`assessing-vector-and-embedding-weaknesses`.

## Tier A build queue (12) — genuinely uncovered, AI-specific, distinct detection skills

| ATLAS | Technique(s) | Proposed slug |
|---|---|---|
| AML.T0015 | Evade AI Model (+T0043 Craft Adversarial Data) | `detecting-adversarial-evasion-attacks` |
| AML.T0029 | Denial of AI Service (+T0034 Cost Harvesting, +T0046 Chaff Spamming) | `detecting-ai-service-denial-and-cost-harvesting` |
| AML.T0061 | LLM Prompt Self-Replication | `detecting-llm-prompt-self-replication` |
| AML.T0060 | Publish Hallucinated Entities | `detecting-package-hallucination-and-slopsquatting` |
| AML.T0077 | LLM Response Rendering | `detecting-llm-output-rendering-exfiltration` |
| AML.T0080 | AI Agent Context Poisoning | `detecting-ai-agent-memory-poisoning` |
| AML.T0081 | Modify AI Agent Configuration (+T0084 Discover, +T0083 Credentials) | `detecting-ai-agent-configuration-tampering` |
| AML.T0105 | Escape to Host (+T0112 Machine Compromise, +T0097 Sandbox Evasion, +T0106/T0107 Exploitation) | `detecting-ai-agent-sandbox-escape` |
| AML.T0109 | AI Supply Chain Rug Pull (+T0111 Reputation Inflation, +T0058 Publish Poisoned Models, +T0019 Publish Poisoned Datasets) | `detecting-ai-model-supply-chain-rug-pull` |
| AML.T0102 | Generate Malicious Commands | `detecting-malicious-ai-generated-code` |
| AML.T0092 | Manipulate User LLM Chat History (+T0094 Delay Execution of LLM Instructions) | `detecting-llm-chat-history-manipulation` |
| AML.T0070 | RAG Poisoning (+T0071 False RAG Entry Injection, +T0064 Gather RAG-Indexed Targets) | `detecting-rag-knowledge-base-poisoning` |

Distinctions that keep the set collision-free against the existing AI skills:
- **adversarial-evasion** (inference-time perturbation to flip a prediction) vs **data/model poisoning**
  (training-time, existing) vs **model-extraction** (stealing, existing).
- **rag-knowledge-base-poisoning** (planting malicious docs in the index / corpus integrity + provenance
  monitoring) vs **indirect-prompt-injection** (screening untrusted content an agent *ingests*, existing)
  vs **assessing-vector-and-embedding-weaknesses** (offensive assessment of the store, existing).
- **ai-agent-configuration-tampering** (the agent's own config/memory files and the creds in them) and
  **ai-agent-memory-poisoning** (persistent context/memory corruption) and **ai-agent-sandbox-escape**
  (code-executing agent breaking out to the host) vs **securing-agentic-ai-tool-invocation** (the
  tool-call boundary policy, existing) and **auditing-mcp-servers-for-tool-poisoning** (the MCP tools,
  existing).
- **ai-model-supply-chain-rug-pull** (model/dataset-hub provenance, rug pulls, reputation inflation) vs
  **detecting-data-and-model-poisoning** (poisoning-effect detection in weights/data, existing).

## Tier B / C (fold or skip)

Tier B (fold into existing enterprise/AI skills): AML.T0006, T0011, T0012, T0025, T0036, T0037, T0049,
T0050, T0055, T0072, T0074, T0075, T0078, T0089, T0090, T0091, T0098, T0100, T0101, T0086 — generic
ATT&CK reuse or already owned by `securing-agentic-ai-tool-invocation` / enterprise detections.
Tier C (adversary capability / recon / outcome, skip): AML.T0000-T0008, T0013, T0014, T0016, T0017,
T0021, T0031, T0035, T0040-T0042, T0044, T0047, T0048, T0063, T0069, T0079, T0087, T0095, T0096,
T0103, T0104, T0108, T0110, T0099, T0059, T0076, T0005.
