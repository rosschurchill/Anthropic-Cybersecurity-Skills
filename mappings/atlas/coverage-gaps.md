# MITRE ATLAS — coverage-gap triage

Computed against the local MITRE ATLAS v5.6.0 technique set (`tools/atlas-technique-names.json`).

## Current baseline (post-cleanup, post-Tier-A)

- **Base techniques:** 101
- **Covered by ≥1 skill:** 41 (41%)
- **Uncovered:** 60

Every covered technique now maps to a skill that genuinely addresses it. The earlier figure of
"21 covered (21%)" was **not comparable**: it was inflated by spurious tags (see *Mapping cleanup*
below) while simultaneously missing the 12 Tier-A skills since shipped.

## ATLAS deliberately reuses ATT&CK techniques

Many uncovered IDs are generic enterprise behaviours re-listed in the ATLAS matrix (Active Scanning,
Valid Accounts, User Execution, Command and Scripting Interpreter, OS Credential Dumping, Reverse
Shell, Masquerading, Process Discovery, Exploit Public-Facing Application, Drive-by Compromise, Cloud
Service Discovery, Exfiltration via Cyber Means, Data from Local System/Information Repositories).
These are **Tier B** — the detection is not AI-specific and is already owned by existing enterprise
skills. Resource-development and reconnaissance primitives (Search Open *, Acquire/Develop/Obtain/
Stage/Establish capabilities, Discover AI Model Ontology/Family, AI-Enabled Product, Deploy AI Agent)
and pure outcomes (External Harms) are **Tier C** — adversary-side capability or an outcome, not
something you detect on your own systems.

## Mapping cleanup (resolved)

The ATLAS mappings were previously polluted by a bulk mis-tagging event. **200 spurious ATLAS tag
instances across 78 non-`ai-security` skills** were removed. The pattern and some representative
false positives:

| Spurious tag set | Count | Examples |
|---|---|---|
| `AML.T0066` + `AML.T0070` + `AML.T0082` (the RAG trio) | 44 skills | `recovering-deleted-files-with-photorec`, `configuring-hsm-for-key-storage`, `detecting-modbus-protocol-anomalies`, `implementing-gdpr-data-protection-controls` |
| `AML.T0051`/`T0054`/`T0056` (LLM injection / jailbreak / system-prompt) | 4 skills | `implementing-passwordless-authentication-with-fido2`, `implementing-hardware-security-key-authentication` |
| `AML.T0018` + `AML.T0043` (Manipulate AI Model / Craft Adversarial Data) | 4 skills | `detecting-dnp3-protocol-anomalies`, `implementing-aws-macie-for-data-classification` |
| `AML.T0024`/`T0035`/`T0086` (AI inference-API / artifact / agent-tool exfil) | 7 skills | `analyzing-dns-logs-for-exfiltration`, `implementing-endpoint-dlp-controls` |
| `AML.T0052` / `AML.T0073` (Phishing / Impersonation) | 11 skills | `analyzing-email-headers-for-phishing-investigation`, `analyzing-typosquatting-domains-with-dnstwist` |

Several were keyword collisions rather than judgement calls:
`analyzing-ios-app-security-with-objection` carried **LLM Jailbreak** (iOS jailbreak is unrelated),
`extracting-config-from-agent-tesla-rat` carried **Exfiltration via AI Agent Tool Invocation**
(Agent Tesla is a RAT, not an AI agent), `analyzing-macro-malware-in-office-documents` carried
**LLM Prompt Obfuscation**, and `detecting-ntlm-relay-with-event-correlation` carried four LLM
techniques.

**Rule applied:** an ATLAS tag is a factual claim that the skill addresses that adversary technique
against an AI system. Skills that merely *use* AI as tooling do not qualify — so
`performing-ai-driven-osint-correlation` (sends OSINT findings to an LLM) and
`detecting-business-email-compromise-with-ai` (uses ML/NLP to classify email) had their tags removed.
The one retained mapping on a non-`ai-security` skill is
`detecting-deepfake-audio-in-vishing-attacks` → `AML.T0052`, `AML.T0088` (it genuinely detects
AI-generated voice), reduced from four tags by dropping `AML.T0018`/`AML.T0043`.

### NIST AI RMF mappings (also cleaned)

The same bulk event had attached `nist_ai_rmf` mappings to skills with no AI dimension.
**260 instances across 78 non-`ai-security` skills** were removed (subjects such as
`analyzing-outlook-pst-for-email-forensics`, `recovering-deleted-files-with-photorec` and
`analyzing-powershell-empire-artifacts`).

AI RMF needed a **different rule than ATLAS**, because the two frameworks point in opposite
directions: an ATLAS tag claims the skill defends against attacks *on* an AI system, whereas AI RMF
governs an AI system you *operate*. So the test applied was: **does the skill's own procedure build,
train, tune, evaluate or govern an AI/ML model, or address AI-generated threats?** Merely deploying a
vendor product that uses ML internally (CrowdStrike, Macie, a cloud SIEM) does not make a skill an
AI-risk-management procedure, so those were cleared.

Four non-`ai-security` skills legitimately keep their AI RMF mappings:

| Skill | Why it qualifies |
|---|---|
| `detecting-anomalies-in-industrial-control-systems` | trains an Isolation Forest with scikit-learn (real model lifecycle) |
| `detecting-business-email-compromise-with-ai` | builds BERT/NLP stylometry detection |
| `performing-ai-driven-osint-correlation` | operates an LLM as part of the workflow |
| `detecting-deepfake-audio-in-vishing-attacks` | addresses AI-generated voice |

`nist_ai_rmf` now appears on 30 skills: the 26 `ai-security` skills plus those four. All values are
valid AI RMF subcategory IDs.

Two false positives were caught during triage and deliberately not kept:
`performing-clickjacking-attack-test` scored highly only because "embedding" appears nine times in
the *iframe* sense, and `implementing-cisa-zero-trust-maturity-model` mentions "AI-driven anomaly
detection" only as a CISA Optimal-stage aspiration, not as work the skill performs.

## Tier A build queue — shipped

All 12 authored and merged; each is the primary owner of its technique.

| ATLAS | Technique(s) | Skill | Status |
|---|---|---|---|
| AML.T0015 | Evade AI Model (+T0043) | `detecting-adversarial-evasion-attacks` | shipped |
| AML.T0029 | Denial of AI Service (+T0034, +T0046) | `detecting-ai-service-denial-and-cost-harvesting` | shipped |
| AML.T0061 | LLM Prompt Self-Replication | `detecting-llm-prompt-self-replication` | shipped |
| AML.T0060 | Publish Hallucinated Entities | `detecting-package-hallucination-and-slopsquatting` | shipped |
| AML.T0077 | LLM Response Rendering | `detecting-llm-output-rendering-exfiltration` | shipped |
| AML.T0080 | AI Agent Context Poisoning | `detecting-ai-agent-memory-poisoning` | shipped |
| AML.T0081 | Modify AI Agent Configuration (+T0084, +T0083) | `detecting-ai-agent-configuration-tampering` | shipped |
| AML.T0105 | Escape to Host (+T0112, +T0097, +T0106, +T0107) | `detecting-ai-agent-sandbox-escape` | shipped |
| AML.T0109 | AI Supply Chain Rug Pull (+T0111, +T0058, +T0019) | `detecting-ai-model-supply-chain-rug-pull` | shipped |
| AML.T0102 | Generate Malicious Commands | `detecting-malicious-ai-generated-code` | shipped |
| AML.T0092 | Manipulate User LLM Chat History (+T0094) | `detecting-llm-chat-history-manipulation` | shipped |
| AML.T0070 | RAG Poisoning (+T0071, +T0064) | `detecting-rag-knowledge-base-poisoning` | shipped |

Distinctions that keep the set collision-free against the pre-existing AI skills:
- **adversarial-evasion** (inference-time perturbation to flip a prediction) vs **data/model poisoning**
  (training-time) vs **model-extraction** (stealing).
- **rag-knowledge-base-poisoning** (planting docs in the index; corpus integrity + provenance) vs
  **indirect-prompt-injection** (screening untrusted content at query time) vs
  **assessing-vector-and-embedding-weaknesses** (offensive assessment of the store).
- **ai-agent-configuration-tampering**, **ai-agent-memory-poisoning** and **ai-agent-sandbox-escape**
  are three distinct agent surfaces, none of which is the tool-call boundary policy
  (**securing-agentic-ai-tool-invocation**) or the MCP tool audit
  (**auditing-mcp-servers-for-tool-poisoning**).
- **ai-model-supply-chain-rug-pull** (hub provenance, rug pulls, reputation inflation) vs
  **detecting-data-and-model-poisoning** (poisoning-effect detection in weights/data).

## Tier B / C (fold or skip)

Tier B (fold into existing enterprise/AI skills): AML.T0006, T0011, T0012, T0025, T0036, T0037, T0049,
T0050, T0055, T0072, T0074, T0075, T0078, T0089, T0090, T0091, T0098, T0100, T0101, T0086.
Tier C (adversary capability / recon / outcome, skip): AML.T0000-T0008, T0013, T0014, T0016, T0017,
T0021, T0031, T0035, T0040-T0042, T0044, T0047, T0048, T0063, T0069, T0079, T0087, T0095, T0096,
T0103, T0104, T0108, T0110, T0099, T0059, T0076, T0005.
