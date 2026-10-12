# Detecting AI Agent Memory Poisoning — research notes

- **Proposed slug:** detecting-ai-agent-memory-poisoning
- **ATLAS:** AML.T0080 AI Agent Context Poisoning (tactic: Persistence) — including sub-techniques AML.T0080.000 (Memory, the persistent durable store) and AML.T0080.001 (Thread, the current conversation thread). Added in the Oct-2025 MITRE/Zenity Labs agentic update. Related but distinct: AML.T0070 RAG Poisoning (targets the retrieval index/corpus), AML.T0081 Modify AI Agent Configuration (config state). Mitigation referenced in ATLAS: Memory Hardening (AML.M0031 — verify ID).
- **Status:** research (not yet a skill)

## Defensive goal
Detect **persistent corruption of an agent's long-term memory / durable context store** so that *future* turns and sessions misbehave. An attacker gets a malicious instruction or false "preference/fact" written into the agent's memory (vector store, summary memory, user-profile/preferences doc, or a shared thread used as context), so the poison survives the originating conversation and silently steers every later session — for one user, or, in shared-memory/shared-thread deployments, for every participant. This is distinct from one-shot indirect injection: the harm is the *stored, replayed* state, not a single ingested document.

## Data sources / telemetry
- **Memory / vector-store write logs:** every `add`/`upsert`/`update`/`delete` to the agent's long-term memory — who/what wrote it, source turn, content, embedding id, timestamp. LangGraph checkpointer / `store` writes, LangMem, Mem0, Zep, Letta/MemGPT memory operations, raw vector-DB write logs (Pinecone/Weaviate/pgvector/Chroma).
- **Agent framework traces:** LangSmith / Langfuse / OpenTelemetry GenAI spans linking a memory-write tool call to the turn and the untrusted input that triggered it.
- **Retrieval/read logs:** what memory records were pulled into context for a given turn (to tie later misbehaviour back to a specific poisoned record).
- **Content integrity:** periodic hash/version snapshots of durable memory; diffs of the user-profile/preferences/"saved instructions" blob.
- **Shared-thread logs:** message provenance in multi-participant threads/channels where thread history is reused as context.

## Detection logic / approach
1. **Write-provenance anomaly:** memory writes that originate from *ingested untrusted content* (web page, email, RAG doc, tool output) rather than a direct user instruction — e.g. a memory `add` whose triggering turn contained externally-fetched text. Flag imperative/instructional content ("always…", "from now on…", "ignore…", "when asked X, do Y") landing in a store that should hold facts/preferences.
2. **Content classification of memory writes:** scan the written payload for injected directives, tool/credential references, URLs, or policy-override language before (or just after) it is persisted.
3. **Behavioural drift / misattribution:** later turns that act on an instruction never given in the current conversation — correlate the anomalous action back to a memory *read* of a specific record (addresses the "memory poisoning looks like model failure" misattribution gap).
4. **Integrity diff:** compare memory snapshots/hashes over time; alert on edits to high-value records (system-preference, standing-instruction, trusted-source lists) outside an approved path.
5. **Baseline:** most memory writes are benign facts/preferences from the user; instruction-shaped writes sourced from third-party content are the anomaly.

## Response / mitigation
- **Quarantine & roll back:** revert the poisoned record from a known-good snapshot/version; purge derived embeddings; replay/re-summarise affected sessions.
- **Write controls (primary prevention):** least-privilege on memory writes; require provenance tagging (trusted-user vs ingested-content); block memory writes that carry imperative instructions; human-in-the-loop or classifier gate on durable-memory commits; AML.M0031 Memory Hardening on durable state.
- **Scope the blast radius:** in shared-memory/thread deployments, identify every user/session that read the poisoned record; notify and re-baseline.
- **Separate trust tiers:** never let content fetched during a turn write to the same durable store as user-authored preferences without tagging.

## Real tools
LangGraph store/checkpointer logs, LangMem, Mem0, Zep, Letta/MemGPT memory ops; vector DB audit/write logs (Pinecone, Weaviate, pgvector, Chroma, Qdrant); LangSmith / Langfuse / OpenTelemetry GenAI tracing; input/output classifiers for directive detection (Llama Guard-class, Prompt-injection detectors); content-hash/version control on memory snapshots. No standard off-the-shelf "memory-poison detector" yet — composed from write logs + classifier + provenance.

## Draft frontmatter mappings
- atlas: [AML.T0080]
- nist_csf: [DE.CM-09, DE.AE-02, PR.PS-01, PR.AA-05, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-indirect-prompt-injection

## Draft description (<=1024 chars)
Detects AI agent memory poisoning (ATLAS AML.T0080 AI Agent Context Poisoning, incl. Memory .000 and Thread .001) — an attacker gets a malicious standing instruction or false preference written into an agent's durable long-term memory or a shared thread, so the poison survives the session and silently steers every future turn (and, in shared stores, every participant). Works by auditing memory and vector-store write logs for instruction-shaped content whose provenance is ingested input not a direct user command, classifying writes for injected directives, diffing memory snapshots for unauthorized edits, and tracing later misbehavior to a specific poisoned read. Use when hunting persistent agent behavior drift, poisoned long-term memory, or shared-thread context corruption. Keywords: AML.T0080, agent memory poisoning, vector store write, LangGraph store, Mem0, Zep, LangMem, memory hardening. Do not use for one-shot injection of a single ingested document - use detecting-indirect-prompt-injection.

## Key references
- MITRE ATLAS AML.T0080 AI Agent Context Poisoning (.000 Memory, .001 Thread) (atlas.mitre.org) — verify wording and sub-technique IDs
- MITRE ATLAS mitigation AML.M0031 Memory Hardening — verify ID
- OWASP Agentic AI threats taxonomy: memory/knowledge-base poisoning; OWASP LLM Top 10 LLM03 (data/model poisoning lineage)
- NIST AI RMF (Manage/Measure functions; data integrity of agent state)
- LangGraph persistence / LangMem docs; Mem0, Zep, Letta memory architecture docs

## Open questions / scope boundaries
- Hard boundary vs detecting-indirect-prompt-injection: that skill is one-shot ingested-content injection; this one is the *persisted, replayed* corruption. Keep the brief on write-logs/provenance/snapshots.
- Boundary vs RAG Poisoning (AML.T0070): the retrieval corpus/index is a different store — note the handoff; do not fold it in here.
- False positives: legitimate "remember that I prefer X" writes. Provenance tagging (user vs ingested) is the critical filter; author must define it concretely.
- Many agent memory layers currently lack write-provenance logging at all — flag the telemetry-availability gap as a prerequisite.
- Verify AML.T0080 sub-technique IDs and the Memory Hardening mitigation ID against ATLAS v5.6.0.
