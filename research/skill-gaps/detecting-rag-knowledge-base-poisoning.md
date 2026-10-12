# Detecting RAG Knowledge Base Poisoning — research notes

- **Proposed slug:** detecting-rag-knowledge-base-poisoning
- **ATLAS:** AML.T0070 RAG Poisoning — plus folded-in AML.T0071 False RAG Entry Injection, AML.T0064 Gather RAG-Indexed Targets
- **Status:** research (not yet a skill)

## Defensive goal
Detect malicious documents planted **into** a RAG index/corpus and the reconnaissance/ingestion activity around it, from the ingestion-pipeline and vector-store provenance side. Shapes: (1) **RAG poisoning (AML.T0070)** — attacker-crafted content indexed so it surfaces for targeted queries, carrying false info or prompt-injection payloads (PoisonedRAG: ~5 malicious texts in a million-doc corpus can exceed 90% attack-success on NQ/HotpotQA/MS-MARCO); (2) **false RAG entry injection (AML.T0071)** — a fake "document" hidden *inside* a legitimate ingested source, with spoofed metadata (title/author/date), which evades data-monitoring and resists direct deletion; (3) **gather RAG-indexed targets (AML.T0064)** — recon that identifies which sources a RAG system indexes (from public docs or by probing the system) to pick poisoning targets. Scope is the **corpus/pipeline/provenance**, distinct from query-time content screening (detecting-indirect-prompt-injection) and offensive store assessment (assessing-vector-and-embedding-weaknesses).

## Data sources / telemetry
- **Ingestion-pipeline logs:** every document ingest event — source URI, fetch connector, crawler/user identity, content hash, timestamp, chunking + embedding job records; which pipeline run wrote which chunks.
- **Vector-store write/provenance logs:** upsert/delete events on Pinecone/Qdrant/Weaviate/Chroma/pgvector/FAISS, with per-vector metadata (`source`, `doc_id`, `author`, `ingested_by`, `ingest_ts`, content hash), and who/what performed the write.
- **Document source allowlist:** canonical list of sanctioned sources/domains/connectors; ingest from anything off-list is an event.
- **Retrieval/relevance monitoring:** per-query top-k results, retrieval scores, and which chunks are surfaced; distribution of a chunk's retrieval frequency over time.
- **LLM observability (Langfuse / Arize Phoenix):** retrieved-context traces tied to responses, enabling traceback from a bad answer to the responsible chunk.
- **Access logs on the corpus sources:** anomalous edits to indexed wikis/tickets/shared drives; recon-style enumeration of what is indexed (AML.T0064 signal).

## Detection logic / approach
- **Source-provenance enforcement at ingest:** reject/quarantine any document whose source is not on the allowlist, lacks a resolvable origin, or arrives via an unexpected connector. Every vector carries immutable provenance metadata; a vector with missing/forged provenance = alert. This directly counters T0071's "hidden inside a legitimate entry" by validating at the chunk level, not the document level.
- **Ingest-time content screening:** scan incoming chunks for prompt-injection/instruction patterns ("ignore previous", "when asked about X answer Y", tool-invocation imperatives), invisible/zero-width/homoglyph text, and HTML/markdown comment smuggling — *at ingest*, before the chunk ever reaches retrieval (contrast with query-time screening).
- **Statistical/embedding anomaly on the corpus:** flag chunks that are outliers in embedding space relative to their claimed source cluster, chunks with anomalously high similarity to many distinct queries (a hallmark of PoisonedRAG craft), duplicate/near-duplicate injected texts, and perplexity outliers. TrustRAG-style K-means clustering of retrieved candidates to isolate suspicious groups (verify).
- **Retrieval-behaviour monitoring:** alert on a newly-ingested chunk that suddenly dominates top-k for many unrelated queries, or a sharp shift in which source answers a query class — poisoned entries are engineered to retrieve broadly.
- **Metadata-spoofing checks:** cross-check chunk metadata (author/date/title) against the source system of record; mismatches indicate false-entry injection.
- **Traceback / forensics:** on a suspicious answer, use context traces (RAGForensics-style) to identify the responsible chunk(s), then purge and re-index; activation-based detectors (RevPRAG, reported ~98% TPR / ~1% FPR) as a response-side backstop (verify).
- **Recon detection (T0064):** flag probing patterns that enumerate indexed sources or systematically ask boundary questions to map the corpus.

## Response / mitigation
- Allowlist sources; sign/provenance-stamp every chunk; make ingest a reviewed, logged pipeline (no direct vector-store writes). Screen content at ingest; quarantine-then-review off-allowlist or flagged docs. On detection: identify and purge the poisoned chunks via provenance/traceback, re-index from clean sources, rotate any connector creds if the write was unauthorized, and apply query-time indirect-prompt-injection controls as defense-in-depth. Note detection-based defenses alone are imperfect (benchmarks show mixed results) — pair corpus hygiene with retrieval-time guardrails.

## Real tools
Pinecone/Qdrant/Weaviate/Chroma/pgvector/FAISS write logs + metadata; LangChain/LlamaIndex ingestion pipelines; Langfuse / Arize Phoenix (retrieval-context traces); embedding-space outlier/clustering (scikit-learn K-means, perplexity filters); research defenses TrustRAG, RobustRAG, RAGForensics, RevPRAG, RAGuard (all academic — verify names/availability before use). PoisonedRAG is the reference attack (Zou et al., arXiv — verify id 2402.07867).

## Draft frontmatter mappings
- atlas: [AML.T0070, AML.T0071, AML.T0064]
- nist_csf: [DE.CM-09, DE.AE-02, DE.AE-03, PR.PS-01, ID.AM-02, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-indirect-prompt-injection (query-time screening) ; assessing-vector-and-embedding-weaknesses (offensive store assessment)

## Draft description (<=1024 chars)
Detects poisoning of a RAG knowledge base from the ingestion-pipeline and vector-store provenance side: malicious documents planted into the index to surface for targeted queries, false entries hidden inside legitimate sources with spoofed metadata, and recon that maps which sources a RAG system indexes. Uses ingestion-pipeline logs, vector-store write and provenance metadata, document source allowlists, embedding-space and retrieval-frequency anomaly monitoring, ingest-time content screening, and retrieval-context traceback. Use when securing a RAG ingestion pipeline or vector store, vetting a corpus for planted content, or tracing a bad answer back to the responsible chunk. Keywords: RAG poisoning, knowledge base poisoning, false RAG entry, PoisonedRAG, vector store provenance, ingestion pipeline, source allowlist, retrieval anomaly, AML.T0070, AML.T0071, AML.T0064. Do not use for screening retrieved content at query time - use detecting-indirect-prompt-injection. Do not use for offensive testing of a vector store - use assessing-vector-and-embedding-weaknesses.

## Key references
- https://atlas.mitre.org/techniques/AML.T0070 (verify path) ; AML.T0071 ; AML.T0064
- https://d3fend.mitre.org/offensive-technique/attack/AML.T0070/ , /AML.T0071/ , /AML.T0064/
- OWASP LLM Top 10 — LLM08:2025 Vector and Embedding Weaknesses, LLM04:2025 Data and Model Poisoning
- PoisonedRAG (Zou et al.) — verify arXiv 2402.07867
- RevPRAG (arXiv 2411.18948), TrustRAG, RobustRAG, RAGForensics, RAGuard (arXiv 2510.25025) — verify ids/dates
- NIST AI RMF (MEASURE/MANAGE data-integrity functions)

## Open questions / scope boundaries
- Confirm AML.T0070/T0071/T0064 tactics and current names against atlas.mitre.org v5.6.0 (secondary sites say Persistence / Defense Evasion / Reconnaissance respectively — verify).
- Verify the arXiv ids/dates for the research defenses; several returned implausible/future identifiers.
- Boundary is the corpus/pipeline: query-time screening of retrieved content → detecting-indirect-prompt-injection; offensive assessment (inversion, cross-tenant leak, store poisoning tests) → assessing-vector-and-embedding-weaknesses. This skill owns ingest provenance + corpus hygiene + traceback.
- Open: how much embedding-anomaly detection to ship vs provenance/allowlist (provenance is more robust; anomaly detection is evadable per benchmarks).
