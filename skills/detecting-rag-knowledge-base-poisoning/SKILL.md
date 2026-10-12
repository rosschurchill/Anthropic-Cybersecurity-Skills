---
name: detecting-rag-knowledge-base-poisoning
description: 'Detects poisoning of a RAG knowledge base from the ingestion-pipeline and vector-store provenance side: malicious documents planted into the index to surface for targeted queries, false entries hidden inside legitimate sources with spoofed metadata, and recon that maps which sources a RAG system indexes. Uses ingestion-pipeline logs, vector-store write and provenance metadata, document source allowlists, embedding-space and retrieval-frequency anomaly monitoring, chunk-level metadata validation, and retrieval-context traceback. Use when securing a RAG ingestion pipeline or vector store, vetting a corpus for planted content, or tracing a bad answer back to the responsible chunk. Keywords: RAG poisoning, knowledge base poisoning, false RAG entry, PoisonedRAG, vector store provenance, source allowlist, retrieval anomaly, AML.T0070, AML.T0071, AML.T0064, OWASP LLM08. Do not use for poisoning of an agent persistent memory store rather than a retrieval corpus - use detecting-ai-agent-memory-poisoning.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- rag
- vector-store
- knowledge-base-poisoning
- ingestion-pipeline
- provenance
- embedding-anomaly
- llm
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0070
- AML.T0071
- AML.T0064
---
# Detecting RAG Knowledge Base Poisoning

## When to Use

- You run a RAG system and need to detect malicious documents planted into the index or vector store so they surface for targeted queries.
- You suspect a false entry hidden inside an otherwise legitimate ingested source, carrying spoofed metadata (title, author, date) to evade document-level monitoring.
- You see reconnaissance that enumerates which sources your RAG system indexes, used to pick poisoning targets.
- You need to trace a bad or manipulated answer back to the responsible chunk, then purge and re-index.

Scope is the corpus, pipeline, and provenance. Injection-payload screening of ingested content belongs to detecting-indirect-prompt-injection, which owns that payload taxonomy and pipeline both as a CI/CD pre-ingestion scan and at query time — delegate to it rather than duplicating it here. For poisoning of an agent persistent memory store (the running agent remembered-state, a different poisoned store than a retrieval corpus), use detecting-ai-agent-memory-poisoning. The two are complementary: this skill owns the RAG corpus; that sibling owns agent memory.

## Prerequisites

- Ingestion-pipeline logs: per-document source URI, fetch connector, crawler/user identity, content hash, timestamp, and chunking/embedding job records.
- Vector-store write/provenance logs (Pinecone, Qdrant, Weaviate, Chroma, pgvector, FAISS) with per-vector metadata (`source`, `doc_id`, `author`, `ingested_by`, `ingest_ts`, content hash).
- A canonical allowlist of sanctioned sources, domains, and connectors.
- LLM observability (Langfuse, Arize Phoenix) with retrieved-context traces tied to responses.
- Python 3.9+ with scikit-learn for embedding-space outlier/clustering checks.

## Workflow

1. **Enforce source provenance at ingest.** Reject or quarantine any document whose source is off-allowlist, lacks a resolvable origin, or arrives via an unexpected connector. Attach immutable provenance metadata to every vector. Validate at the chunk level, not the document level, which counters a false entry hidden inside a legitimate source.
2. **Hand injection-payload screening to detecting-indirect-prompt-injection.** That skill owns pre-ingestion scanning for instruction patterns, invisible/zero-width/homoglyph text and comment smuggling, both at ingest and at query time; run its pipeline in your ingest path and treat its verdict as the screening gate instead of maintaining a second pattern set here.
3. **Run embedding and statistical anomaly checks over the corpus.** Flag chunks that are outliers in embedding space relative to their claimed source cluster, chunks with anomalously high similarity to many distinct queries, duplicate/near-duplicate injected texts, and perplexity outliers.
4. **Monitor retrieval behaviour.** Alert on a newly ingested chunk that suddenly dominates top-k for many unrelated queries, or a sharp shift in which source answers a query class. Poisoned entries are engineered to retrieve broadly.
5. **Cross-check metadata.** Compare chunk metadata (author, date, title) against the source system of record; mismatches indicate false-entry injection.
6. **Trace back on suspicion.** Use retrieved-context traces to identify the responsible chunk(s) behind a bad answer, then purge and re-index from clean sources.
7. **Detect recon.** Flag probing that enumerates indexed sources or systematically asks boundary questions to map the corpus.

## Key Concepts

- **RAG poisoning (AML.T0070):** attacker-crafted content is indexed so it surfaces for targeted queries, carrying false information or an injection payload. Research shows a handful of malicious texts in a very large corpus can dominate retrieval for chosen questions.
- **False RAG entry injection (AML.T0071):** a fake document is hidden inside a legitimate ingested source with spoofed metadata, which evades document-level monitoring and resists direct deletion. Chunk-level provenance is the counter.
- **Gather RAG-indexed targets (AML.T0064):** reconnaissance that identifies which sources a system indexes, from public docs or by probing, to choose poisoning targets.
- **Provenance over anomaly:** source allowlisting and immutable chunk provenance are more robust than embedding anomaly detection, which benchmarks show is evadable. Ship provenance as the backbone and anomaly detection as a supporting signal.
- **Named reference:** PoisonedRAG is the reference attack demonstrating broad-retrieval poisoning and is cited here only for recognition.

## Tools & Systems

| Layer | Tool | Signal |
|-------|------|--------|
| Pipeline | LangChain / LlamaIndex ingest logs | Source URI, connector, content hash per chunk |
| Vector store | Pinecone/Qdrant/Weaviate/Chroma/pgvector/FAISS write logs | Upsert/delete provenance and metadata |
| Allowlist | Internal source registry | Off-allowlist ingest events |
| Anomaly | scikit-learn (clustering, outlier), perplexity filter | Embedding outliers, broad-similarity chunks |
| Traceback | Langfuse, Arize Phoenix | Retrieved-context to responsible chunk |

Research-prototype RAG defenses (clustering-based and activation-based detectors described in the literature) are unverified for production here; treat them as experimental and verify availability and claims before relying on them. Provenance and allowlisting do not depend on them.

## Detection Queries

Ingest-time provenance gate:

```python
def ingest_gate(chunk, allowlist):
    src = chunk.get("source")
    if src is None or src not in allowlist:
        return {"action": "QUARANTINE", "reason": "off-allowlist-or-missing-source", "doc": chunk.get("doc_id")}
    if not chunk.get("content_hash") or not chunk.get("ingested_by"):
        return {"action": "QUARANTINE", "reason": "missing-provenance", "doc": chunk.get("doc_id")}
    return {"action": "ACCEPT"}
```

For injection-payload and hidden-text screening of a chunk before it is indexed, call the pipeline in
detecting-indirect-prompt-injection; this skill does not carry a second copy of that pattern set.

Embedding-space outlier within a claimed source cluster (tune contamination):

```python
import numpy as np
from sklearn.ensemble import IsolationForest

def source_outliers(embeddings, source_ids, target_source):
    idx = [i for i, s in enumerate(source_ids) if s == target_source]
    X = np.array([embeddings[i] for i in idx])
    if len(X) < 20:
        return []
    flags = IsolationForest(contamination=0.02, random_state=0).fit_predict(X)
    return [idx[i] for i, f in enumerate(flags) if f == -1]
```

Retrieval-frequency anomaly over observability logs (SQL-style; verify schema):

```sql
-- a newly ingested chunk dominating top-k across unrelated queries
SELECT chunk_id, COUNT(DISTINCT query_class) AS query_classes, COUNT(*) AS retrievals,
       MIN(ingest_ts) AS first_seen
FROM retrieval_events
WHERE event_ts > now() - interval '24 hours'
GROUP BY chunk_id
HAVING COUNT(DISTINCT query_class) > 10         -- surfaces for many unrelated query classes
   AND MIN(ingest_ts) > now() - interval '48 hours';  -- and is brand new
```

## Common Scenarios

- **Broad-retrieval payload:** a few crafted chunks are engineered to be similar to many queries and dominate top-k. Retrieval-frequency anomaly plus embedding-outlier checks fire.
- **Hidden false entry:** a malicious passage is embedded inside a legitimate wiki page with spoofed author/date. Chunk-level provenance and metadata cross-check fire where document-level monitoring misses it.
- **Zero-width injection:** an ingested doc carries a zero-width or HTML-comment instruction. The pre-ingestion scan owned by detecting-indirect-prompt-injection flags it before indexing; this skill contributes the provenance record and the traceback once it is indexed.
- **Corpus recon:** a user systematically asks boundary questions to enumerate indexed sources. Recon detection flags the probing pattern.
- **Bad answer traceback:** a manipulated response is traced via context logs to the responsible chunk, which is purged and the index rebuilt from clean sources.

## Output Format

Report each finding with:

- Chunk id / doc id, source, and the signal: off-allowlist ingest, missing/forged provenance, injection-screen hit from the delegated pre-ingestion scan, embedding outlier, retrieval-frequency anomaly, metadata mismatch, or recon.
- Provenance record: who/what ingested it, when, from where, and content hash.
- For traceback: the query and response the poisoned chunk drove.
- ATLAS mapping: AML.T0070 (RAG poisoning), AML.T0071 (false entry), AML.T0064 (recon).
- Recommended action: quarantine, purge-and-reindex, or connector-credential rotation.

## Response

- Allowlist sources; provenance-stamp every chunk; make ingest a reviewed, logged pipeline with no direct vector-store writes.
- Quarantine-then-review off-allowlist or flagged documents; run the delegated pre-ingestion injection scan (detecting-indirect-prompt-injection) in the ingest path.
- On detection: identify and purge the poisoned chunks via provenance/traceback, re-index from clean sources, and rotate connector credentials if the write was unauthorized.
- Pair corpus hygiene with query-time indirect-prompt-injection controls as defense in depth; detection-based defenses alone are imperfect.
- For a poisoned agent memory store rather than a retrieval corpus, use detecting-ai-agent-memory-poisoning.
