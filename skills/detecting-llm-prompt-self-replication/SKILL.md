---
name: detecting-llm-prompt-self-replication
description: 'Detects self-propagating prompts (AI worms such as Morris II): injections crafted so an LLM reproduces the malicious prompt in its own output, which then spreads into connected LLM and agent systems via RAG stores, email assistants, and agent handoffs, often carrying a jailbreak or data-leak payload. Uses paired LLM input and output traces (Langfuse, Arize Phoenix), input and output guardrail scanners (LLM Guard, Llama Guard, NeMo Guardrails), and RAG write and retrieval plus agent tool-call logs to catch input-to-output replication, cross-node payload recurrence, and replication written back into persistence. Use when a prompt injection appears to spread or self-replicate across agents or a RAG knowledge base. Keywords: AI worm, Morris II, prompt self-replication, AML.T0061, RAG poisoning, agent propagation, output scanner, LLM Guard, OWASP LLM01, OWASP LLM02. Do not use for single-shot prompt injection against one model - use detecting-ai-model-prompt-injection-attacks.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm
- prompt-self-replication
- ai-worm
- rag
- ai-agent
- output-scanner
- prompt-injection
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0061
---
# Detecting LLM Prompt Self-Replication

## Overview

Prompt self-replication is the LLM analogue of a worm. An adversary injects instructions crafted so the model **reproduces the malicious prompt in its own output**; that output then flows into other LLM or agent systems — RAG knowledge bases, email assistants, agent-to-agent handoffs — where it re-executes and spreads laterally, often carrying a secondary payload (a jailbreak or a data-exfiltration instruction). MITRE ATLAS catalogs this as **AML.T0061 (LLM Prompt Self-Replication)**, a persistence technique. The canonical demonstration is the Morris II / ComPromptMized self-replicating prompt (Cohen, Bitton, and Nassi, 2024).

The defensive goal is to catch the **replication signal** — injected instructions appearing in output, and the same adversarial payload recurring across connected nodes — before the worm establishes persistence in a vector store or agent mesh. This skill owns the *replication and propagation* signal; the initial single-shot injection against one model belongs to detecting-ai-model-prompt-injection-attacks. It maps to OWASP LLM Top 10 **LLM01 (Prompt Injection)** and **LLM02 (Insecure Output Handling)**.

## When to Use

- A prompt injection appears to **spread**: the same adversarial text shows up across multiple agents, principals, or RAG chunks.
- Agent-generated output is being written back into a vector store or sent outbound (email, agent handoff) and you need to gate those edges.
- You are instrumenting a multi-agent or RAG system and want to detect input-to-output replication.
- You are investigating a RAG knowledge base suspected of being poisoned with a recurring payload.
- You are mapping propagation blast radius across an agent mesh.

## Prerequisites

- Paired LLM I/O trace logs (prompt + completion per request) from Langfuse, Arize Phoenix, or Helicone — the core signal is overlap between input/context instructions and generated output.
- Input and output guardrail/scanner logs: LLM Guard (PromptInjection and output scanners), Meta Llama Guard / Prompt Guard, NeMo Guardrails rail hits.
- RAG / vector-store write and retrieval logs (Pinecone, Weaviate, pgvector): what agent-generated content gets embedded and which chunks are served downstream.
- Agent orchestration / tool-call logs: agent-to-agent messages, email-send actions, inter-service calls (the propagation edges).
- Python 3.9+ for the correlation helpers below.

## Workflow

### 1. Instrument every agent boundary
Ensure each agent logs its input (including retrieved context and tool output), its completion, and every storage/egress action. Treat retrieved and tool content as untrusted data, not instructions.

### 2. Input-to-output replication detector
Flag completions that reproduce an injected instruction span from their own input or context, especially when the echoed text carries imperative/role-override or propagation verbs.

```python
import re
from difflib import SequenceMatcher

PROPAGATION_MARKERS = [
    "ignore previous", "ignore all previous", "forward this", "send this to",
    "include this prompt in your reply", "copy these instructions", "when you reply, repeat",
]

def replication_score(input_context, completion, tau=0.6):
    """High fuzzy overlap between a suspected injection span and the output,
    plus propagation markers, signals a self-replicating prompt."""
    sim = SequenceMatcher(None, input_context.lower(), completion.lower()).ratio()
    markers = [m for m in PROPAGATION_MARKERS if m in completion.lower()]
    return {"overlap": round(sim, 3), "markers": markers,
            "suspected_replication": sim > tau and bool(markers)}  # tau: calibrate vs legit quoting
```

Pair this with an injection-signature hit (LLM Guard PromptInjection, Prompt Guard) so legitimate quoting or echoing does not trip the alert on overlap alone.

### 3. Cross-node payload recurrence
Hash or embed suspected worm payloads and watch the same payload appear across distinct principals, RAG chunks, or agents within a short window. Independent benign prompts do not recur verbatim across nodes; a worm does.

```python
import hashlib, collections

def payload_recurrence(events, window_min=60, min_nodes=3):
    """events: [{payload, node, ts_min}]; node = principal/agent/rag_chunk id."""
    seen = collections.defaultdict(set)
    for e in events:
        h = hashlib.sha256(e["payload"].strip().lower().encode()).hexdigest()
        seen[h].add(e["node"])
    return [{"payload_hash": h, "node_count": len(nodes), "propagating": len(nodes) >= min_nodes}
            for h, nodes in seen.items() if len(nodes) >= min_nodes]
```

### 4. Replication-into-persistence detector
The worm survives by being written back. Alert when agent output that matches a replication signature is embedded into a vector store or sent outbound — an output-scanner hit on a **storage or egress edge**.

### 5. Chain output scanners on every write/send edge
Gate every storage and egress edge with an output scanner (LLM Guard output scanners, Llama Guard, NeMo output rails) so a replicated payload cannot be persisted or forwarded. Require human approval on output-to-storage and output-to-send edges for untrusted-origin content.

### 6. Map propagation and contain
Reconstruct the propagation graph from tool-call and RAG logs to establish blast radius, then quarantine and purge (see Response).

## Key Concepts

- **Self-replication vs single-shot injection.** Single-shot injection subverts one response; self-replication makes the output *carry the injection onward*. This skill owns the recurrence/propagation signal.
- **Propagation edge.** Any point where one agent output becomes another agent input: a RAG write, an email send, an agent-to-agent handoff.
- **Persistence via RAG.** Embedding worm text into a retrievable store means it is served to many future requests — the worm's foothold.
- **Content/instruction separation.** The structural defense: retrieved and tool-returned content must be processed as data, never executed as instructions.
- **Overlap false positives.** Legitimate summarization and quoting also echo input; require an injection signature or propagation marker alongside overlap.

## Tools & Systems

| Tool / system | Role |
|---------------|------|
| Langfuse, Arize Phoenix, Helicone | Paired LLM input/output tracing |
| LLM Guard | Input PromptInjection scanner and output scanners on write/send edges |
| Meta Llama Guard / Prompt Guard | Input and output safety classification |
| NeMo Guardrails | Input and output rails on agent boundaries |
| Rebuff, Lakera Guard | Additional prompt-injection detection |
| Garak | Defensive testing of replication/injection resistance |
| Vector stores (Pinecone, Weaviate, pgvector) | Write and retrieval logs for persistence detection |

## Detection Queries

```kusto
// Input-to-output replication with propagation markers
LLMTraces
| where OutputInjectionScore > 0.7 and InputOutputOverlap > 0.6
| where Completion has_any ("ignore previous","forward this","include this prompt")
| project Timestamp, Principal, AgentId, InputOutputOverlap, OutputInjectionScore
```

```kusto
// Same payload recurring across many nodes within an hour
LLMTraces
| where Timestamp > ago(1h)
| summarize nodes=dcount(AgentId), principals=dcount(Principal) by PayloadHash
| where nodes >= 3
| order by nodes desc
```

```kusto
// Replicated payload hitting a storage or egress edge
AgentActions
| where ActionType in ("vector_store_write","email_send","agent_handoff")
| where OutputScannerHit == true
| project Timestamp, AgentId, ActionType, TargetNode, PayloadHash
```

## Common Scenarios

- **Email-assistant worm:** a crafted email instructs the assistant to reply with the same instructions, which reach the next recipient's assistant and re-execute.
- **RAG knowledge-base poisoning:** agent output containing the worm is embedded; later retrievals serve the poisoned chunk to many downstream requests.
- **Agent-mesh propagation:** one agent's output becomes another's input across a tool-call graph, carrying a secondary data-exfiltration payload.

## Output Format

Report per finding:
- Signal: input-to-output replication, cross-node recurrence, or replication-into-persistence.
- Payload hash/signature, overlap score, propagation markers, and the set of affected nodes (principals, agents, RAG chunks).
- The storage/egress edges hit and whether human approval was in place.
- ATLAS mapping: AML.T0061 (LLM Prompt Self-Replication); OWASP LLM01 / LLM02.
- Propagation graph and estimated blast radius.

## Response

- Block or strip output that replicates injected instructions before it is stored or forwarded.
- Quarantine affected RAG chunks and purge the poisoned embeddings.
- Sanitize retrieved context (content/instruction separation) and require human approval on output-to-storage and output-to-send edges.
- Rate-limit and isolate the originating principal/agent; deploy input and output injection scanners on every agent boundary.
- Map the agent mesh so blast radius is known, and re-test replication resistance (for example with Garak) after hardening.
