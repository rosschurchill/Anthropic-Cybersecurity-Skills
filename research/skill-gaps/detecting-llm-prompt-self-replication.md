# Detecting LLM Prompt Self-Replication — research notes

- **Proposed slug:** detecting-llm-prompt-self-replication
- **ATLAS:** AML.T0061 LLM Prompt Self-Replication (Persistence; closely related to
  AML.T0057 LLM Data Leakage in the Morris II case study — **verify** ID)
- **Status:** research (not yet a skill)

## Defensive goal
Detect self-propagating prompts — "AI worms" (Morris II) — that inject instructions crafted so
a model reproduces the malicious prompt in its own output, which then flows into other
LLM/agent systems (RAG stores, email assistants, agent-to-agent handoffs) and re-executes,
spreading laterally and often carrying a secondary payload (jailbreak, data exfiltration).
The defensive goal is to catch the replication signal — input instructions appearing in
output, and the same adversarial payload recurring across connected LLM nodes — before it
establishes persistence in the knowledge base or agent mesh.

## Data sources / telemetry
- **LLM I/O trace logs** — paired prompt+completion per request (Langfuse, Arize Phoenix,
  Helicone). The core signal is *overlap between input instructions and generated output*.
- **Guardrail / scanner logs** — LLM Guard (PromptInjection, output scanners), Llama Guard /
  Prompt Guard, NeMo Guardrails rail hits on both input and output paths.
- **RAG / vector-store write logs** — what agent-generated content gets embedded and stored
  (self-replication persists by writing the worm into retrievable memory), plus retrieval
  logs showing the same poisoned chunk served to many downstream requests.
- **Agent orchestration / tool-call logs** — agent-to-agent messages, email-send actions, and
  inter-service calls where one agent's output becomes another's input (propagation edges).

## Detection logic / approach
1. **Input→output replication detector** — flag completions that reproduce injected
   instruction text or a known worm signature from their own input/context:
   ```
   # pseudo-rule
   sim = fuzzy_overlap(generated_output, detected_injection_span(input/context))
   if sim > tau and output contains imperative/role-override tokens
      ("ignore previous", "forward this", "include this prompt in your reply")
   -> flag self-replicating prompt (AML.T0061)
   ```
2. **Cross-node payload recurrence** — hash/embed suspected worm payloads and watch the same
   payload appear across distinct principals, RAG chunks, or agents within a short window
   (propagation = the same adversarial string spreading, not independent prompts).
3. **Replication into persistence** — alert when agent output that matches a worm signature is
   *written back* into a vector store or sent outbound (email/agent handoff), i.e. an output
   scanner hit on a storage/egress edge, which is how the worm survives.

Chain the output scanner (LLM Guard / Llama Guard / NeMo output rails) to gate every
storage/egress edge, so a replicated payload cannot be persisted or forwarded.

## Response / mitigation
Block/strip output that replicates injected instructions before it is stored or forwarded;
quarantine affected RAG chunks and purge the poisoned embeddings. Break propagation by
sanitizing retrieved context (treat retrieved/tool content as untrusted data, not
instructions — content/instruction separation), and require human approval on
output→storage and output→send edges. Rate-limit and isolate the originating principal/agent.
Deploy input *and* output prompt-injection scanners on every agent boundary; map the agent
mesh so blast radius is known. Reference OWASP LLM01 (prompt injection) and LLM02
(insecure output handling) hardening.

## Real tools
LLM Guard (PromptInjection + output scanners), Meta Llama Guard / Prompt Guard, NeMo
Guardrails, Rebuff, Lakera Guard; Langfuse / Arize Phoenix / Helicone (LLM I/O tracing);
Garak (LLM vulnerability scanner, used defensively to test replication/injection resistance);
vector-store (Pinecone/Weaviate/pgvector) write+retrieval logs.

## Draft frontmatter mappings
- atlas: [AML.T0061]
- nist_csf: [DE.CM-09, DE.AE-02, DE.AE-03, RS.MI-01, PR.PS-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-ai-model-prompt-injection-attacks

## Draft description (<=1024 chars)
Detects self-propagating prompts (AI worms such as Morris II) — injections crafted so an LLM
reproduces the malicious prompt in its output, which then spreads into connected LLM/agent
systems via RAG stores, email assistants and agent handoffs, often carrying a jailbreak or
data-leak payload. Uses paired LLM input/output traces (Langfuse, Arize Phoenix), input and
output guardrail scanners (LLM Guard, Llama Guard, NeMo Guardrails), and RAG write/retrieval
plus agent tool-call logs to catch input-to-output replication, cross-node payload recurrence,
and replication written back into persistence. Use when a prompt injection appears to spread
or self-replicate across agents or a RAG knowledge base. Keywords: AI worm, Morris II, prompt
self-replication, AML.T0061, RAG poisoning, agent propagation, output scanner, LLM Guard. Do
not use for single-shot prompt injection against one model - use
detecting-ai-model-prompt-injection-attacks.

## Key references
- MITRE ATLAS AML.T0061 LLM Prompt Self-Replication; case study AML.CS0024 Morris II worm
  RAG-based attack (verify ID): https://atlas.mitre.org/
- Cohen, Bitton, Nassi, "ComPromptMized / Morris II: self-replicating prompts against
  GenAI-powered applications" (2024) — verify exact title/venue
- OWASP LLM Top 10 — LLM01 Prompt Injection, LLM02 Insecure Output Handling: https://owasp.org/
- NIST AI 100-2 Adversarial ML taxonomy (GenAI / abuse): https://csrc.nist.gov/

## Open questions / scope boundaries
- Confirm AML.T0061 tactic placement (Persistence) and the related/folded technique in the
  Morris II case study (AML.T0057 LLM Data Leakage) — **verify** against live ATLAS.
- Input→output overlap threshold (tau) risks false positives on legitimate quoting/echoing;
  pair with injection-signature and egress-edge context to cut noise.
- Boundary with plain prompt injection: this skill owns the *replication/propagation* signal,
  not the first injection — cross-reference the sibling.
