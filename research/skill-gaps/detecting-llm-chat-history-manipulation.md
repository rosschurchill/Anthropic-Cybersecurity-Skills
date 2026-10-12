# Detecting LLM Chat History Manipulation — research notes

- **Proposed slug:** detecting-llm-chat-history-manipulation
- **ATLAS:** AML.T0092 Manipulate User LLM Chat History — plus folded-in AML.T0094 Delay Execution of LLM Instructions
- **Status:** research (not yet a skill)

## Defensive goal
Detect tampering with the **stored conversation history / session state** of an LLM application that alters later model behaviour or conceals adversary activity. Two linked shapes: (1) **history manipulation (AML.T0092)** — an adversary with the victim's backend auth tokens or direct chat-interface access deletes/edits prior messages or creates new threads to hide injected prompts or persistent behavioural changes (desktop clients often render history only once at open, so injected turns go unseen); (2) **delayed/"sleeper" instructions (AML.T0094)** — instructions planted in history that fire only on a future trigger (a keyword or the *next* interaction), evading same-turn prompt-injection controls (anchor: AML.CS0038, Gemini Workspace-extension call postponed to the next turn). Defensive stance: the conversation store must be **server-authoritative and tamper-evident**, and history must be screened for latent trigger-gated instructions.

## Data sources / telemetry
- **Conversation/session store writes:** append/edit/delete events on the message table or session document (DB audit log, change-data-capture), with actor identity, timestamp, and source IP/token.
- **Server-side history integrity records:** per-message hash chain / HMAC, monotonic sequence numbers, `created_at` immutability, soft-delete flags (never hard delete).
- **Auth/session telemetry:** backend token issuance and reuse, session-token theft indicators, anomalous access to another user's session (horizontal access), API calls that mutate history out-of-band from the chat UI.
- **LLM observability traces (Langfuse / Arize Phoenix):** the exact message array sent to the model each turn vs the canonical stored history — divergence = client-injected or out-of-band turns; tool-call traces showing a tool fired on a turn with no corresponding user request.
- **Client vs server state diff:** what the client renders vs what the server holds (catches the "rendered once at open" blind spot).

## Detection logic / approach
- **Hash-chain / sequence verification:** maintain a server-side hash chain over messages (each message hashes prior-hash + content + role + ts). On load and before each model call, recompute; a broken chain, a reordered sequence, or an edited-but-same-id message = tamper alert. Edits/deletes must be append-only revisions, never in-place.
- **Out-of-band mutation detection:** alert when a message is created/edited/deleted by an actor, token, or code path that is **not** the live chat turn flow (e.g., a direct DB/API write, a different session token, or a write with no corresponding inbound user request). Correlate with session-token-theft signals.
- **Injected/hidden-turn detection:** diff the message array actually sent to the model against canonical stored history; flag turns present in the prompt but absent from (or differing from) the store, and turns with roles that don't match their origin (a `user`/`system` turn written by a tool path).
- **Delayed-instruction ("sleeper") screening:** scan history content for trigger-gated imperatives — "when the user next asks about X, do Y", "on the next turn, call tool Z", "if you see keyword K, then…", or instructions whose execution is explicitly deferred. Flag any stored turn that conditions a privileged tool-call or data access on a *future* event — this is the AML.T0094 same-turn-control bypass. Re-screen history, not just the live input, because the payload was planted earlier.
- **Behavioural-drift correlation:** a tool invocation or policy-relevant action on a turn whose current user input does not request it, especially pointing back to an older history entry, indicates a fired sleeper.

## Response / mitigation
- Make the conversation store **server-authoritative**: never trust client-supplied history; reconstruct the model prompt from the signed server record each turn. Append-only/soft-delete with hash-chain integrity; scope session tokens tightly and detect reuse/theft. Apply prompt-injection controls to *retrieved history* as untrusted context, and make same-turn tool restrictions **persist across turns** when any untrusted content ever entered the session (defeats the deferral bypass). On detection: invalidate the session, restore history to last-verified state, revoke/rotate the implicated token, and audit any tool-calls the sleeper may have fired.

## Real tools
Langfuse, Arize Phoenix (prompt vs stored-history trace diffing); application DB audit logs / CDC (Debezium) for store-write provenance; HMAC/hash-chain integrity in the app layer; session/token-theft detection in IdP logs; guardrail/LLM-judge screening of retrieved history for deferred-instruction patterns. (Verify product specifics before shipping.)

## Draft frontmatter mappings
- atlas: [AML.T0092, AML.T0094]
- nist_csf: [DE.AE-02, DE.AE-03, DE.CM-09, PR.PS-01, PR.PS-02, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-indirect-prompt-injection (same-turn injected input) ; defending-llms-with-guardrails

## Draft description (<=1024 chars)
Detects tampering with an LLM application's stored conversation history and session state that alters later model behaviour or hides adversary activity: edited, deleted, reordered, or injected prior turns written out-of-band (via stolen backend tokens or direct store access), and time-delayed "sleeper" instructions planted in history that fire on a future keyword or the next interaction to bypass same-turn prompt-injection controls. Uses server-authoritative history, hash-chain and sequence integrity, conversation-store write audit logs, and observability traces that diff the prompt sent to the model against canonical stored history. Use when hardening the session/conversation store of a chat or agent product, or when a tool fired or behaviour changed with no matching user request. Keywords: chat history tampering, session state integrity, sleeper instruction, delayed execution, server-authoritative history, hash chain, out-of-band message edit, AML.T0092, AML.T0094. Do not use for screening untrusted input or documents arriving in the current turn - use detecting-indirect-prompt-injection.

## Key references
- https://atlas.mitre.org/techniques/AML.T0092 (verify path) ; AML.T0094
- https://d3fend.mitre.org/offensive-technique/attack/AML.T0092/ and /AML.T0094/
- AML.CS0038 — delayed Gemini Workspace-extension invocation case study (verify id)
- AML.CS0036 (AiKatz, attacking LLM desktop apps) and AML.CS0021 (ChatGPT conversation exfiltration) — verify ids
- OWASP LLM Top 10 — LLM01 Prompt Injection, LLM05 Excessive Agency (verify current numbering)

## Open questions / scope boundaries
- Confirm AML.T0092 / T0094 tactic (Defense Evasion per secondary sources) and the CS0038/CS0036/CS0021 ids against atlas.mitre.org v5.6.0.
- Boundary: this is about the *stored* history and *deferred* execution. Screening untrusted content arriving in the current turn → detecting-indirect-prompt-injection; general guardrails → defending-llms-with-guardrails.
- Open: deferred-instruction screening overlaps with prompt-injection screening; decide the clean split (this skill owns the "planted earlier, fires later" + store-integrity half).
- Open: feasibility of hash-chain integrity in products that allow legitimate user message editing/branching — need a revision model that distinguishes sanctioned edits from tampering.
