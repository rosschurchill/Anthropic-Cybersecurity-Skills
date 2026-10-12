---
name: detecting-llm-chat-history-manipulation
description: 'Detects tampering with an LLM application stored conversation history and session state that alters later model behaviour or hides adversary activity: edited, deleted, reordered, or injected prior turns written out-of-band via stolen backend tokens or direct store access, and time-delayed sleeper instructions planted in history that fire on a future keyword or the next turn to bypass same-turn prompt-injection controls. Uses server-authoritative history, hash-chain and sequence integrity, store write audit logs, and observability traces that diff the prompt sent to the model against stored history. Use when hardening the session store of a chat or agent product, or when a tool fired with no matching user request. Keywords: chat history tampering, session integrity, sleeper instruction, delayed execution, hash chain, out-of-band edit, AML.T0092, AML.T0094, OWASP LLM01. Do not use for screening untrusted input arriving in the current turn - use detecting-ai-model-prompt-injection-attacks.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm
- chat-history
- session-integrity
- hash-chain
- sleeper-instruction
- audit-log
- observability
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0092
- AML.T0094
---
# Detecting LLM Chat History Manipulation

## When to Use

- You operate a chat or agent product with a persistent conversation/session store and need to detect edits, deletions, reordering, or injection of prior turns.
- A tool fired or model behaviour changed on a turn whose current user input did not request it, and you suspect an instruction planted earlier.
- You are hardening the session store against out-of-band writes performed with stolen backend tokens or direct database/API access.
- You need to catch sleeper instructions: imperatives planted in history that fire only on a future keyword or the next interaction, evading same-turn controls.

This skill owns the stored history and deferred execution problem. For screening untrusted input or documents that arrive in the current turn, use detecting-ai-model-prompt-injection-attacks.

## Prerequisites

- Read access to conversation/session store write events (DB audit log or change-data-capture such as Debezium) with actor identity, timestamp, and source IP/token.
- Authority to add a server-side per-message hash chain / HMAC and monotonic sequence numbers to the message model.
- LLM observability (Langfuse, Arize Phoenix) capturing the exact message array sent to the model each turn.
- IdP/session telemetry for token issuance, reuse, and theft indicators.

## Workflow

1. **Make history server-authoritative.** Reconstruct the model prompt from the signed server record each turn; never trust client-supplied history. Many desktop clients render history only once at open, so an injected turn goes unseen unless the server is the source of truth.
2. **Maintain a hash chain over messages.** Each message hashes prior-hash plus content plus role plus timestamp. Recompute on load and before each model call. A broken chain, a reordered sequence, or an edited-but-same-id message is a tamper alert. Edits and deletes must be append-only revisions or soft-deletes, never in-place.
3. **Detect out-of-band mutation.** Alert when a message is created, edited, or deleted by an actor, token, or code path that is not the live chat turn flow, such as a direct DB/API write, a different session token, or a write with no corresponding inbound user request. Correlate with session-token-theft signals.
4. **Detect injected or hidden turns.** Diff the message array actually sent to the model against canonical stored history. Flag turns present in the prompt but absent from or differing from the store, and turns with roles that do not match their origin (a user or system turn written by a tool path).
5. **Screen history for sleeper instructions.** Scan stored content, not just the live input, for trigger-gated imperatives: when the user next asks about X do Y, on the next turn call tool Z, if you see keyword K then act. Flag any stored turn that conditions a privileged tool-call or data access on a future event.
6. **Correlate behavioural drift.** A tool invocation or policy-relevant action on a turn whose current input does not request it, especially pointing back to an older history entry, indicates a fired sleeper.

## Key Concepts

- **Manipulate chat history (AML.T0092):** an adversary with backend auth or direct store access alters prior messages or threads to hide injected prompts or persistent behavioural changes.
- **Delay execution of instructions (AML.T0094):** instructions planted in history fire on a future trigger, so same-turn prompt-injection controls never see them in the turn that matters. A documented pattern postponed a workspace-extension call to the next turn.
- **Server-authoritative history:** the canonical, integrity-protected record the server reconstructs the prompt from. The defeat for both techniques starts here.
- **Persist same-turn restrictions:** once any untrusted content has entered a session, keep same-turn tool restrictions in force across subsequent turns, which defeats the deferral bypass.
- **Sanctioned-edit distinction:** products that allow legitimate message editing or branching need a revision model that records edits as new revisions, so a sanctioned edit and a tamper both appear, but only the unsanctioned path alerts.

## Tools & Systems

| Layer | Tool | Signal |
|-------|------|--------|
| Store writes | DB audit log / CDC (Debezium) | Who/what wrote, edited, or deleted a message |
| Integrity | App-layer HMAC / hash chain | Broken chain, reorder, edited-but-same-id |
| Prompt vs store | Langfuse, Arize Phoenix | Prompt array diverges from canonical history |
| Session | IdP logs | Token reuse, horizontal access, theft |
| Screening | Guardrail / LLM-judge over stored history | Deferred-instruction patterns |

## Detection Queries

Server-side hash chain and verification:

```python
import hashlib

def link(prev_hash, msg):
    payload = f"{prev_hash}|{msg['role']}|{msg['content']}|{msg['created_at']}"
    return hashlib.sha256(payload.encode()).hexdigest()

def verify_chain(messages):
    prev = "GENESIS"
    for i, m in enumerate(messages):
        expect = link(prev, m)
        if m.get("chain_hash") != expect:
            return {"ok": False, "break_at": i, "msg_id": m.get("id")}
        if i and m["seq"] != messages[i-1]["seq"] + 1:
            return {"ok": False, "reorder_at": i, "msg_id": m.get("id")}
        prev = expect
    return {"ok": True}
```

Out-of-band write detection over the store audit log (KQL-style; verify schema):

```kusto
ConversationStoreWrites
| where Operation in ("update","delete","insert")
| join kind=leftouter (ChatTurnFlow | project MessageId, TurnToken) on MessageId
| where isempty(TurnToken)                       // no live turn produced this write
      or ActorToken != TurnToken                 // written by a different token
| project TimeGenerated, SessionId, MessageId, Operation, Actor, ActorToken, SourceIp
```

Prompt-vs-store divergence from observability traces:

```python
def divergence(prompt_array, stored_history):
    stored = {(m["role"], m["content"]) for m in stored_history}
    return [t for t in prompt_array if (t["role"], t["content"]) not in stored]
```

Sleeper-instruction screen over stored history (patterns to review, not to auto-execute):

```python
import re
SLEEPER = [
    r"when (the user|you) next", r"on the next (turn|message|interaction)",
    r"if you (see|receive|encounter) [\"']?\w+[\"']?.{0,40}\b(then|call|run|send)\b",
    r"later,? (call|invoke|run|execute)\b", r"remember to .{0,40}\bwhen\b",
]
def scan_history(messages):
    hits = []
    for m in messages:
        for pat in SLEEPER:
            if re.search(pat, m["content"], re.I):
                hits.append({"msg_id": m.get("id"), "pattern": pat})
    return hits
```

## Common Scenarios

- **Out-of-band edit:** a prior assistant turn is rewritten via a direct API call with a token that did not originate the turn. Audit-log rule and hash-chain break both fire.
- **Injected turn:** the prompt array sent to the model contains a system turn absent from the store. Divergence check fires.
- **Sleeper tool-call:** history contains on the next turn, call the payments tool; the next innocuous user message triggers a transfer. Sleeper screen flagged it at ingest; behavioural-drift correlation confirms the fire.
- **Reorder to hide:** messages are reordered to bury an injected instruction. Sequence check fires.
- **Session theft:** another user session is accessed horizontally and its history edited. IdP reuse signal plus out-of-band write correlate.

## Output Format

Report each finding with:

- Session id, message id(s), and the signal: chain break, reorder, out-of-band write, prompt-vs-store divergence, or sleeper pattern.
- Actor, token, source IP, and whether a live turn produced the write.
- For a fired sleeper: the older history entry and the tool-call or action it drove.
- ATLAS mapping: AML.T0092 (history manipulation), AML.T0094 (delayed execution).
- Last-verified chain state to restore to.

## Response

- Invalidate the session, restore history to the last-verified state, and revoke/rotate the implicated token.
- Keep the store append-only / soft-delete with hash-chain integrity; scope session tokens tightly and detect reuse.
- Treat retrieved history as untrusted context and keep same-turn tool restrictions in force across turns once untrusted content has entered the session.
- Audit every tool-call a sleeper may have fired and reverse any unauthorized action.
- For current-turn injected input or documents, hand off to detecting-ai-model-prompt-injection-attacks.
