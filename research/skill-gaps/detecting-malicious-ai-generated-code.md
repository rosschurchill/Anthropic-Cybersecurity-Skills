# Detecting Malicious AI-Generated Code — research notes

- **Proposed slug:** detecting-malicious-ai-generated-code
- **ATLAS:** AML.T0102 Generate Malicious Commands — (no folded-in techniques for this row)
- **Status:** research (not yet a skill)

## Defensive goal
Detect when an LLM, coding assistant, or autonomous agent in your development/agent workflow **produces** malicious or dangerous code or shell commands — destructive filesystem/OS commands (`rm -rf`, disk wipes, `dd`), reverse shells and C2 stagers, data-exfil snippets (curl/POST of env or secrets to external hosts), credential/secret harvesting, backdoors, obfuscated/encoded payloads, or living-off-the-land one-liners. This is **output-side** detection: the observable artifact is the generated command/code itself, reviewed before it executes or merges. ATLAS notes dynamically-generated commands are hard to signature because the surface constantly changes (e.g., APT28 LAMEHUG used a HuggingFace-hosted model to generate commands at runtime), and that generation prompts blend into normal traffic — so the defense sits at the output/execution boundary, not the prompt.

## Data sources / telemetry
- **Coding-assistant / agent output stream:** proposed diffs, file writes, and tool calls from Copilot/Cursor/Claude Code/agent frameworks; the exact shell commands an agent proposes before execution (pre-exec hook payloads).
- **Agent tool-call logs / LLM observability:** Langfuse, Arize Phoenix, or equivalent traces capturing generated tool arguments (especially `bash`/`exec`/`shell` tool inputs) and generated code blocks.
- **SAST / policy scanners run on generated code:** Semgrep, CodeQL, Bandit (Python), gosec, with rulesets tuned for destructive ops, subprocess/`os.system`/`eval`/`exec`, deserialization, network callbacks.
- **Secrets scanners on generated output:** gitleaks, TruffleHog, detect-secrets — catch hardcoded keys or exfil of existing secrets.
- **Pre-commit / pre-exec hooks:** command-string gates (destructive-command, force-push, supply-chain) that inspect what the agent is about to run.
- **EDR / process-creation telemetry:** when a generated command does reach a shell, process-create + outbound-connection events as a backstop.

## Detection logic / approach
- **Policy-gate the agent's shell tool-calls before execution:** parse the command string the agent proposes and block/flag destructive patterns (`rm -rf`, `mkfs`, `dd of=/dev/`, `shred`, `:(){ :|:& };:`), reverse-shell shapes (`bash -i >& /dev/tcp/`, `nc -e`, `python -c 'socket...'`), and exfil shapes (curl/wget POST of files/env to non-allowlisted hosts). Clause-split on `&& || ; | & ( )` and strip prose/heredocs so a leading `echo` can't launder the payload (same scar-class as supply-chain/force-push gates).
- **SAST on every AI-authored diff:** route generated code through Semgrep/CodeQL/Bandit **before** it merges; alert on subprocess/eval/deserialization/network-callback sinks that the human didn't ask for. Treat AI authorship as a risk tag that lowers the alert threshold.
- **Secrets + exfil correlation:** secrets scanner on the diff plus a rule for outbound-to-external-host code paths; flag generated code that reads `~/.aws`, `.env`, `~/.ssh`, token stores and transmits them.
- **Obfuscation heuristics:** flag generated code with high-entropy string blobs, `base64`/`hex`-decode-then-`exec`, dynamic import of attacker-controlled names — classic signature-evasion shapes ATLAS calls out.
- **Intent/anomaly:** compare generated artifact to the task ask (a "format a date" task that emits a network callback is anomalous); optionally an LLM-judge or guardrail model as a second reviewer. Baseline the agent's normal tool-call distribution; alert on first-time destructive/network tools.

## Response / mitigation
- Run the agent under least privilege in a sandbox; require human approval for destructive/network tool-calls; keep SAST + secrets + command-policy gates **fail-closed** in the pre-exec/pre-commit path. On detection: block the command/merge, surface the exact file:line and command string, quarantine the generated artifact, and review the triggering prompt/context for indirect prompt injection as the upstream cause. Never auto-approve a generated `--force`/`--no-verify`/gate-weakening command.

## Real tools
Semgrep, CodeQL, Bandit, gosec (SAST); gitleaks, TruffleHog, detect-secrets (secrets); Langfuse, Arize Phoenix (agent/LLM observability of tool-calls); pre-commit framework and command-string hooks; Falco / EDR (execution backstop); OpenAI/Anthropic/Llama-Guard-style guardrail or LLM-judge as a second reviewer. (Verify ruleset names before shipping.)

## Draft frontmatter mappings
- atlas: [AML.T0102]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, PR.PS-01, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-indirect-prompt-injection (the upstream cause) ; defending-llms-with-guardrails (input/output guardrails generally)

## Draft description (<=1024 chars)
Detects when an LLM, coding assistant, or autonomous agent produces malicious or dangerous code or shell commands in a dev/agent workflow: destructive OS commands, reverse shells, C2 stagers, data-exfil snippets, hardcoded-secret or credential-harvest code, backdoors, and obfuscated or encoded payloads. Output-side detection at the review/execution boundary, using SAST (Semgrep, CodeQL, Bandit), secrets scanners (gitleaks, TruffleHog), command-string policy gates on agent tool-calls, and LLM/agent observability traces. Use when hardening a coding assistant or agent that writes code or runs shell commands, reviewing AI-authored diffs, or policy-gating an agent's bash tool before execution. Keywords: malicious generated code, AI-generated command, destructive shell, reverse shell, data exfil snippet, SAST on agent output, agent tool-call policy, AML.T0102, LAMEHUG. Do not use for screening untrusted input that steers the model - use detecting-indirect-prompt-injection. Do not use for general input and output guardrail design - use defending-llms-with-guardrails.

## Key references
- https://atlas.mitre.org/techniques/AML.T0102 (verify path)
- https://d3fend.mitre.org/offensive-technique/attack/AML.T0102/
- APT28 / LAMEHUG campaign (HuggingFace-hosted model generating commands) — verify ATLAS case-study id
- OWASP LLM Top 10 — LLM02:2025 Insecure Output Handling (verify current numbering), LLM05 (excessive agency)
- Semgrep, CodeQL, Bandit rule docs; gitleaks / TruffleHog docs
- arXiv 2111.15039 — Living-Off-The-Land Command Detection (general command-line classification, not LLM-specific)

## Open questions / scope boundaries
- Confirm AML.T0102 tactic placement (AI Attack Staging per secondary sources) and LAMEHUG case-study id against atlas.mitre.org v5.6.0.
- Decide boundary with the upstream cause: this skill detects the *output*; the *why* (injected instruction) is detecting-indirect-prompt-injection. Cross-reference, don't merge.
- Open: how much to rely on an LLM-judge second reviewer vs deterministic SAST/policy, given judge evasion.
- Must stay defensive — detection rules and policy patterns only, no payload authoring.
