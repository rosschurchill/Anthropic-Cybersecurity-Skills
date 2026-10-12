# Detecting AI Agent Configuration Tampering — research notes

- **Proposed slug:** detecting-ai-agent-configuration-tampering
- **ATLAS:** AML.T0081 Modify AI Agent Configuration (tactic: Persistence) — folding in **AML.T0084 Discover AI Agent Configuration** (reconnaissance; incl. .001 Tool Definitions, .002 Activation Triggers) and **AML.T0083 Credentials from AI Agent Configuration** (Credential Access — harvesting secrets stored in the agent's own config/env). All part of the Oct-2025 MITRE/Zenity Labs agentic update. Related: AML.T0080 (memory/context state — separate row).
- **Status:** research (not yet a skill)

## Defensive goal
Detect three linked moves against an agent's **own configuration state**: (1) reconnaissance — an adversary enumerating the agent's system prompt, connected-tool manifest, knowledge sources, activation triggers, and settings (T0084); (2) tampering — modifying those config files to insert hidden instructions, add/rewrite tool definitions, redirect knowledge sources, or **disable safety controls / user-confirmation gates** so the change persists across sessions and across every agent sharing that config (T0081); and (3) credential harvesting — reading API keys, tokens, and connection secrets stored in the config/env the agent exposes (T0083). This is the *integrity + secret-exposure of the agent's configuration surface*, not the tool-call runtime boundary and not MCP server content.

## Data sources / telemetry
- **Config file integrity:** version control (git) + file-integrity monitoring (hashes, inotify/auditd watches) on system-prompt files, tool/MCP manifests (`mcp.json`, agent manifests, `.well-known`/connector configs), knowledge-source lists, model/settings files, `CLAUDE.md`/agent instruction files. Alert on any unversioned/out-of-band edit.
- **Config-read telemetry (recon):** access logs / auditd `open` events on config and manifest files; agent-dashboard/API calls that list tools, read the system prompt, or dump settings; LLM traces where the agent is *asked* to reveal its tools/instructions (T0084 via the agent itself).
- **Secrets-access logs (T0083):** process reads of `.env`, credential files, keychain/secret-manager fetches performed by or on behalf of the agent; env-var dumps; MCP/connector credential-store access.
- **Agent framework traces:** LangSmith / Langfuse / OpenTelemetry GenAI spans showing a config/settings mutation or a confirmation-gate being disabled; tool-manifest diff between runs.
- **Change provenance:** who/what process made the edit, under which session, triggered by which input.

## Detection logic / approach
1. **Integrity baseline + diff:** cryptographic hash and VCS state of every config/manifest/system-prompt file; alert on any change not made through the approved deploy path. Especially flag edits that *remove* a safety directive, *add* a tool, *disable a user-confirmation flag*, or redirect a knowledge/connector source.
2. **Recon pattern:** bursts of config/manifest reads, dashboard tool-enumeration, or model turns that output the full tool list / system prompt (T0084) — precursor signal; raise severity if followed by a config write.
3. **Credential exposure:** agent or its subprocess reading secret files / env beyond its known baseline, or config containing plaintext secrets (static scan) that were then read (T0083). Correlate with egress (secrets leaving the host).
4. **Out-of-band mutation:** config change whose provenance is an ingested/untrusted turn (prompt-injection-driven self-reconfiguration) rather than an operator deploy — the strongest signal.
5. **Correlation (DE.AE-03):** recon read -> config write -> safety flag off -> anomalous tool call, as a chain.

## Response / mitigation
- **Restore from VCS/known-good** immediately; revoke the tampered config; re-enable disabled confirmation/safety gates; RS.MI-01 containment (freeze the agent).
- **Rotate every credential** reachable from the config/env (assume T0083 succeeded once tampering is confirmed).
- **Harden (prevent):** config and manifests under version control, read-only at runtime, deployed only via a privileged path the agent cannot self-modify; secrets in a secret manager referenced by handle, never plaintext in config/env the agent can read; least-privilege file perms (PR.AA-05); signed/attested config; inventory every agent config (ID.AM-02).
- **Note the structural limit:** a PASS/integrity marker writable by the same identity the agent runs as is defeatable — genuine integrity needs a separate privileged runner or signer (mirror of the sentinel-deploy-gate trade-off).

## Real tools
Git + pre-commit / FIM (auditd file watches, inotifywait, Tripwire/AIDE, osquery file_events); OPA/Conftest or JSON-schema validation of manifests; secret scanners (gitleaks, trufflehog) on config; HashiCorp Vault / cloud secret managers (referenced-by-handle pattern); LangSmith / Langfuse / OpenTelemetry GenAI traces; Falco/Tetragon for runtime file-access and secrets-read events; Sigma rules on auditd open-events for config/`.env`.

## Draft frontmatter mappings
- atlas: [AML.T0081, AML.T0084, AML.T0083]
- nist_csf: [PR.PS-01, DE.CM-09, DE.AE-03, PR.AA-05, ID.AM-02, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): securing-agentic-ai-tool-invocation

## Draft description (<=1024 chars)
Detects tampering with an AI agent's own configuration (ATLAS AML.T0081 Modify AI Agent Configuration) plus the recon (AML.T0084 Discover AI Agent Configuration) and credential harvesting (AML.T0083 Credentials from AI Agent Configuration) — out-of-band edits to system-prompt files, tool/MCP manifests and settings that insert hidden instructions, add tools, or disable confirmation gates, plus reads of secrets in that config or env. Works by file-integrity monitoring and VCS diffing of manifests, flagging edits that remove safety directives or disable confirmation flags, detecting config-enumeration recon, and watching secrets-access logs for credential reads beyond baseline. Use when hunting agent config tampering, unauthorized system-prompt or tool-manifest changes, disabled safety gates, or secret exposure in agent config. Keywords: AML.T0081, AML.T0084, AML.T0083, system prompt tampering, tool manifest, mcp.json. Do not use for runtime tool-call policy - use securing-agentic-ai-tool-invocation.

## Key references
- MITRE ATLAS AML.T0081 Modify AI Agent Configuration; AML.T0084 Discover AI Agent Configuration (.001 Tool Definitions, .002 Activation Triggers); AML.T0083 Credentials from AI Agent Configuration (atlas.mitre.org) — verify names/IDs
- CSA research note: ATLAS Agentic Gap Analysis (Oct-2025 MITRE/Zenity Labs techniques)
- Anthropic Model Context Protocol security guidance (manifest/connector trust, config integrity)
- OWASP Agentic AI threats taxonomy (agent configuration / tooling integrity); OWASP LLM Top 10 (sensitive info disclosure)
- NIST AI RMF; NIST SP 800-53 config-management (CM) and SI file-integrity controls

## Open questions / scope boundaries
- Boundary vs securing-agentic-ai-tool-invocation: that governs the *runtime tool-call boundary/policy*; this governs *config/manifest integrity and config-stored secrets at rest*. Keep briefs disjoint.
- Boundary vs auditing-mcp-servers-for-tool-poisoning: that audits the *content/behaviour of an MCP server/tool*; this detects *local edits to the agent's manifest/config and secret exposure*. Note the handoff.
- Boundary vs detecting-ai-agent-memory-poisoning: config state (T0081) vs memory/context state (T0080) — separate rows, do not merge.
- Structural limit: self-writable integrity markers are bypassable; the skill should recommend an external signer and say so plainly.
- Verify AML.T0083 exact name ("Credentials from AI Agent Configuration") and AML.T0084 sub-technique IDs against ATLAS v5.6.0 — DNS blocked direct fetch during research; names are task-supplied and consistent with ATLAS convention but UNVERIFIED on the primary page.
