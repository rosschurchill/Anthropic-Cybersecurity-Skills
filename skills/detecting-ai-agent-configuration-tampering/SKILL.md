---
name: detecting-ai-agent-configuration-tampering
description: 'Detects tampering with an AI agent own configuration (ATLAS AML.T0081 Modify AI Agent Configuration, with recon AML.T0084 and credential harvesting AML.T0083): out-of-band edits to system-prompt files, tool and MCP manifests, and settings that insert hidden instructions, add tools, or disable confirmation gates, plus reads of secrets in that config or env. Works by file-integrity monitoring and VCS diffing of manifests, flagging edits that remove safety directives or disable confirmation flags, detecting config-enumeration recon, and watching secrets-access logs for credential reads beyond baseline. Use when hunting agent config tampering, unauthorized system-prompt or tool-manifest changes, disabled safety gates, or secret exposure in agent config. Keywords: AML.T0081, AML.T0084, AML.T0083, system prompt tampering, tool manifest, mcp.json, file integrity monitoring. Do not use for the runtime tool-call policy boundary - use securing-agentic-ai-tool-invocation.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- ai-agent
- configuration-integrity
- file-integrity-monitoring
- mcp
- secrets-exposure
- persistence
- system-prompt
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0081
- AML.T0084
- AML.T0083
---
# Detecting AI Agent Configuration Tampering

## When to Use

- A system-prompt file, tool or MCP manifest, knowledge-source list, or settings file changed outside the approved deploy path.
- You are hunting hidden instructions inserted into an agent config, added or rewritten tool definitions, or a disabled user-confirmation / safety gate that persists across sessions.
- An agent was asked to reveal its own tools, instructions, or settings, or you see bursts of config / manifest reads (reconnaissance).
- The agent or a subprocess read `.env`, a credential file, or a secret-manager entry beyond its known baseline, or config contains plaintext secrets.
- You are inventorying agent configurations and want integrity baselines in place.

This skill owns the integrity and secret-exposure of the agent's own configuration surface at rest. The runtime tool-call policy boundary is the sibling securing-agentic-ai-tool-invocation; auditing the behavior of an MCP server or tool is a separate concern.

## Prerequisites

- Version control (git) over every config / manifest / system-prompt file, plus file-integrity monitoring (hashes, auditd or inotify watches, Tripwire/AIDE, osquery `file_events`) on them.
- Access-log / auditd `open` telemetry on config and manifest files (`mcp.json`, agent manifests, connector configs, `CLAUDE.md` or equivalent instruction files, model/settings files).
- Secrets-access telemetry: process reads of `.env` and credential files, keychain or secret-manager fetches, env-var dumps, and MCP/connector credential-store access.
- Agent framework traces (Langfuse, LangSmith, OpenTelemetry GenAI spans) that show a config mutation, a confirmation gate being disabled, or a tool-manifest diff between runs.
- Change-provenance data: which process made an edit, under which session, triggered by which input.

## Workflow

1. **Baseline.** Record a cryptographic hash and VCS state of every config, manifest, and system-prompt file, and inventory every agent configuration (ID.AM-02).
2. **Integrity diff.** Alert on any change not made through the approved deploy path. Raise severity for edits that remove a safety directive, add a tool, disable a confirmation flag, or redirect a knowledge/connector source.
3. **Recon detection.** Flag bursts of config/manifest reads, dashboard tool-enumeration, or model turns that output the full tool list or system prompt. This is a precursor; escalate if a config write follows.
4. **Credential exposure.** Static-scan config for plaintext secrets, and watch for the agent or its subprocess reading secret files or env beyond baseline. Correlate with egress (secrets leaving the host).
5. **Out-of-band provenance.** The strongest signal is a config change whose provenance is an ingested or untrusted turn (prompt-injection-driven self-reconfiguration) rather than an operator deploy.
6. **Chain correlation (DE.AE-03).** Link recon read, then config write, then safety flag off, then anomalous tool call as a single chain.

## Key Concepts

- **The config is the persistence surface.** A hidden instruction, an added tool, or a disabled confirmation gate written into config persists across sessions and across every agent sharing that config — far more durable than a single-turn injection.
- **Three linked moves.** Reconnaissance (enumerate system prompt, tools, triggers, settings), tampering (edit those files), and credential harvesting (read secrets in the config/env). They often occur as a chain; detecting the chain is higher confidence than any single event.
- **Safety-gate removal is the high-value edit.** An edit that disables a user-confirmation flag or strips a safety directive is the one most likely to enable downstream abuse; weight it heavily.
- **Out-of-band is the discriminator.** Operators change config through a deploy path. A change whose provenance is an untrusted model turn is self-reconfiguration driven by injection.
- **Structural limit, stated plainly.** A PASS or integrity marker writable by the same identity the agent runs as is defeatable. Genuine integrity needs a separate privileged runner or signer that the agent cannot modify. Document this rather than claiming the marker is authoritative.

## Tools & Systems

| Role | Tools |
|------|-------|
| VCS + file integrity | git + pre-commit, auditd, inotifywait, Tripwire/AIDE, osquery `file_events` |
| Manifest validation | OPA / Conftest, JSON-schema validation |
| Secret scanning | gitleaks, trufflehog |
| Secret storage (prevent) | HashiCorp Vault, cloud secret managers (reference-by-handle) |
| Runtime file/secret access | Falco, Tetragon/eBPF, Sigma rules on auditd open-events |
| Tracing | Langfuse, LangSmith, OpenTelemetry GenAI spans |

## Detection Queries

File-integrity baseline and out-of-band diff, flagging high-value edits (defensive; tune patterns):

```python
import hashlib, re

SAFETY_REMOVED = re.compile(
    r"(require[_ ]?confirmation|human[_ ]?in[_ ]?the[_ ]?loop|"
    r"needs?[_ ]?approval|safety|guardrail)", re.IGNORECASE)

def baseline(paths):
    return {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in paths}

def diff_configs(prev, curr, approved=()):  # approved: paths changed via deploy
    # prev/curr: {path: sha256}. approved: paths changed through the deploy path.
    return [{"path": p, "out_of_band": True}
            for p, h in curr.items()
            if prev.get(p) != h and p not in approved]

def classify_edit(before_text, after_text):
    removed_safety = bool(SAFETY_REMOVED.search(before_text)) and not \
                     bool(SAFETY_REMOVED.search(after_text))
    added_tool = ('"tools"' in after_text and after_text.count('"tools"') and
                  after_text.count("name") > before_text.count("name"))
    return {"removed_safety_directive": removed_safety, "added_tool": added_tool}
```

Sigma-style rule for auditd reads of agent config / `.env` (verify field names for your pipeline).
This rule assumes a pipeline that **merges the auditd SYSCALL and PATH records into one event** —
auditbeat, the Elastic auditd module, or auditd `-k` keys plus a correlating forwarder. On raw,
unmerged auditd, `name` (a PATH-record field) and `exe` (a SYSCALL-record field) arrive in separate
records and the `not filter_known` clause can never match. The allowlist must also cover the agent
runtime itself, which reads `mcp.json` and `CLAUDE.md` on every launch — without that, the rule
alerts on baseline behaviour despite its title:

```yaml
title: Agent config or secret file read outside baseline
logsource:
  product: linux
  service: auditd       # requires SYSCALL+PATH merged into a single event (see note above)
detection:
  open_config:
    type: 'PATH'
    name:
      - '*/mcp.json'
      - '*/CLAUDE.md'
      - '*.env'
      - '*/agent-manifest*'
  filter_known:
    exe:
      - '/usr/bin/approved-deploy'   # verify/tune allowlist of expected readers
      - '*/claude'                   # the agent runtime's own binary - reads config every launch
      - '*/node'                     # adjust to the interpreter/comm your agent actually runs as
  condition: open_config and not filter_known
level: high
```

Recon burst detection on config-read access logs (KQL-style; illustrative fields):

```kql
ConfigAccessLogs
| where file_path has_any ("mcp.json", "system_prompt", "agent-manifest", ".env")
| summarize reads = count(), files = dcount(file_path) by principal, bin(TimeGenerated, 5m)
| where reads > 20 or files > 5          // verify/tune thresholds
| project TimeGenerated, principal, reads, files
```

## Common Scenarios

- **Hidden-instruction insertion.** An out-of-band edit appends a directive to the system-prompt file. Signal: integrity diff not through deploy path, instruction added.
- **Tool-manifest expansion.** A new tool definition appears in `mcp.json` between runs. Signal: manifest diff adding a tool; escalate if the tool reaches sensitive capability.
- **Confirmation-gate disable.** A settings edit flips a user-confirmation flag off. Signal: safety-directive removal, often immediately preceding an anomalous tool call.
- **Config recon then write.** A model turn dumps the full tool list, followed minutes later by a config write. Signal: the DE.AE-03 chain.
- **Credentials from config.** Plaintext secrets in config are read and then egress. Signal: secret-scan hit plus a non-baseline read plus outbound.

## Output Format

Report each finding with:

- The file(s) changed or read, and whether the change went through the approved deploy path.
- The nature of the edit: inserted instruction, added tool, removed safety directive, disabled confirmation flag, redirected source.
- Recon evidence (read bursts, tool enumeration, system-prompt dump) and whether a write followed.
- Secret exposure: plaintext secrets present, non-baseline reads, correlated egress.
- Change provenance: process, session, and triggering input (operator deploy vs untrusted turn).
- The correlated chain if present, with severity and confidence.

## Response

- **Restore and contain (RS.MI-01).** Restore config from VCS or a known-good copy, re-enable any disabled confirmation/safety gates, and freeze the agent.
- **Rotate credentials.** Rotate every credential reachable from the config or env — assume harvesting succeeded once tampering is confirmed.
- **Harden (prevent).** Keep config and manifests under version control, read-only at runtime, deployed only via a privileged path the agent cannot self-modify. Store secrets in a secret manager referenced by handle, never plaintext in config/env the agent can read. Apply least-privilege file permissions (PR.AA-05) and signed/attested config.
- **Use an external signer.** Because a self-writable integrity marker is bypassable, place integrity signing in a separate privileged runner the agent cannot modify, and say so plainly in the report.
