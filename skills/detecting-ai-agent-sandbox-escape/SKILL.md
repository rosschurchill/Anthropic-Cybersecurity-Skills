---
name: detecting-ai-agent-sandbox-escape
description: 'Detects a code-executing AI agent escaping its sandbox or container to the host (ATLAS AML.T0105 Escape to Host) and follow-on machine compromise (AML.T0112), sandbox evasion (AML.T0097), credential access (AML.T0106), and defense evasion (AML.T0107), typically a prompt-injected agent running host-level commands through its tools. Works by watching container-runtime syscall and eBPF telemetry (Falco, Tetragon, gVisor) for escape primitives such as host-socket access, release_agent abuse, nsenter, and privileged mounts, plus seccomp/AppArmor denials, network-isolation violations to cloud metadata, namespace and cgroup crossings, and post-escape credential reads and log tampering. Use when hunting agent container escape, code-interpreter breakout, or sandbox evasion by an AI agent. Keywords: AML.T0105, AML.T0112, AML.T0097, AML.T0106, AML.T0107, escape to host, container breakout, Falco, Tetragon, gVisor, seccomp, IMDS. Do not use for the tool-call policy boundary - use securing-agentic-ai-tool-invocation.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- ai-agent
- sandbox-escape
- container-security
- runtime-security
- ebpf
- code-interpreter
- privilege-escalation
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0105
- AML.T0112
- AML.T0097
- AML.T0106
- AML.T0107
---
# Detecting AI Agent Sandbox Escape

## When to Use

- A code-executing agent (code-interpreter or tool-running agent) runs inside a container or sandbox and you need to catch it breaking out to the host.
- You see container-escape primitives, seccomp/AppArmor denials, or namespace crossings originating from a code-interpreter workload.
- A network-isolated sandbox makes an outbound connection, especially to a cloud metadata endpoint.
- You are hunting the chain where a disabled confirmation gate or self-reconfiguration precedes host-level command execution.
- You are investigating post-escape host behavior: credential-file reads, security-agent or log tampering, or sandbox-detection probing.

This skill is AI-agent-specific escape detection: the agent-turn correlation, the confirmation-gate-disable signal, and the tight code-interpreter baseline are what make it distinct from generic runtime-security setup. The tool-call policy boundary is the sibling securing-agentic-ai-tool-invocation.

## Prerequisites

- Syscall / eBPF runtime security on the sandbox host: Falco, Tetragon (Cilium/eBPF), or Tracee (Aqua) with container-escape rulesets.
- Seccomp, AppArmor, or SELinux denial logs, and, if the sandbox runs under gVisor, gVisor Runtime Monitoring trace sessions (trace points configured via `--pod-init-config`, delivered over a Unix socket) — or `runsc` debug logs, which are off by default. gVisor is not a seccomp-bpf filter and its Sentry emits no denial events: unimplemented syscalls simply return `ENOSYS` to the sandboxed process.
- Sandbox egress and DNS telemetry (the sandbox should be network-isolated; any egress is signal).
- Process and file telemetry: process-tree, namespace/cgroup membership, and reads of host credential files (SSH keys, cloud creds, kube service-account tokens).
- Agent framework traces (Langfuse, LangSmith, OpenTelemetry GenAI spans) showing the tool call or generated code that preceded an escape, and whether a confirmation/safety gate was disabled first.

**Telemetry gap to flag up front:** many hosted agent sandboxes do not expose syscall telemetry to the tenant. If yours does not, obtaining that telemetry (or running the sandbox where you control the runtime) is a prerequisite — without it, syscall-level escape detection is not possible.

## Workflow

1. **Deploy escape rulesets.** Run Falco/Tetragon/Tracee rules for the known escape classes (below). Any one from inside an agent sandbox is high-severity.
2. **Treat denials as signal.** A seccomp/AppArmor/SELinux denial from a code-interpreter is near-definitive — that workload should never need those syscalls. Under gVisor there is no denial event to key on; use Runtime Monitoring trace points for the equivalent syscall-level visibility.
3. **Network-isolation check.** Alert on any outbound connection from an egress-restricted sandbox, especially to cloud metadata, correlated with the agent turn that generated the code.
4. **Boundary crossing.** Detect a process that started in the container appearing in the host namespace/cgroup, or host-socket access.
5. **Pre-escape config signal.** Correlate with a just-prior confirmation/safety-gate disable or self-reconfiguration (linkage to agent configuration tampering) — a strong chain indicator.
6. **Post-escape behavior.** Credential-file reads, security-agent/log tampering, and sandbox-detection probing each raise confidence and widen response scope.

## Key Concepts

- **Tight baseline, high signal.** A code-interpreter has a tiny, well-known syscall and network profile. Escape primitives sit far outside it, so detection is high-confidence with few false positives.
- **The AI path.** ATLAS notes the agent-specific route: an agent coerced (often by prompt injection) into running host-level commands through its allowed tools, or into disabling its own confirmation/safety gates so tool calls land on the host instead of the sandbox.
- **Escape then compromise.** After breakout come machine compromise, sandbox-evasion checks, exploitation for credential access, and disabling or evading defenses. Each post-escape signal drives response scope.
- **Denials are wins that are also alerts.** The sandbox refusing a disallowed operation is both a successful control and the clearest detection event.
- **Chain, do not merge.** A disabled confirmation gate frequently precedes escape; cross-reference detecting-ai-agent-configuration-tampering rather than duplicating it.
- **Enterprise analogue.** The host-escape behavior mirrors a well-known enterprise container-escape pattern; the enterprise detection detail is useful background, but the framework id here is the ATLAS one.

## Tools & Systems

| Role | Tools |
|------|-------|
| Syscall / eBPF detection | Falco, Tetragon (Cilium/eBPF), Tracee (Aqua) |
| Stronger isolation | gVisor (runsc), Kata Containers, microVMs |
| Kernel-level controls | seccomp/seccomp-bpf, AppArmor, SELinux |
| Host telemetry | auditd, osquery |
| Admission / policy | Kubernetes Pod Security Standards, OPA Gatekeeper, Kyverno |
| Cloud post-escape | IMDSv2 enforcement, CloudTrail, GuardDuty |
| Tracing | Langfuse, LangSmith, OpenTelemetry GenAI spans |

The generic Tetragon tooling setup is covered by the sibling implementing-runtime-security-with-tetragon; this skill uses it for AI-agent escape detection specifically.

## Detection Queries

Escape-primitive classes to alert on from inside an agent sandbox (detection signals, not exploit steps):

| Primitive | Signal |
|-----------|--------|
| Host Docker socket access | open of `/var/run/docker.sock` from the sandbox |
| cgroup-v1 `release_agent` / notify-on-release abuse | write to `release_agent` or `core_pattern` |
| Namespace entry | `nsenter` / `setns` from the container |
| Privileged mount | `mount` / `unshare` / `pivot_root`, host-path mount |
| Dangerous capabilities | use of `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE` |
| Metadata egress | outbound to the cloud metadata IP (169.254.169.254) |

Falco-style rule for host-socket and namespace-entry from an agent sandbox (verify fields/macros against your Falco version):

```yaml
- rule: Agent sandbox escape primitive
  desc: Escape-primitive syscall from a code-interpreter sandbox container
  condition: >
    container and container.image.repository contains "code-interpreter"
    and (
      (evt.type=open and fd.name="/var/run/docker.sock") or
      proc.name in (nsenter, setns, unshare, pivot_root) or
      (evt.type in (mount) ) or
      fd.name startswith "/proc/sys/kernel/core_pattern"
    )
  output: >
    Agent sandbox escape primitive (proc=%proc.cmdline file=%fd.name
    container=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, escape, ai-agent]
```

Network-isolation violation to metadata, correlated with an agent turn (KQL-style; illustrative fields):

```kql
// Detection 1 - metadata-endpoint egress from the sandbox
let meta_ip = "169.254.169.254";
SandboxNetFlows
| where src_container has "code-interpreter"
| where dest_ip == meta_ip
| join kind=leftouter (
    LLMTraces | where SpanName == "gen_ai.tool_call"
    | project turn_time = Timestamp, session_id, tool_code = ToolInput
  ) on $left.session_id == $right.session_id
// keep unmatched flows: a flow with no correlating turn is still a violation
| where isnull(turn_time) or FlowTime between (turn_time .. turn_time + 10s)  // verify/tune window
| project FlowTime, src_container, dest_ip, session_id, tool_code
```

```kql
// Detection 2 - any egress outside the allowlist (an isolated sandbox should have none).
// allowed_egress must be a real, non-empty allowlist; an empty array makes this clause match
// every row and the detection meaningless.
let allowed_egress = dynamic(["10.0.0.0/8-internal-proxy-ip"]);  // replace with your allowlist
SandboxNetFlows
| where src_container has "code-interpreter"
| where dest_ip !in (allowed_egress)
| project FlowTime, src_container, dest_ip, dest_port, session_id
```

Tetragon/eBPF-style intent: alert on a process whose cgroup/namespace membership leaves the container, or a host process newly parented to the sandbox runtime. Post-escape, alert on reads of host credential files (SSH keys, cloud credential files, kube service-account token paths) and on tampering with the Falco/audit agent itself.

## Common Scenarios

- **Injected host command.** A prompt-injected agent is coerced into running a host-level command through an allowed shell tool; the syscall leaves the sandbox profile. Signal: escape-primitive rule fires correlated with the generating turn.
- **Gate-disable then escape.** The agent self-reconfigures to disable a confirmation gate, then a tool call lands on the host. Signal: config-tampering chain into an escape primitive.
- **Metadata credential theft.** The sandbox reaches the cloud metadata endpoint for instance credentials. Signal: network-isolation violation to the metadata IP. This is post-escape credential access by retrieval of an unsecured credential, not exploitation of a software vulnerability.
- **Defense evasion.** Code probes for sandbox artifacts (hypervisor strings, cgroup paths, `/.dockerenv`) — sandbox-evasion checks, T0097 — or, post-escape with host privileges, tampers with the logging agent, which is defense evasion rather than exploitation. Both raise confidence.

## Output Format

Report each finding with:

- The sandbox/container and the agent session/turn that generated the triggering code or tool call.
- The escape primitive or denial observed, with the raw runtime event.
- Any pre-escape config signal (disabled confirmation gate, self-reconfiguration).
- Network-isolation violations, especially metadata-endpoint egress.
- Post-escape behavior: credential reads, log/agent tampering, sandbox-detection probing.
- Severity and confidence; note which ATLAS technique each observed behavior maps to.

## Response

- **Contain immediately (RS.MI-01).** Kill the sandbox, isolate the host, snapshot for forensics, and revoke the agent tool access.
- **Rotate credentials.** Rotate every credential reachable from the host or sandbox (cloud creds, SSH keys, kube tokens, metadata-derived creds) — assume credential access succeeded on a confirmed escape.
- **Harden (prevent).** Run code-executing agents under gVisor/Kata or a strong microVM; drop all capabilities, run non-root with a read-only rootfs, no host-socket mount, a seccomp default-deny profile, and network egress default-deny with an allowlist; never mount host paths. Disable `--dangerously-skip-permissions`-style bypasses in launch wrappers, and keep confirmation gates server-enforced rather than agent-disableable.
- **Protect the detector.** Tamper-protect the runtime security agent itself and ship its logs off-host so defense-evasion attempts remain visible.
