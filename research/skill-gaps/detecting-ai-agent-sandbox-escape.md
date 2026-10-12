# Detecting AI Agent Sandbox Escape — research notes

- **Proposed slug:** detecting-ai-agent-sandbox-escape
- **ATLAS:** AML.T0105 Escape to Host (tactic: Privilege Escalation) — folding in **AML.T0112 Machine Compromise**, **AML.T0097 Virtualization/Sandbox Evasion**, **AML.T0106 Exploitation for Credential Access**, and **AML.T0107 Exploitation for Defense Evasion**. These model a code-executing agent breaking out of its container/sandbox to the host, then compromising the machine, evading controls, and harvesting credentials. Enterprise analogue: ATT&CK T1611 Escape to Host (DET0219) — useful for detection/mitigation detail, different ID.
- **Status:** research (not yet a skill)

## Defensive goal
Detect a **code-executing AI agent (code-interpreter / tool-running agent) breaking out of its sandbox or container to the underlying host.** ATLAS specifically notes the AI path: an agent coerced (often via prompt injection) into running host-level commands through its allowed tools, or into modifying its own config to disable confirmation/safety gates so tool calls land on the host instead of the sandbox (ties to AML.T0081). Once out: machine compromise (T0112), sandbox-evasion checks (T0097), exploitation for credential access (T0106), and disabling/evading defences (T0107). Defender-side: catch the escape at the container/sandbox runtime boundary and the post-escape host behaviour.

## Data sources / telemetry
- **Syscall / eBPF runtime security:** Falco, Tetragon, Tracee rules for container-escape primitives — writes to `/proc/sys/kernel/core_pattern`, `release_agent`/cgroup-v1 notify-on-release abuse, mounting host filesystems, access to the host Docker socket (`/var/run/docker.sock`), `nsenter`/`setns`, privileged capability use (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`), unexpected `mount`/`unshare`/`pivot_root`.
- **Seccomp / AppArmor / SELinux denials:** denied-syscall and profile-violation logs (the sandbox refusing a disallowed operation is itself the signal). gVisor (`runsc`) sentry logs for intercepted/blocked calls.
- **Code-interpreter sandbox egress + syscall telemetry:** network connections from a sandbox that should be network-isolated; outbound to metadata endpoints (169.254.169.254) for cloud-cred theft; DNS from the sandbox.
- **Process/file telemetry:** process tree escaping the container cgroup/namespace; new processes on the *host* parented to the sandbox runtime; reads of host credential files, SSH keys, cloud creds, kube service-account tokens (T0106).
- **Agent framework traces:** LangSmith / Langfuse / OpenTelemetry GenAI spans showing the tool call / generated code that triggered the escape, and whether a confirmation/safety gate was disabled first (T0107/T0081 linkage).
- **Defense-evasion signals (T0097/T0107):** code probing for sandbox artifacts (hypervisor strings, cgroup paths, `/.dockerenv`), tampering with Falco/audit/logging agents, clearing logs.

## Detection logic / approach
1. **Runtime escape primitives:** deploy Falco/Tetragon rulesets for the known escape classes above; any one from inside an agent sandbox is high-severity. gVisor/seccomp denials from a code-interpreter are near-definitive — that workload should never need those syscalls.
2. **Network-isolation violation:** a sandbox designed to be egress-restricted making *any* outbound connection, especially to cloud metadata IPs or arbitrary hosts, correlated with the agent turn that generated the code.
3. **Boundary crossing:** process/namespace/cgroup membership change — a process that started in the container appearing in the host namespace; host-socket access.
4. **Pre-escape config signal:** correlate with a just-prior disabling of a user-confirmation/safety gate or self-reconfiguration (AML.T0081) — strong chain indicator.
5. **Post-escape host behaviour:** credential-file reads (T0106), security-agent/log tampering (T0107), sandbox-detection probing (T0097) — each raises confidence and drives response scope.
6. **Baseline:** a code-interpreter has a tiny, well-known syscall/network profile; escape primitives are far outside it, so the detection is high-signal with a tight baseline.

## Response / mitigation
- **Contain immediately (RS.MI-01):** kill the sandbox, isolate the host, snapshot for forensics; revoke the agent's tool access.
- **Rotate credentials** reachable from the host/sandbox (cloud creds, SSH, kube tokens, metadata-derived creds) — assume T0106 on confirmed escape.
- **Harden (prevent):** run code-executing agents under gVisor/Kata or a strong microVM; drop all capabilities, non-root, read-only rootfs, no host-socket mount, seccomp default-deny profile, network egress default-deny with allowlist; never mount host paths; disable `--dangerously-skip-permissions`-style bypasses in launch wrappers; keep confirmation gates server-enforced, not agent-disableable.
- Tamper-protect the runtime security agent itself (T0107) and ship its logs off-host.

## Real tools
Falco, Tetragon (Cilium/eBPF), Tracee (Aqua), gVisor (runsc), Kata Containers, seccomp/seccomp-bpf, AppArmor, SELinux; auditd; osquery; container-escape detection rulesets (Falco community rules, Elastic/Sigma); Kubernetes admission control (OPA Gatekeeper/Kyverno) + Pod Security Standards; cloud IMDSv2 enforcement; CloudTrail/GuardDuty for post-escape cloud activity. Sibling skill implementing-runtime-security-with-tetragon covers the Tetragon tooling generically.

## Draft frontmatter mappings
- atlas: [AML.T0105, AML.T0112, AML.T0097, AML.T0106, AML.T0107]
- nist_csf: [DE.CM-09, DE.CM-01, DE.AE-03, PR.PS-01, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): implementing-runtime-security-with-tetragon

## Draft description (<=1024 chars)
Detects a code-executing AI agent escaping its sandbox or container to the host (ATLAS AML.T0105 Escape to Host) and the follow-on machine compromise (AML.T0112), sandbox evasion (AML.T0097), exploitation for credential access (AML.T0106) and defense evasion (AML.T0107) — typically a prompt-injected agent coerced into running host-level commands through its tools, or self-disabling confirmation gates so tool calls hit the host. Works by watching container-runtime syscall/eBPF telemetry (Falco, Tetragon, gVisor) for escape primitives (host socket, release_agent, nsenter, privileged mounts), seccomp/AppArmor denials, network-isolation violations to cloud metadata, namespace/cgroup boundary crossings, and post-escape credential-file reads and log tampering, correlated with the agent turn and any just-disabled safety gate. Use when hunting agent container escape, code-interpreter breakout, or sandbox evasion by an AI agent. Keywords: AML.T0105, escape to host, container breakout, code interpreter sandbox, Falco, Tetragon, gVisor, seccomp denial, release_agent, docker.sock, IMDS. Do not use for generic non-agent Tetragon deployment - use implementing-runtime-security-with-tetragon.

## Key references
- MITRE ATLAS AML.T0105 Escape to Host; AML.T0112 Machine Compromise; AML.T0097 Virtualization/Sandbox Evasion; AML.T0106 Exploitation for Credential Access; AML.T0107 Exploitation for Defense Evasion (atlas.mitre.org) — verify names/IDs
- MITRE ATT&CK T1611 Escape to Host + Detection Strategy DET0219 (enterprise analogue; detection/mitigation detail)
- Falco rules (container escape), Tetragon/Cilium runtime security docs, gVisor (runsc) documentation
- OWASP Agentic AI threats taxonomy (code execution / sandbox breakout); NIST AI RMF
- Kubernetes Pod Security Standards; cloud IMDSv2 guidance

## Open questions / scope boundaries
- Boundary vs implementing-runtime-security-with-tetragon: that is generic runtime-security tooling setup; this is *AI-agent-specific escape detection* — the agent-turn correlation, confirmation-gate-disable signal, and code-interpreter baseline are what make it distinct. Keep the brief AI-agent-framed.
- Linkage, not merge, with detecting-ai-agent-configuration-tampering (AML.T0081): a disabled confirmation gate often precedes escape; cross-reference, do not duplicate.
- Defensive framing only — the skill must NOT contain working escape payloads; describe primitives at the detection-signal level only.
- Verify AML.T0112 / AML.T0097 / AML.T0106 / AML.T0107 exact names and IDs against ATLAS v5.6.0 — DNS blocked direct fetch during research; AML.T0105 and AML.T0106 confirmed via secondary sources, the other three are task-supplied and consistent with ATLAS convention but UNVERIFIED on the primary page.
- Many hosted agent sandboxes do not expose syscall telemetry to the tenant; flag the telemetry-availability prerequisite.
