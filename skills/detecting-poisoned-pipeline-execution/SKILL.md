---
name: detecting-poisoned-pipeline-execution
description: 'Detects poisoned CI/CD pipeline execution (MITRE T1677) by correlating high-risk workflow triggers (pull_request_target, fork PRs that check out an untrusted head SHA - the "pwn request"), self-hosted runner usage on public repos, tampering with pipeline-definition and referenced build files (.github/workflows, .gitlab-ci.yml, Jenkinsfile, build scripts), and secret exfiltration from runner hosts, using GitHub/GitLab/Jenkins audit logs and runner EDR telemetry. Use when hunting or alerting on attacker code injected into GitHub Actions, GitLab CI, or Jenkins pipelines, or when a fork PR appears to reach pipeline secrets. Keywords: poisoned pipeline, PPE, pwn request, pull_request_target, self-hosted runner, CI/CD secret exfiltration, Jenkinsfile tampering, T1677. Do not use for dependency/package supply-chain compromise in CI - use detecting-supply-chain-attacks-in-ci-cd.'
domain: cybersecurity
subdomain: devsecops
tags:
- devsecops
- threat-detection
- ci-cd-security
- poisoned-pipeline
- github-actions
- pull-request-target
- self-hosted-runner
- secret-exfiltration
- t1677
- supply-chain-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.PS-06
- ID.RA-09
mitre_attack:
- T1677
- T1195.002
- T1204
- T1078.004
---

# Detecting Poisoned Pipeline Execution

## When to Use

Use this skill to detect when an adversary injects and executes
attacker-controlled code **inside a CI/CD pipeline** (GitHub Actions, GitLab CI,
Jenkins) by abusing insecure triggers or writable pipeline-definition files
(ATT&CK T1677). It covers **direct** poisoning (editing `.github/workflows/*.yml`,
`.gitlab-ci.yml`, `Jenkinsfile`) and **indirect** poisoning (malicious code in
referenced build scripts, makefiles, tests, or linters the pipeline invokes). The
headline signal is a workflow run from an untrusted fork/PR that reaches pipeline
secrets and tries to exfiltrate them. Reach for it when:

- Hunting attacker code in your pipelines.
- A fork PR appears to reach secrets or run on a self-hosted runner.

For dependency/package supply-chain compromise, use
`detecting-supply-chain-attacks-in-ci-cd`.

## Prerequisites

- **GitHub Actions audit log** (workflow run events, `pull_request_target`
  triggers, `runner_name`, workflow-file add/modify, secret-access patterns) via
  the audit-log API.
- **GitLab** CI/CD pipeline + project audit events; **Jenkins** build logs and
  audit-trail plugin.
- **SCM repo events**: fork creation, PR open/synchronize, commits touching CI
  config or referenced build files, checkout of PR head SHA under a privileged
  trigger.
- **Self-hosted runner host telemetry**: Sysmon/EDR process creation and outbound
  connections (Sysmon ID 3/22) from runner work directories.
- A **baseline of normal build egress** (package registries, artifact stores).

## Workflow

1. **High-risk trigger + fork correlation.** Alert on a workflow using
   `pull_request_target` (or Jenkins SCM trigger / GitLab privileged
   `merge_request`) **that also checks out the PR head ref/SHA** — the classic
   "pwn request" that runs untrusted code with base-branch secrets.
2. **Self-hosted runner on a public repo.** Flag any job whose `runner_name` is
   not a GitHub-hosted reserved name while the repo is public; raise severity when
   combined with `pull_request_target`.
3. **CI-config / referenced-file tampering.** Diff-based rule: a PR from a fork
   that modifies `.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`, or the
   build scripts/makefiles/test configs the pipeline executes.
4. **Secret exfil on the runner.** Correlate pipeline secret access with outbound
   connections carrying encoded blobs (base64/hex) to external hosts, or
   `curl`/`wget`/`nc` to non-allowlisted domains inside a build step. Baseline
   normal egress and alert on deviation, not string-match alone.
5. **Respond** (see *Response*) — rotate exposed secrets and quarantine runners.

## Key Concepts

- **The "pwn request":** `pull_request_target` runs in the context of the base
  repo (with its secrets) but, if it checks out the PR head, executes untrusted
  fork code — the single highest-value pattern to detect.
- **Self-hosted + public = danger:** a self-hosted runner attached to a public
  repo lets any fork PR run code on your infrastructure.
- **Indirect poisoning hides in referenced files:** the workflow YAML can be
  clean while a `make test` target or a linter config it calls is malicious.
- **Egress is the exfil tell:** a build step reaching a non-registry destination,
  especially with encoded data, is the secret-theft signal.

## Tools & Systems

GitHub Actions audit log API, GitLab audit events API, Jenkins audit-trail
plugin, Sysmon, StepSecurity Harden-Runner, Falco (runner host), Sigma, Splunk,
Panther (GitHub Actions detections).

## Detection Queries

### Sigma -- pwn request: pull_request_target from a fork (GitHub audit)

```yaml
title: GitHub Actions Pwn Request (pull_request_target from fork)
status: experimental
logsource:
  product: github
  service: audit
detection:
  selection_trigger:
    action: 'workflows.run'
    trigger: 'pull_request_target'
  selection_fork:
    head_repository_fork: true
  condition: selection_trigger and selection_fork
level: high
```

### Splunk -- self-hosted runner on a public repo

```spl
`github_audit` action="workflows.run"
| where runner_group_name!="GitHub Actions" AND repo_visibility="public"
| stats count values(workflow) as workflows by repo, runner_name, actor
| `comment("self-hosted runner executing on a public repo = exposure")`
```

### Splunk -- secret exfil from a runner (EDR, egress deviation)

```spl
`ci_runner_edr` (process_name IN ("curl","wget","nc","python","node"))
| where match(CommandLine, "(?i)(base64|xxd|openssl enc|/dev/tcp)")
| lookup build_egress_allowlist domain AS dest_domain OUTPUT allowed
| where isnull(allowed)
| stats values(CommandLine) as cmds values(dest_domain) as dsts by host, workflow, repo
```

## Common Scenarios

- **Pwn request:** a fork PR modifies a test that `pull_request_target` runs,
  printing `secrets.AWS_KEY` to an attacker server.
- **Self-hosted takeover:** a public repo's self-hosted runner executes fork code
  that persists on the host.
- **Indirect poisoning:** PR edits `Makefile` (not the YAML) to curl a payload
  during `make build`.
- **False positive:** a maintainer's trusted PR touching workflow files in a
  change window — resolved by fork/first-time-contributor context.

## Output Format

```
POISONED PIPELINE DETECTION
  Repo/pipeline:   <repo> / <workflow or job>
  Verdict:         <confirmed | suspected | trusted-change>
  Vector:          <pwn-request | self-hosted-on-public | CI-config tamper | indirect build-file | secret-exfil>
  Actor/PR:        <actor> (fork: <y/n>, first-time: <y/n>), PR #<n>
  Secret access:   <secrets reached? which> ; egress: <dest>
  ATT&CK:          T1677[, T1195.002, T1204, T1078.004]
  Actions taken:   <secrets rotated | runner quarantined | artifacts reviewed | trigger restricted>
```

## Response

- **Restrict/disable `pull_request_target`**; require manual approval for
  workflows from first-time/fork contributors; **never run self-hosted runners on
  public repos**.
- Scope `GITHUB_TOKEN`/secrets to **least privilege**; prefer OIDC short-lived
  tokens; branch-protect and CODEOWNERS-protect CI config files (NIST CSF
  PR.PS-06).
- **On detection:** revoke/rotate exposed pipeline secrets, quarantine
  self-hosted runners, and review artifacts produced by the suspect run.
