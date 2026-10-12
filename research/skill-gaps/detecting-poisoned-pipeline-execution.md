# Detecting Poisoned Pipeline Execution — research notes

- **Proposed slug:** detecting-poisoned-pipeline-execution
- **ATT&CK:** T1677 Poisoned Pipeline Execution (tactic: execution) — closely related: T1195.002 (Compromise Software Supply Chain), T1204 (User Execution via malicious PR), T1552.007 (Credentials from CI/CD secrets)
- **Status:** research (not yet a skill)

## Defensive goal
Detect when an adversary injects and executes attacker-controlled code inside a CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins) by abusing insecure triggers or writable pipeline-definition files. The skill catches direct poisoning (editing `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`) and indirect poisoning (malicious code injected into referenced build scripts, makefiles, unit tests, or linters that the pipeline invokes). Primary signal is a workflow run from an untrusted fork/PR that gains access to pipeline secrets and attempts to exfiltrate them.

## Data sources / telemetry
- **GitHub Actions / audit logs:** workflow run events, `workflow_run`, `pull_request_target` triggers, `runner_name` field (GitHub-hosted runners use reserved names; any other value = self-hosted), workflow file add/modify events, `org.update_actions_settings`, secret-access patterns.
- **GitLab:** CI/CD pipeline events, `.gitlab-ci.yml` change events, project audit events, runner job logs.
- **Jenkins:** job build logs, SCM-polling events, `Jenkinsfile` changes, credential-binding usage.
- **SCM repo events:** fork creation, pull request open/synchronize, commits touching CI config or referenced build files, checkout of PR head SHA under a privileged trigger.
- **Runner host telemetry (self-hosted):** process creation (Sysmon ID 1 / EDR), outbound network connections (Sysmon ID 3/22) from runner work directories, DNS lookups to non-build destinations.
- MITRE detection strategy DET0533 maps to data components cloud service modification (DC0069) and cloud service metadata (DC0070) on the `saas:github` channel; analytic AN1473 = anomalous workflow execution from forked repos. (verify IDs against live attack.mitre.org.)

## Detection logic / approach
- **High-risk trigger + fork correlation:** alert on a workflow using `pull_request_target` (or Jenkins SCM trigger / GitLab `merge_request` with privileged scope) **that also checks out the PR head ref/SHA** — the classic "pwn request" pattern that runs untrusted code with base-branch secrets. Pseudo-Sigma (GitHub audit source):
  ```
  selection_trigger: { event: 'workflow_run', trigger: 'pull_request_target' }
  selection_fork:    { head_repository_is_fork: true }
  condition: selection_trigger and selection_fork
  ```
- **Self-hosted runner on public repo:** flag any job where `runner_name` is not a GitHub-hosted reserved name and the repo is public; raise severity when combined with `pull_request_target`.
- **CI-config / referenced-file tampering in a PR:** diff-based rule — PR from a fork that modifies `.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`, or build scripts/makefiles/test configs the pipeline executes.
- **Secret-exfil on the runner:** correlate pipeline secret access with outbound connections carrying encoded blobs (base64/hex) to external hosts, or `curl`/`wget`/`nc` to non-allowlisted domains inside a build step. Splunk SPL sketch over runner EDR:
  ```
  index=ci_runner (process IN ("curl","wget","nc","python") OR CommandLine="*base64*")
  | where NOT match(dest_domain, allowlist) | stats values(CommandLine) by host, workflow
  ```
- Baseline normal build egress (package registries, artifact stores) and alert on deviation rather than string-matching alone.

## Response / mitigation
- Restrict/disable `pull_request_target`; require manual approval for workflows from first-time/fork contributors; never run self-hosted runners on public repos. Scope `GITHUB_TOKEN`/secrets to least privilege; use OIDC short-lived tokens. Branch-protect and CODEOWNERS-protect CI config files. On detection: revoke/rotate exposed pipeline secrets, quarantine self-hosted runners, review artifacts produced by the suspect run.

## Real tools
GitHub Actions audit log API, GitLab audit events API, Jenkins audit trail plugin, Sysmon, Panther (GitHub Actions detections), StepSecurity Harden-Runner, Sigma, Splunk, Falco (runner host). (verify any product-specific field names before use.)

## Draft frontmatter mappings
- mitre_attack: [T1677, T1195.002, T1204, T1552.007, T1078.004]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, PR.PS-06, ID.RA-09]
- d3fend (optional): D3-STA (System Call Analysis), D3-OTF (Outbound Traffic Filtering), D3-FA (File Analysis) — verify current D3FEND IDs
- suggested subdomain: devsecops
- nearest existing sibling (for the negative trigger): detecting-supply-chain-attacks-in-ci-cd

## Draft description (<=1024 chars)
Detects poisoned CI/CD pipeline execution by correlating high-risk workflow triggers (pull_request_target, fork PRs checking out untrusted head SHAs), self-hosted runner usage on public repos, tampering with pipeline-definition and referenced build files, and secret exfiltration from runner hosts, using GitHub/GitLab/Jenkins audit logs and runner EDR telemetry. Use when hunting for or alerting on attacker code injected into GitHub Actions, GitLab CI, or Jenkins pipelines, or when a fork PR appears to reach pipeline secrets. Keywords: poisoned pipeline, PPE, pwn request, pull_request_target, self-hosted runner, CI/CD secret exfiltration, Jenkinsfile tampering, T1677. Do not use for scanning dependency/package supply-chain compromise in CI - use detecting-supply-chain-attacks-in-ci-cd.

## Key references
- https://attack.mitre.org/techniques/T1677/
- https://attack.mitre.org/detectionstrategies/DET0533 (verify)
- https://panther.com/blog/detecting-and-hunting-for-github-actions-compromise
- https://securityarsenal.com/blog/github-actions-repository-takeover-detecting-and-mitigating-pwn-request-attacks
- OWASP Top 10 CI/CD Security Risks (CICD-SEC-4 Poisoned Pipeline Execution) — verify URL

## Open questions / scope boundaries
- Must decide platform scope (GitHub/GitLab/Jenkins vs. all). Confirm exact GitHub audit-log event names for secret access and workflow modification (Panther snippet was truncated).
- Must NOT cover dependency/package poisoning (covered by supply-chain sibling), nor offensive construction of pwn-request payloads. Decide whether runner-host EDR is in scope or the skill stays at the SCM/audit-log layer.
