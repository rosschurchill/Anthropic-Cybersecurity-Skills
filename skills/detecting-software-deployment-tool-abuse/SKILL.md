---
name: detecting-software-deployment-tool-abuse
description: 'Detects adversary abuse of enterprise software-deployment and configuration-management systems (MITRE T1072) - SCCM/MECM, Intune, Puppet/Chef/Ansible, JAMF/MDM - to push code to many endpoints at once as trusted, SYSTEM-context mass execution (NotPetya-style lateral movement and impact). Correlates server-side signals (new or out-of-window deployments/scripts/app assignments by unusual accounts, broad collection or group targeting) with endpoint process creation where the deployment agent (CCMExec.exe, IntuneManagementExtension) spawns PowerShell/cmd. Use when hunting lateral movement via deployment tooling or triaging unexpected enterprise software pushes. Keywords: T1072, SCCM, MECM, Intune, Scripts feature, CCMExec, IntuneManagementExtension, Ansible, Puppet, JAMF, Event ID 4688. Do not use for CI/CD build-pipeline poisoning - use detecting-poisoned-pipeline-execution.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- software-deployment
- sccm
- intune
- lateral-movement
- configuration-management
- mass-execution
- t1072
- endpoint-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- PR.AA-05
- PR.IR-01
mitre_attack:
- T1072
- T1570
- T1078
- T1651
---

# Detecting Software Deployment Tool Abuse

## When to Use

Use this skill to detect an adversary who, after compromising an admin of an
enterprise **software-deployment / configuration-management** system, uses it to
push code to many endpoints at once (ATT&CK T1072). These systems exist to do
trusted, authenticated, **SYSTEM-context mass execution**, so one compromised
console is lateral movement and impact at scale — the 2017 NotPetya vector. It
covers Microsoft SCCM/MECM and Intune, Puppet/Chef/Ansible/SaltStack, and
JAMF/MDM on macOS. Reach for it when:

- Hunting lateral movement via deployment tooling.
- Triaging an unexpected enterprise software/script push.

For CI/CD build-pipeline poisoning use `detecting-poisoned-pipeline-execution`;
for cloud VM management-service execution use
`detecting-cloud-administration-command-abuse`.

## Prerequisites

- **Endpoint process creation**: Windows Security 4688 / Sysmon Event ID 1
  (ParentImage, SYSTEM user context, CommandLine).
- **SCCM/MECM**: client `execmgr.log`, `AppEnforce.log`, `PolicyAgent.log`,
  Scripts-feature logs; site-server audit of new packages/applications/
  deployments and collection changes; SCCM admin-role group changes (Windows
  4720/4728/4732).
- **Intune**: Entra/Intune audit logs (new device-config / PowerShell script /
  Win32-app assignments, assignment-group changes).
- **Config management**: Ansible Tower/AWX job logs, Puppet/Chef server reports.
- A **baseline**: approved deployment authors, parent processes, signed payload
  hashes, and change windows.

## Workflow

1. **Baseline legitimate deployment** (who authors deployments, expected agent
   parents, change windows, approved content).
2. **Server-side.** Alert on a new SCCM package/application/deployment,
   Scripts-feature run, or Intune script/app assignment created by an account
   that does not normally author deployments, or outside the change window;
   sudden broad collection/assignment-group targeting (fan-out).
3. **Endpoint-side.** Alert when the deployment agent spawns a script/binary from
   SYSTEM with an unexpected parent or command line: `CCMExec.exe` /
   `IntuneManagementExtension` / `puppet` / `chef-client` / `ansible` /
   `salt-minion` → `powershell.exe`/`cmd.exe`/`wscript.exe`.
4. **Correlate.** A new/odd server-side deployment immediately followed by the
   same payload executing across many hosts confirms abuse over a one-off.
5. **Watch precursors.** SCCM admin-role group adds, PXE/NAA credential access.
6. **Respond** (see *Response*).

## Key Concepts

- **The platform is domain-wide SYSTEM:** its legitimate function is exactly what
  an attacker wants — trusted mass execution — so detection is about *who
  authored* the deployment and whether it fits baseline, not whether execution
  "looks malicious."
- **Two angles, correlated:** server-side (deployment authored/assigned) and
  endpoint-side (agent spawns a shell) corroborate each other; either alone is
  noisy because legitimate deployments do exactly this.
- **Fan-out is the tell:** broad collection/assignment targeting by an unusual
  account is the scale signal that separates abuse from routine ops.
- **Allowlist is load-bearing:** without approved parents/hashes/windows, the
  endpoint rule drowns in legitimate deployments.

## Tools & Systems

Microsoft Configuration Manager (SCCM/MECM), Microsoft Intune, Entra audit logs;
Puppet, Chef, Ansible/AWX/Tower, SaltStack; JAMF Pro and other MDM; Sysmon,
Windows Security auditing, Splunk/Sentinel/Elastic.

## Detection Queries

### Sigma -- deployment agent spawning an interpreter (endpoint)

```yaml
title: Software Deployment Agent Spawning Script Interpreter
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith: ['\CcmExec.exe', '\IntuneManagementExtension.exe']
  selection_child:
    Image|endswith: ['\powershell.exe','\cmd.exe','\wscript.exe','\cscript.exe','\mshta.exe']
  filter_expected:
    CommandLine|contains: '<approved-deployment-script-name>'
  condition: selection_parent and selection_child and not filter_expected
falsepositives:
  - Legitimate software deployments (allowlist approved content)
level: medium
```

### Splunk -- new SCCM/Intune deployment by an unusual author then fan-out

```spl
`sccm_or_intune_audit` (action="CreateDeployment" OR action="assignment.create" OR action="RunScript")
| search NOT [ | inputlookup deployment_authors | fields account ]
| eval authorTime=_time
| join [ search `sysmon` EventCode=1 (ParentImage="*\\CcmExec.exe" OR ParentImage="*IntuneManagementExtension*")
        | stats dc(Computer) as hosts min(_time) as execTime by CommandLine ]
| where execTime>=authorTime AND hosts > 20
| table _time, account, action, CommandLine, hosts
```

## Common Scenarios

- **NotPetya-style:** compromised SCCM admin deploys a malicious package to a
  broad collection — server-side new deployment + endpoint CCMExec→PowerShell on
  thousands of hosts.
- **Intune script push:** attacker assigns a PowerShell script to all devices via
  a new assignment group.
- **Ansible playbook abuse:** stolen Tower creds run a playbook that drops a
  payload fleet-wide.
- **False positive:** monthly patch deployment by the SCCM service account in the
  change window — allowlisted.

## Output Format

```
DEPLOYMENT TOOL ABUSE DETECTION
  Platform:        <SCCM/MECM | Intune | Ansible/Puppet/Chef | JAMF>
  Verdict:         <confirmed | suspected | approved-deployment>
  Server-side:     <new deployment/script/assignment> by <account> (author expected: <y/n>), targets <scope>
  Endpoint-side:   <agent> -> <interpreter> on <n hosts> as SYSTEM
  Window:          author <t0> -> exec <t1>
  ATT&CK:          T1072[, T1570, T1078, T1651]
  Actions taken:   <deployment suspended | targeted hosts contained | author account revoked | logs preserved>
```

## Response

- **Least privilege + tiered admin** on SCCM/MECM, Intune, and config-management
  masters; MFA + PAW for deployment admins; treat the deployment system as its
  own admin tier (it is effectively domain-wide SYSTEM) (NIST CSF PR.AA-05).
- **Change-control gate + approval** for new deployments; alert on out-of-band
  package/script creation; code-sign and allowlist deployment payloads; restrict
  and audit the SCCM Scripts feature.
- Harden SCCM (NAA, PXE, site-server) per vendor guidance; monitor admin-role
  membership.
- **Respond:** suspend the deployment/assignment, identify every targeted host,
  contain and triage them, revoke the authoring account, preserve server +
  client `execmgr`/`AppEnforce` logs, and review recently created
  packages/scripts for implants.
