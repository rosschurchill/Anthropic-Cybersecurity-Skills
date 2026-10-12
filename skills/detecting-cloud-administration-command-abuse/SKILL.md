---
name: detecting-cloud-administration-command-abuse
description: 'Detects adversary abuse of cloud VM-administration services to run commands inside guest instances (MITRE T1651) - AWS SSM Run Command/Session Manager, Azure VM Run Command and Automation runbooks, GCP OS Config - "living off the cloud" execution via pre-installed trusted agents with no inbound RDP/SSH. Flags control-plane command calls from new or rare identities, mass-instance fan-out, suspicious script payloads, and the managed (persistent) Azure RunCommand resource, then correlates to on-guest process creation to confirm what ran. Use when hunting cloud execution/lateral movement or triaging SSM/RunCommand activity in CloudTrail or Azure Activity logs. Keywords: T1651, SSM SendCommand, StartSession, AWS-RunShellScript, Azure runCommand, Automation runbook, OS Config, living off the cloud. Do not use for generic cloud control-plane anomaly baselining - use detecting-aws-cloudtrail-anomalies.'
domain: cybersecurity
subdomain: cloud-security
tags:
- cloud-security
- threat-detection
- cloud-execution
- ssm
- run-command
- living-off-the-cloud
- cloudtrail
- azure-activity-log
- t1651
- lateral-movement
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- PR.AA-05
mitre_attack:
- T1651
- T1072
- T1059
- T1078.004
---

# Detecting Cloud Administration Command Abuse

## When to Use

Use this skill to detect when an adversary with control-plane credentials uses
the **cloud provider's own VM-management service** to run commands inside guest
instances (ATT&CK T1651) — AWS Systems Manager (SSM) Run Command / Session
Manager, Azure VM Run Command and Automation Runbooks, GCP OS Config. This is
"living off the cloud": the agent is pre-installed and trusted, so execution
lands on the host with **no new malware and no inbound RDP/SSH**. Reach for it
when:

- Hunting cloud execution / lateral movement.
- Triaging SSM/RunCommand activity in CloudTrail or Azure Activity logs.
- A single control-plane call fans out to many instances.

For generic cloud control-plane anomaly baselining use
`detecting-aws-cloudtrail-anomalies`; for compute-infrastructure tampering
(snapshots/instances) use `detecting-cloud-compute-infrastructure-tampering`.

## Prerequisites

- **AWS CloudTrail** management events (ssm.amazonaws.com) + Session Manager
  session logging to CloudWatch/S3.
- **Azure Activity Log / Monitor** (`Microsoft.Compute/.../runCommand`,
  `.../runCommands/write`, Automation job logs).
- **GCP Cloud Audit Logs** (OS Config, `compute.instances.setMetadata`).
- **On-guest telemetry**: SSM/WaAppAgent process spawning shells (Sysmon/EDR),
  SSM agent logs.
- A **baseline** of which identities/automation routinely issue admin commands
  and the approved SSM documents / automation accounts.

## Workflow

1. **Baseline expected admin-command use** (CI/ops principals, approved SSM
   documents, automation accounts, maintenance windows).
2. **New/rare principal.** Alert when an identity issues `SendCommand`/RunCommand
   for the first time or outside its baseline, from an unusual
   `sourceIPAddress`/`userAgent` (CLI/SDK vs console) or geo.
3. **Scope / fan-out.** One call targeting many instances (tag-based or large
   `instanceIds`) is a strong lateral-movement/impact signal.
4. **Payload inspection.** Flag command/script bodies with download-and-execute,
   base64/`-enc`, `curl|bash`, metadata-endpoint access (`169.254.169.254`), or
   logging-disable.
5. **Managed vs transient (Azure).** `runCommands/write` creates a **persistent**
   run-command resource (persistence-capable) — higher severity than a one-shot
   `runCommand/action`.
6. **Correlate control-plane → host.** Join the CloudTrail/Activity event to the
   guest's process creation (agent spawning a shell) within a short window to
   confirm execution and see what ran.
7. **Respond** (see *Response*).

## Key Concepts

- **The agent is the attack surface:** SSM/RunCommand agents are trusted,
  pre-installed, and reach inside the guest — execution needs no malware delivery
  or network ingress, so network controls never see it.
- **Control-plane identity is the pivot:** detection centers on *who* issued the
  command and whether it fits their baseline, not on a host signature.
- **Managed run-command = persistence:** Azure `runCommands/write` leaves a
  durable resource that re-runs; treat it more seriously than a transient action.
- **Fan-out is impact:** one API call to many instances is how cloud-native
  ransomware/wipers scale — a key high-severity pattern.

## Tools & Systems

AWS CloudTrail, Systems Manager (Run Command / Session Manager / Automation),
Amazon GuardDuty, AWS Config; Azure Activity Log, Azure Monitor, Microsoft
Defender for Cloud, Microsoft Sentinel; GCP Cloud Audit Logs, OS Config,
Security Command Center; Splunk, Elastic Security, Datadog Cloud SIEM.

## Detection Queries

### Splunk -- SSM command from a rare principal or mass fan-out

```spl
`cloudtrail` eventSource="ssm.amazonaws.com"
  eventName IN ("SendCommand","StartSession","StartAutomationExecution","CreateAssociation")
| spath requestParameters.documentName output=doc
| eval targets=mvcount('requestParameters.instanceIds{}')
| stats values(doc) as docs max(targets) as n_targets min(_time) as t
        by userIdentity.arn, sourceIPAddress, userAgent
| where n_targets > 5
    OR userIdentity.arn IN [ | inputlookup rare_ssm_principals | fields arn ]
```

### KQL -- Azure RunCommand, managed (persistent) weighted higher

```kql
AzureActivity
| where OperationNameValue in~
    ("Microsoft.Compute/virtualMachines/runCommand/action",
     "Microsoft.Compute/virtualMachines/runCommands/write")
| where ActivityStatusValue == "Success"
| extend persistent = OperationNameValue has "runCommands/write"
| summarize ops=count(), vms=dcount(_ResourceId) by Caller, CallerIpAddress, persistent, bin(TimeGenerated,1h)
| where persistent or vms > 5 or Caller !in (dynamic(["ops-automation@contoso.com"]))
```

### Correlate SSM agent -> shell on the guest (Sysmon)

```spl
`sysmon` EventCode=1 (ParentImage="*amazon-ssm-agent*" OR ParentImage="*ssm-session-worker*"
   OR ParentImage="*WindowsAzureGuestAgent*")
  (Image="*\\powershell.exe" OR Image="*/sh" OR Image="*/bash")
| table _time, Computer, ParentImage, Image, CommandLine
```

## Common Scenarios

- **SSM fan-out:** stolen role calls `SendCommand` with `AWS-RunShellScript`
  across all tagged instances to deploy a miner — targets>5 fires.
- **Azure persistence:** attacker creates a managed Run Command that re-executes
  on boot — `runCommands/write`.
- **Session Manager hands-on-keyboard:** `StartSession` from a new IP, then shell
  activity on the guest.
- **False positive:** the patch-automation role running an approved document in a
  maintenance window — allowlisted.

## Output Format

```
CLOUD ADMIN COMMAND DETECTION
  Cloud/account:   <aws|azure|gcp> / <account/subscription/project>
  Verdict:         <confirmed | suspected | approved-automation>
  Service:         <SSM SendCommand/StartSession | Azure RunCommand(action/write) | GCP OSConfig>
  Principal:       <arn/caller> (new/rare: <y/n>) from <ip/geo>, agent <userAgent>
  Scope:           <n instances> ; persistent resource: <y/n>
  Payload:         <download-exec | metadata access | benign>
  On-guest:        <agent-spawned shell confirmed? what ran>
  ATT&CK:          T1651[, T1072, T1059, T1078.004]
  Actions taken:   <creds/session revoked | output pulled | guests triaged | rogue run-command deleted>
```

## Response

- **Least privilege** on `ssm:SendCommand`/`ssm:StartSession`, Azure
  `runCommand*` and Automation roles; require MFA / privileged-access
  workstations; gate with SCPs / Azure Policy / Org Policy (NIST CSF PR.AA-05).
- Restrict SSM documents to an approved set; enable Session Manager and Azure
  resource logging to an **immutable** store.
- **Respond:** revoke the principal's credentials/session, pull Session Manager /
  run-command output to see what executed, triage targeted guests for implants,
  and delete rogue managed run-command resources, Automation runbooks and
  webhooks.
