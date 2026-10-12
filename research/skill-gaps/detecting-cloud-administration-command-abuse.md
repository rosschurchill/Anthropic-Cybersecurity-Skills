# Detecting Cloud Administration Command Abuse — research notes

- **Proposed slug:** detecting-cloud-administration-command-abuse
- **ATT&CK:** T1651 Cloud Administration Command (tactic: execution) — related: T1072 Software Deployment Tools, T1059 Command and Scripting Interpreter, T1078.004 Cloud Accounts. Detection strategy: **DET0545** (verify against v19.2).
- **Status:** research (not yet a skill)

## Defensive goal
Detect when an adversary with control-plane credentials uses the cloud provider's own VM-management service to run commands inside guest instances — AWS Systems Manager (SSM) Run Command / Session Manager, Azure VM Run Command and Automation Runbooks, GCP OS Config / guest agent. This is "living off the cloud": the agent is pre-installed and trusted, so execution lands on the host with no new malware and no inbound RDP/SSH. The skill flags administration-command API calls that fall outside expected identities, VM scope, automation, and maintenance windows, and correlates them with follow-on host activity.

## Data sources / telemetry
- **AWS CloudTrail (management events):** `SendCommand`, `StartSession`, `StartAutomationExecution`, `CreateAssociation`, `ResumeSession` (ssm.amazonaws.com). Fields: `userIdentity.arn`, `sourceIPAddress`, `userAgent`, `requestParameters.documentName` (e.g. `AWS-RunShellScript`, `AWS-RunPowerShellScript`), `requestParameters.instanceIds`/`targets`, `requestParameters.parameters` (command payload). Session Manager session logs can be shipped to CloudWatch Logs / S3.
- **On-instance:** SSM agent logs (`/var/log/amazon/ssm/amazon-ssm-agent.log`), `amazon-ssm-agent` process spawning `sh`/`powershell`; EDR/Sysmon process-creation on the guest.
- **Azure Activity Log / Monitor:** `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` (action-based, transient) and `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE` (managed Run Command — leaves a durable resource, so persistence-capable); scale-set variants `MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/...`. Automation Account job logs (`Microsoft.Automation/automationAccounts/jobs`), Custom Script Extension (`...virtualMachines/extensions/write`). Check `event.outcome`/status for success. (Exact operationName casing — verify in Microsoft docs.)
- **GCP Cloud Audit Logs (Admin Activity):** OS Config `osconfig.googleapis.com` patch/guest-policy method names, `compute.instances.setMetadata` (startup-script abuse), guest agent activity (verify exact methodNames).

## Detection logic / approach
Per DET0545, judge the command event against identity, scope, and timing — not in isolation:
- **New/rare principal runs commands:** alert when an identity (user/role/service principal) issues `SendCommand`/RunCommand for the first time, or outside its baseline, especially from an unusual `sourceIPAddress`/`userAgent` (CLI/SDK vs console) or geo.
- **Scope/fan-out:** one call targeting many instances (mass `targets`/tag-based `instanceIds`) is a strong lateral-movement/impact signal.
- **Payload inspection:** `requestParameters.parameters` or the script body containing download-and-execute, base64/`-enc`, `curl|bash`, credential/metadata-endpoint access (`169.254.169.254`), or disabling of logging.
- **Correlate control-plane → host:** join the CloudTrail/Activity event to the guest's process-creation (ssm-agent/WaAppAgent spawning a shell) within N minutes to confirm execution and see what ran.
- **Managed vs transient (Azure):** `RUNCOMMANDS/WRITE` creating a persistent run-command resource warrants higher severity than a one-shot `RUNCOMMAND/ACTION`.

Example Splunk SPL over CloudTrail:
```
index=cloudtrail eventSource=ssm.amazonaws.com eventName IN ("SendCommand","StartSession","StartAutomationExecution","CreateAssociation")
| spath requestParameters.documentName output=doc
| stats values(doc) values(requestParameters.instanceIds{}) dc(requestParameters.instanceIds{}) as n_targets min(_time) by userIdentity.arn sourceIPAddress userAgent
| where n_targets>5 OR new_or_rare_principal=1
```
Example KQL (Azure Activity): filter `OperationNameValue` in the two RunCommand operations above, `ActivityStatusValue == "Success"`, summarize by `Caller`, `CallerIpAddress`, join to a baseline of callers that have used the operation before. Elastic ships a prebuilt rule "Azure Compute VM Command Executed" on these operations.

## Response / mitigation
- Least privilege on `ssm:SendCommand`/`ssm:StartSession`, Azure `Microsoft.Compute/virtualMachines/runCommand*`, and Automation contributor roles; require MFA / privileged-access workstations; gate with SCPs / Azure Policy / Org Policy.
- Restrict SSM documents to an approved set; enable Session Manager logging to immutable S3/CloudWatch; enable Azure resource logs to a tamper-resistant workspace.
- Response: revoke the principal's credentials/session, pull Session Manager / run-command output to see what executed, triage targeted guests for implants, delete rogue managed run-command resources and Automation runbooks/webhooks.

## Real tools
AWS CloudTrail, Systems Manager (Run Command / Session Manager / Automation), Amazon GuardDuty, AWS Config; Azure Activity Log, Azure Monitor, Microsoft Defender for Cloud, Microsoft Sentinel; GCP Cloud Audit Logs, OS Config, Security Command Center; Splunk, Elastic Security (prebuilt rule), Datadog Cloud SIEM; Stratus Red Team / Azure Threat Research Matrix (AZT301.6) for detection validation.

## Draft frontmatter mappings
- mitre_attack: [T1651, T1072, T1059, T1078.004]
- nist_csf: [DE.CM-09, DE.AE-02, DE.AE-03, PR.AA-05, PR.PS-01, DE.CM-01]
- suggested subdomain: cloud-security
- nearest existing sibling (for the negative trigger): hunting-for-living-off-the-cloud-techniques

## Draft description (<=1024 chars)
Detects adversary abuse of cloud VM-administration services to run commands inside guest instances — AWS SSM Run Command/Session Manager, Azure VM Run Command and Automation runbooks, GCP OS Config — "living off the cloud" execution via pre-installed, trusted agents with no inbound RDP/SSH. Flags control-plane command calls from new or rare identities, mass-instance fan-out, suspicious script payloads, and the managed (persistent) Azure RunCommand resource, then correlates to on-guest process creation to confirm what ran. Use when hunting cloud execution/lateral movement or triaging SSM/RunCommand activity in CloudTrail or Azure Activity logs. Keywords: T1651, SSM SendCommand, StartSession, AWS-RunShellScript, Azure runCommand/action, runCommands/write, Automation runbook, OS Config, living off the cloud. Do not use for generic cloud control-plane anomaly baselining (use detecting-aws-cloudtrail-anomalies) or broad LOTC technique hunting (use hunting-for-living-off-the-cloud-techniques).

## Key references
- https://attack.mitre.org/techniques/T1651/
- https://attack.mitre.org/detectionstrategies/DET0545 (verify id against v19.2)
- https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/executing-commands-on-a-virtual-machine-runcommand/
- https://microsoft.github.io/Azure-Threat-Research-Matrix/Execution/AZT301/AZT301-6/
- https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/azure/execution_compute_vm_command_executed

## Open questions / scope boundaries
- Verify DET0545 id and the exact Azure operationName casing (`RUNCOMMAND/ACTION` vs `RUNCOMMANDS/WRITE`) and GCP OS Config methodNames against primary docs before writing provider queries.
- Decide multi-cloud vs per-provider; baseline source of "expected" SSM documents and automation accounts is author-provided.
- Must NOT cover IaaS compute-infrastructure tampering (snapshots/instances — detecting-cloud-compute-infrastructure-tampering) or on-prem software-deployment tools like SCCM (detecting-software-deployment-tool-abuse). Keep the execution-via-management-service framing.
