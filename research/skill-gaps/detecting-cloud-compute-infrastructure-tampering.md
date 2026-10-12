# Detecting Cloud Compute Infrastructure Tampering — research notes

- **Proposed slug:** detecting-cloud-compute-infrastructure-tampering
- **ATT&CK:** T1578 Modify Cloud Compute Infrastructure (tactic: defense-evasion). Sub-techniques: **T1578.001 Create Snapshot, T1578.002 Create Cloud Instance, T1578.003 Delete Cloud Instance, T1578.004 Revert Cloud Instance, T1578.005 Modify Cloud Compute Configurations**. Detection strategies: **DET0308** (parent), **DET0423** (.001 Create Snapshot).
- **Status:** research (not yet a skill)

## Defensive goal
Detect when an adversary manipulates IaaS compute control-plane primitives to evade defenses or stage theft — creating a snapshot of a sensitive volume to exfiltrate it to an attacker-controlled instance, spinning up new instances to run tooling outside monitored images, deleting/reverting instances to destroy forensic evidence, or changing compute configs (quotas, images) to enable later abuse. The skill alerts on these control-plane API calls when they fall outside change-control, automation, and baseline user context.

## Data sources / telemetry
- **AWS CloudTrail** (management events): `CreateSnapshot`, `CreateImage`, `CopySnapshot`, `ModifySnapshotAttribute` (sharing a snapshot to another account — key exfil signal), `RunInstances`, `TerminateInstances`, `StopInstances`, `CreateInstanceExportTask`, `ModifyInstanceAttribute`, `RequestSpotInstances`, `RestoreSnapshotTier`. Fields: `userIdentity`, `sourceIPAddress`, `userAgent`, `requestParameters`, `recipientAccountId`.
- **Azure Activity Log / Azure Monitor:** `Microsoft.Compute/snapshots/write`, `Microsoft.Compute/disks/beginGetAccess/action` (export SAS URL — exfil signal), `Microsoft.Compute/virtualMachines/write`, `.../delete`, `.../deallocate`, `Microsoft.Compute/images/write` (verify exact operationNames in Microsoft docs).
- **GCP Cloud Audit Logs (Admin Activity):** `v1.compute.snapshots.insert`, `v1.compute.disks.createSnapshot`, `v1.compute.images.insert`, `v1.compute.instances.insert`, `v1.compute.instances.delete`, `compute.disks.setIamPolicy` (verify method names).
- **Cloud-native detections:** AWS GuardDuty, Azure Defender for Cloud, GCP Security Command Center / Event Threat Detection.
- IAM context: recent user/role creation (CloudTrail `CreateUser`/`CreateAccessKey`), to catch "snapshot from a newly created IAM user."

## Detection logic / approach
Per DET0423 (snapshots) and DET0308 (parent), judge control-plane events against context, not in isolation:
- **Snapshot exfil chain (T1578.001):** `CreateSnapshot` of a sensitive volume with no corresponding change-control ticket → followed by `ModifySnapshotAttribute` sharing it with an external `recipientAccountId`, or `CopySnapshot` to another region/account, or the snapshot mounted to a new/unauthorized instance. Flag snapshots taken by newly created or rarely-used IAM principals.
- **Rogue instance (T1578.002):** `RunInstances` using an unusual AMI/image, instance type (GPU for cryptomining), region outside baseline, or launched by a service principal that never launches instances. Correlate with GuardDuty cryptomining findings.
- **Evidence destruction (T1578.003/.004):** `TerminateInstances`/`StopInstances` or `RevertToSnapshot` shortly after suspicious activity on that host, especially during an active incident window.
- **Config tamper (T1578.005):** `ModifyInstanceAttribute` disabling source/dest check, changing security groups/IAM instance profile.

Example Splunk SPL over CloudTrail:
```
index=cloudtrail eventName IN ("CreateSnapshot","ModifySnapshotAttribute","CopySnapshot")
| eval shared=if(eventName="ModifySnapshotAttribute" AND match(requestParameters.*, "all|external_acct"),1,0)
| stats earliest(_time) latest(_time) values(eventName) by userIdentity.arn sourceIPAddress
| where (new_or_rare_principal=1) OR shared=1
```
Example KQL (Azure) / GCP Logging query filter by the operationName / protoPayload.methodName lists above, joined to IAM-change events within N minutes. DET0308 tuning fields: change windows, user context, rate thresholds, geolocation; allowlist known automation/service accounts (Terraform, autoscaling, backup services).

## Response / mitigation
- Enforce change-control + least privilege on compute APIs; require MFA / session policies for snapshot/share/terminate actions; SCPs (AWS) / Azure Policy / GCP Org Policy to deny cross-account snapshot sharing and public snapshot/image exposure.
- Enable multi-region CloudTrail + log-file validation, Azure Activity Log export, GCP Admin Activity (always-on) → immutable SIEM store so instance deletion cannot erase the control-plane trail.
- Response: revoke the principal's credentials, un-share/delete rogue snapshots, quarantine new instances, preserve the control-plane logs, check whether the deleted instance's volumes/snapshots still exist for forensics.

## Real tools
AWS CloudTrail, Amazon GuardDuty, AWS Config; Azure Activity Log, Microsoft Defender for Cloud, Microsoft Sentinel (KQL); GCP Cloud Audit Logs, Security Command Center, Event Threat Detection; Splunk, Stratus Red Team (for detection validation), Cloud Custodian, Prowler/ScoutSuite (posture).

## Draft frontmatter mappings
- mitre_attack: [T1578, T1578.001, T1578.002, T1578.003, T1578.004, T1578.005]
- nist_csf: [DE.CM-09, DE.AE-02, DE.AE-03, PR.AA-05, PR.PS-01, PR.DS-01]
- d3fend (optional): D3-CAA (Cloud Audit Analysis) n/a-verify; candidate D3-RAPA (Resource Access Pattern Analysis), D3-UGLPA — verify exact ids
- suggested subdomain: cloud-security
- nearest existing sibling (for the negative trigger): detecting-aws-cloudtrail-anomalies

## Draft description (<=1024 chars)
Detects tampering with IaaS compute infrastructure to evade defenses or stage theft — creating/sharing/copying snapshots of sensitive volumes (exfil), launching rogue instances, deleting or reverting instances to destroy evidence, and altering compute configs — across AWS, Azure, and GCP. Correlates control-plane events (CloudTrail CreateSnapshot/ModifySnapshotAttribute/RunInstances/TerminateInstances, Azure Microsoft.Compute operations, GCP compute methods) with IAM-change context, change windows, and geolocation, and allowlists known automation. Use when hunting cloud defense-evasion or triaging suspicious compute API activity. Keywords: snapshot exfiltration, CreateSnapshot, ModifySnapshotAttribute, rogue instance, instance deletion, T1578, cloud compute tampering, CloudTrail, Azure Activity, GCP audit. Do not use for cloud account/org hierarchy changes (use detecting-cloud-resource-hierarchy-tampering) or generic CloudTrail anomaly baselining (use detecting-aws-cloudtrail-anomalies).

## Key references
- https://attack.mitre.org/techniques/T1578/
- https://attack.mitre.org/techniques/T1578/001/
- https://attack.mitre.org/detectionstrategies/DET0423
- https://attack.mitre.org/detectionstrategies/DET0308
- https://attack.mitre.org/datacomponents/DC0062

## Open questions / scope boundaries
- Verify exact Azure Activity operationNames and GCP methodNames for snapshot create/export before writing provider queries (Microsoft/Google docs).
- Decide whether the skill is multi-cloud or split per provider; the catalogue already has AWS-leaning siblings, so a multi-cloud skill fills a real gap.
- Must NOT cover cloud resource-hierarchy / org-structure changes (T1666 — separate skill) or identity/credential abuse (separate skills). Snapshot-as-data-theft overlaps Collection/Exfiltration tactics — keep the defense-evasion framing but note the overlap.
