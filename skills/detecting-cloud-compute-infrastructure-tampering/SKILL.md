---
name: detecting-cloud-compute-infrastructure-tampering
description: 'Detects tampering with IaaS compute infrastructure to evade defenses or stage theft (MITRE T1578) - creating/sharing/copying snapshots of sensitive volumes (exfil), launching rogue instances, deleting or reverting instances to destroy evidence, and altering compute configs - across AWS, Azure, and GCP. Correlates control-plane events (CloudTrail CreateSnapshot/ModifySnapshotAttribute/CopySnapshot/RunInstances/TerminateInstances, Azure Microsoft.Compute snapshot/disk operations, GCP compute snapshot/instance methods) with IAM-change context, change windows, and geolocation, and allowlists known automation (Terraform, autoscaling, backup). Use when hunting cloud defense-evasion or triaging suspicious compute API activity. Keywords: snapshot exfiltration, CreateSnapshot, ModifySnapshotAttribute, rogue instance, instance deletion, cloud compute tampering, CloudTrail, Azure Activity, GCP audit, T1578. Do not use for generic CloudTrail anomaly baselining - use detecting-aws-cloudtrail-anomalies.'
domain: cybersecurity
subdomain: cloud-security
tags:
- cloud-security
- threat-detection
- defense-evasion
- snapshot-exfiltration
- cloudtrail
- azure-activity-log
- gcp-audit-logs
- multi-cloud
- t1578
- incident-response
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.AE-02
- DE.AE-03
- PR.AA-05
- PR.DS-01
mitre_attack:
- T1578
- T1578.001
- T1578.002
- T1578.003
- T1578.004
- T1578.005
---

# Detecting Cloud Compute Infrastructure Tampering

## When to Use

Use this skill to detect when an adversary manipulates **IaaS compute
control-plane primitives** to evade defenses or stage theft (ATT&CK T1578):

- **Snapshot exfil (.001):** snapshot a sensitive volume, then share/copy it to
  an attacker-controlled account.
- **Rogue instance (.002):** spin up instances to run tooling outside monitored
  images.
- **Evidence destruction (.003/.004):** delete or revert instances to destroy
  forensic state.
- **Config tamper (.005):** change compute configs (security groups, instance
  profile, source/dest check) to enable later abuse.

Reach for it when hunting cloud defense-evasion or triaging suspicious compute
API activity across AWS, Azure, or GCP. For generic CloudTrail anomaly
baselining use `detecting-aws-cloudtrail-anomalies`.

## Prerequisites

- **AWS CloudTrail** management events (multi-region + log-file validation).
- **Azure Activity Log / Azure Monitor** (`Microsoft.Compute/*`) exported.
- **GCP Cloud Audit Logs** (Admin Activity, always-on).
- Cloud-native detections: GuardDuty, Defender for Cloud, Security Command
  Center / Event Threat Detection.
- IAM-change events for context (CloudTrail `CreateUser`/`CreateAccessKey`;
  Azure/GCP equivalents) and an **allowlist of automation principals**
  (Terraform, autoscaling, backup).

## Workflow

1. **Baseline automation & change control.** Record the service principals that
   routinely snapshot, launch, and terminate, plus change windows.
2. **Snapshot exfil chain (.001).** Alert on `CreateSnapshot` of a sensitive
   volume with no change ticket, **followed by** `ModifySnapshotAttribute`
   sharing it with an external `recipientAccountId`, `CopySnapshot` to another
   region/account, or the snapshot mounted to a new instance. Weight snapshots
   by newly created or rarely-used IAM principals.
3. **Rogue instance (.002).** Alert on `RunInstances` with an unusual AMI/image,
   GPU instance type (cryptomining), region outside baseline, or launched by a
   principal that never launches instances; correlate with GuardDuty
   cryptomining findings.
4. **Evidence destruction (.003/.004).** Alert on `TerminateInstances`/
   `StopInstances`/revert **shortly after** suspicious activity on that host,
   especially during an active incident window.
5. **Config tamper (.005).** Alert on `ModifyInstanceAttribute` disabling
   source/dest check or changing security groups / IAM instance profile.
6. **Correlate with IAM changes** within a short window and **respond** (see
   *Response*).

## Key Concepts

- **Judge control-plane events in context, not isolation:** `CreateSnapshot` is
  routine; `CreateSnapshot` by a day-old IAM user then shared externally is an
  exfil chain.
- **Snapshot sharing is the exfil tell:** `ModifySnapshotAttribute` to `all` or an
  external account (AWS), `disks/beginGetAccess` SAS export (Azure) move data out
  without touching the guest OS.
- **Deletion erases evidence:** immutable, externalized control-plane logs mean
  terminating an instance cannot erase the trail.
- **Multi-cloud by design:** the same tactic maps to AWS/Azure/GCP events; a
  multi-cloud skill fills a real gap.

## Tools & Systems

AWS CloudTrail, Amazon GuardDuty, AWS Config; Azure Activity Log, Microsoft
Defender for Cloud, Microsoft Sentinel (KQL); GCP Cloud Audit Logs, Security
Command Center, Event Threat Detection; Splunk, Cloud Custodian, Prowler/ScoutSuite
(posture), Stratus Red Team (detection validation).

## Detection Queries

### Splunk -- AWS snapshot exfil chain

```spl
`cloudtrail` eventName IN ("CreateSnapshot","ModifySnapshotAttribute","CopySnapshot")
| eval shared=if(eventName="ModifySnapshotAttribute"
      AND (like(requestParameters,"%\"groups\":[\"all\"]%") OR match(requestParameters,"userId")),1,0)
| stats earliest(_time) as t0 latest(_time) as t1 values(eventName) as evts
        values(sourceIPAddress) as ips by userIdentity.arn
| where shared=1 OR userIdentity.arn IN [ | inputlookup rare_or_new_principals | fields arn ]
```

### KQL -- Azure compute snapshot/disk export + IAM change join

```kql
let compute = AzureActivity
| where OperationNameValue in~
    ("Microsoft.Compute/snapshots/write","Microsoft.Compute/disks/beginGetAccess/action",
     "Microsoft.Compute/virtualMachines/delete")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId;
let iam = AzureActivity
| where OperationNameValue has "roleAssignments/write"
| project iamTime=TimeGenerated, Caller;
compute | join kind=leftouter iam on Caller
| where isempty(iamTime) or (TimeGenerated - iamTime) between (0min .. 60min)
```

### GCP -- audit methods (concept)

```
# Cloud Logging filter
protoPayload.methodName=("v1.compute.snapshots.insert" OR
  "v1.compute.disks.createSnapshot" OR "v1.compute.instances.delete")
AND protoPayload.authenticationInfo.principalEmail!~"serviceAccount:.*@terraform"
```

## Common Scenarios

- **Snapshot theft:** new IAM user snapshots a DB volume and shares it to an
  external account — the SPL chain fires.
- **Cryptomining:** `RunInstances` of GPU instances in an unused region +
  GuardDuty finding.
- **Anti-forensics:** instance terminated minutes after malware detection during
  an incident.
- **False positive:** nightly backup service snapshots volumes — allowlisted by
  principal.

## Output Format

```
CLOUD COMPUTE TAMPERING DETECTION
  Cloud/account:   <aws|azure|gcp> / <account/subscription/project>
  Verdict:         <confirmed | suspected | approved-automation>
  Action:          <snapshot+share | rogue instance | terminate/revert | config change>
  Principal:       <arn/caller> (new/rare: <y/n>) from <ip/geo>
  Exfil target:    <external account/region | n/a>
  ATT&CK:          T1578(.001-.005)
  Actions taken:   <creds revoked | snapshot un-shared/deleted | instance quarantined | logs preserved>
```

## Response

- Enforce **change control + least privilege** on compute APIs; require MFA /
  session policies for snapshot/share/terminate; use **SCPs / Azure Policy / GCP
  Org Policy** to deny cross-account snapshot sharing and public snapshot/image
  exposure (NIST CSF PR.AA-05).
- Keep **multi-region CloudTrail + log-file validation**, Azure Activity export,
  and GCP Admin Activity flowing to an **immutable SIEM store** so instance
  deletion cannot erase the trail.
- **Respond:** revoke the principal's credentials, un-share/delete rogue
  snapshots, quarantine new instances, preserve control-plane logs, and check
  whether a deleted instance's volumes/snapshots still exist for forensics.
