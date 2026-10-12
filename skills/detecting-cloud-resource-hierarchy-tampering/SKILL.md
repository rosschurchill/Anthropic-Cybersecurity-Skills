---
name: detecting-cloud-resource-hierarchy-tampering
description: 'Detects tampering with cloud resource hierarchy to escape policy inheritance and centralized logging (MITRE T1666) - accounts leaving or being removed from an AWS Organization, OU/management-group moves, SCP/policy detachment, out-of-baseline account/subscription/project creation, and Azure subscription hijacking via tenant transfer - across AWS, Azure, and GCP. Correlates org-management control-plane events (CloudTrail LeaveOrganization/MoveAccount/DetachPolicy, Azure management-group and subscription-transfer operations, GCP MoveProject/MoveFolder) with privileged-role elevation in a short window. Use when hunting cloud defense-evasion via org-structure changes. Keywords: cloud resource hierarchy, AWS Organizations, LeaveOrganization, MoveAccount, SCP detach, Azure management group, subscription transfer, tenant hijack, GCP folder move, T1666. Do not use for compute/snapshot/instance changes - use detecting-cloud-compute-infrastructure-tampering.'
domain: cybersecurity
subdomain: cloud-security
tags:
- cloud-security
- threat-detection
- defense-evasion
- aws-organizations
- management-groups
- subscription-hijack
- scp
- multi-cloud
- t1666
- governance
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-09
- DE.AE-02
- GV.OC-03
- PR.AA-05
- PR.PS-01
mitre_attack:
- T1666
- T1578
- T1098
- T1484
- T1136.003
---

# Detecting Cloud Resource Hierarchy Tampering

## When to Use

Use this skill to detect when an adversary alters the **hierarchical structure**
of a cloud environment to evade defenses and policy inheritance (ATT&CK T1666):
moving accounts/subscriptions/projects out from under organizational guardrails,
leaving an organization, creating accounts outside the governed hierarchy, or
**hijacking a subscription** by transferring it to an attacker-controlled tenant.
These moves escape SCPs / Azure Policy / Org Policy and centralized logging.
Reach for it when hunting cloud defense-evasion via org-structure changes, or
triaging org-management control-plane activity across AWS, Azure, or GCP.

For compute-plane changes (snapshots/instances/configs) use
`detecting-cloud-compute-infrastructure-tampering`.

## Prerequisites

- **AWS CloudTrail** (AWS Organizations API events) in the management account.
- **Azure Activity Log + Microsoft Entra ID audit logs** (`Microsoft.Management/
  managementGroups`, `Microsoft.Subscription/*` transfer operations).
- **GCP Cloud Audit Logs** (Resource Manager, Admin Activity).
- Privileged-role context: recent assignments of AWS Organizations
  management-account access, Entra Global Administrator / `elevateAccess`, GCP
  Organization Admin.
- A **known org baseline** (accounts, OUs/management groups, folders/projects)
  and change tickets.

## Workflow

1. **Baseline the hierarchy and its change automation.** Record the legitimate
   principals that create accounts, move OUs, and manage policies.
2. **AWS.** Alert on `LeaveOrganization`, `RemoveAccountFromOrganization`,
   `MoveAccount`, `CreateAccount`/`CloseAccount`, OU create/delete, and SCP
   detach/disable (`DetachPolicy`, `DisablePolicyType`) outside change control. A
   member account leaving the org drops out of centralized guardrails and
   consolidated CloudTrail/billing.
3. **Azure.** Alert on new subscription creation by a Global Admin outside
   baseline, management-group moves, and especially **subscription hijacking** —
   a subscription transferred from the victim tenant to an adversary-controlled
   directory ("change directory"). Correlate with a recent Global Admin elevation
   or `elevateAccess`.
4. **GCP.** Alert on `MoveProject`/`MoveFolder` relocating a project out of a
   policed folder, and org/folder `SetIamPolicy` changes.
5. **Core correlation (DET0155).** Link a **privileged-role assignment →
   hierarchy/structure change** within a short window; check new
   accounts/subscriptions/projects and tenant transfers against the org baseline.
6. **Respond** (see *Response*) — reverse unauthorized moves and audit what ran
   while a resource was outside guardrails.

## Key Concepts

- **The goal is escaping inheritance:** moving a resource out of an OU/management
  group/folder detaches it from SCPs/Policy and centralized logging — defenses
  stop applying without being "disabled."
- **Subscription hijack is the Azure headline:** transferring a subscription to
  an attacker tenant is both evasion and theft; it needs Global Admin context to
  confirm.
- **Elevation + structure change is the signal:** a role elevation immediately
  followed by a hierarchy change is the high-confidence correlation.
- **Logging must outlive the move:** org-level logging has to be centralized and
  immutable so a departing/moved account cannot sever its own trail.

## Tools & Systems

AWS CloudTrail + AWS Organizations, AWS Config, SCPs; Azure Activity Log,
Microsoft Entra ID audit logs, Microsoft Defender for Cloud, Microsoft Sentinel
(KQL), Azure Policy; GCP Cloud Audit Logs, Resource Manager, Security Command
Center, Organization Policy Service; Splunk, Prowler/ScoutSuite, Cloud Custodian.

## Detection Queries

### Splunk -- AWS Organizations structural change

```spl
`cloudtrail` eventSource="organizations.amazonaws.com"
  eventName IN ("LeaveOrganization","RemoveAccountFromOrganization","MoveAccount",
                "CreateAccount","DetachPolicy","DisablePolicyType","CloseAccount")
| stats values(eventName) as evts count by userIdentity.arn, sourceIPAddress, recipientAccountId
| search NOT [ | inputlookup org_change_automation | fields arn ]
```

### KQL -- Azure management-group move / subscription transfer + role elevation

```kql
let struct = AzureActivity
| where OperationNameValue has_any
    ("Microsoft.Management/managementGroups/subscriptions/write",
     "Microsoft.Management/managementGroups/write",
     "Microsoft.Subscription")                 // subscription transfer / create
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue;
let elev = AuditLogs
| where OperationName in ("Add member to role","Elevate access")
| project elevTime=TimeGenerated, Caller=tostring(InitiatedBy.user.userPrincipalName);
struct | join kind=inner elev on Caller
| where (TimeGenerated - elevTime) between (0min .. 30min)
```

### GCP -- project/folder move (concept)

```
protoPayload.methodName=("google.cloud.resourcemanager.v3.Projects.MoveProject"
  OR "google.cloud.resourcemanager.v3.Folders.MoveFolder"
  OR "SetIamPolicy")
AND resource.type=("project" OR "folder" OR "organization")
```

## Common Scenarios

- **Account breakout (AWS):** attacker calls `LeaveOrganization` on a member
  account to drop SCPs and consolidated logging.
- **SCP detach:** `DetachPolicy` removes a deny guardrail before abuse.
- **Subscription hijack (Azure):** a subscription is transferred to an attacker
  tenant after a Global Admin elevation.
- **Project relocation (GCP):** `MoveProject` moves a project out of a policed
  folder.
- **False positive:** a planned reorg by the cloud platform team in a change
  window — suppressed by change-control correlation.

## Output Format

```
CLOUD HIERARCHY TAMPERING DETECTION
  Cloud:           <aws|azure|gcp>
  Verdict:         <confirmed | suspected | approved-change>
  Action:          <LeaveOrganization | MoveAccount | DetachPolicy | subscription transfer | MoveProject>
  Principal:       <arn/caller> (role elevated <t-elev>?) from <ip/geo>
  Target:          <account/subscription/project> -> <new parent/tenant>
  ATT&CK:          T1666[, T1578, T1098, T1484, T1136.003]
  Actions taken:   <move reversed | creds/roles revoked | SCP re-attached | out-of-guardrail activity audited>
```

## Response

- **Lock the org-management plane:** restrict who can call Organizations /
  management-group / Resource-Manager APIs; require MFA and break-glass; SCP to
  deny `organizations:LeaveOrganization`/`RemoveAccountFromOrganization` for
  non-management principals; Azure policy to restrict subscription transfer /
  tenant change; GCP org-policy constraints on project moves (NIST CSF PR.AA-05).
- Ensure **org-level logging is centralized and immutable** so a departing/moved
  account cannot sever the trail.
- **Respond:** reverse unauthorized moves/transfers, revoke the actor's
  credentials/roles, re-attach detached SCPs/policies, and audit what was
  deployed in any new or moved account/subscription/project while it was outside
  guardrails.
