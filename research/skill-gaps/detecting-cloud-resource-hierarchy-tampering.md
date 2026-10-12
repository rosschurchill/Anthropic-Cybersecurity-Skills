# Detecting Cloud Resource Hierarchy Tampering — research notes

- **Proposed slug:** detecting-cloud-resource-hierarchy-tampering
- **ATT&CK:** T1666 Modify Cloud Resource Hierarchy (tactic: defense-evasion). Detection strategy: **DET0155**. Related: T1578 Modify Cloud Compute Infrastructure, T1098 Account Manipulation, T1484 Domain/Tenant Policy Modification, T1136.003 Create Cloud Account.
- **Status:** research (not yet a skill)

## Defensive goal
Detect when an adversary alters the hierarchical structure of a cloud environment to evade defenses and policy inheritance — moving accounts/subscriptions/projects out from under organizational guardrails, leaving an organization, creating accounts/subscriptions outside the governed hierarchy, or hijacking a subscription by transferring it to an attacker-controlled tenant. These moves escape SCPs/Azure Policy/Org Policy and centralized logging, so the skill watches the org-management control plane for structural changes that fall outside baseline.

## Data sources / telemetry
- **AWS CloudTrail (AWS Organizations API):** `LeaveOrganization`, `RemoveAccountFromOrganization`, `CreateAccount`, `CloseAccount`, `MoveAccount` (between OUs), `CreateOrganizationalUnit`, `DeleteOrganizationalUnit`, `DisablePolicyType`, `DetachPolicy`/`DisablePolicy` (detaching SCPs), `AcceptHandshake`/`InviteAccountToOrganization`. Fields: `userIdentity`, `sourceIPAddress`, `recipientAccountId`.
- **Azure Activity Log / Microsoft Entra / Microsoft.Management:** management-group create/move operations (`Microsoft.Management/managementGroups/write`, `.../subscriptions/write` to move a subscription under a management group), subscription creation, and **subscription transfer / directory (tenant) change** (`Microsoft.Subscription/...`, "Change directory" / `transferBillingSubscription`) — verify exact operationNames; correlate with Entra ID audit logs for Global Administrator role use.
- **GCP Cloud Audit Logs (Resource Manager, Admin Activity):** `google.cloud.resourcemanager.v3.Projects.MoveProject`, `...Folders.CreateFolder`/`MoveFolder`, `SetIamPolicy` at org/folder level, `Projects.Create`/`Projects.Delete` (verify method names).
- IAM/role context: recent privileged-role assignments (e.g. Entra Global Admin, AWS Organizations management-account access, GCP Organization Admin) to tie elevation to the structural change.

## Detection logic / approach
Per DET0155, monitor for unusual changes to AWS Organizations and Azure Management Groups and correlate role elevation with hierarchy changes in a short window:
- **AWS:** alert on `LeaveOrganization`, `RemoveAccountFromOrganization`, `MoveAccount`, `CreateAccount`, and SCP detach/disable (`DetachPolicy`, `DisablePolicyType`) — any of these outside change control. A member account leaving the org drops it out of centralized guardrails and consolidated CloudTrail/billing.
- **Azure:** alert on new subscription creation by a Global Administrator outside baseline, management-group moves, and especially **subscription hijacking** — a pay-as-you-go/EA subscription transferred from the victim tenant to an adversary-controlled tenant (directory change). Correlate with a recent Global Admin elevation or `elevateAccess` (root management-group access grant).
- **GCP:** alert on `MoveProject`/`MoveFolder` that relocates a project out of a policed folder, and org/folder `SetIamPolicy` changes.
- **Core correlation (DET0155):** link privileged-role assignment → hierarchy/structure change within N minutes; check new subscriptions/accounts/projects and tenant transfers against the known org baseline and change tickets.

Example Splunk SPL (AWS):
```
index=cloudtrail eventSource=organizations.amazonaws.com
  eventName IN ("LeaveOrganization","RemoveAccountFromOrganization","MoveAccount","CreateAccount","DetachPolicy","DisablePolicyType")
| stats values(eventName) count by userIdentity.arn sourceIPAddress recipientAccountId
| where NOT [inline allowlist of change-automation principals]
```
Example KQL (Azure) — filter `AzureActivity`/`MicrosoftGraphActivityLogs` for management-group writes and subscription directory transfers, join to `AuditLogs` role-assignment events within 30m.

## Response / mitigation
- Lock the org-management plane: restrict who can call Organizations/management-group/Resource-Manager APIs; require MFA and break-glass procedures; AWS SCP to deny `organizations:LeaveOrganization`/`RemoveAccountFromOrganization` for non-management principals; Azure policy to restrict subscription transfer and tenant change; GCP org policy constraints on project moves.
- Ensure org-level logging is itself centralized and immutable so a departing/moved account cannot sever the audit trail.
- Response: reverse unauthorized moves/transfers, revoke the actor's credentials/roles, re-attach detached SCPs/policies, and audit what was deployed in any new or moved account/subscription/project while it was outside guardrails.

## Real tools
AWS CloudTrail + AWS Organizations, AWS Config, SCPs; Azure Activity Log, Microsoft Entra ID audit logs, Microsoft Defender for Cloud, Microsoft Sentinel (KQL), Azure Policy; GCP Cloud Audit Logs, Resource Manager, Security Command Center, Organization Policy Service; Splunk, Prowler/ScoutSuite (posture), Cloud Custodian.

## Draft frontmatter mappings
- mitre_attack: [T1666, T1578, T1098, T1484, T1136.003]
- nist_csf: [DE.CM-09, DE.AE-02, GV.OC-03, PR.AA-05, PR.PS-01]
- d3fend (optional): candidate D3-ANAA (Administrative Network Activity Analysis) n/a-verify; D3-UAA (User Account Analysis) — verify exact ids
- suggested subdomain: cloud-security
- nearest existing sibling (for the negative trigger): detecting-aws-cloudtrail-anomalies

## Draft description (<=1024 chars)
Detects tampering with cloud resource hierarchy to escape policy inheritance and centralized logging — accounts leaving or being removed from an AWS Organization, OU/management-group moves, SCP/policy detachment, out-of-baseline account/subscription/project creation, and Azure subscription hijacking via tenant transfer — across AWS, Azure, and GCP. Correlates org-management control-plane events (CloudTrail LeaveOrganization/MoveAccount/DetachPolicy, Azure management-group and subscription-transfer operations, GCP MoveProject/MoveFolder) with privileged-role elevation in a short window. Use when hunting cloud defense-evasion via org-structure changes. Keywords: cloud resource hierarchy, AWS Organizations, LeaveOrganization, MoveAccount, SCP detach, Azure management group, subscription transfer, tenant hijack, GCP folder/project move, T1666. Do not use for compute/snapshot/instance changes (use detecting-cloud-compute-infrastructure-tampering) or generic CloudTrail anomaly baselining (use detecting-aws-cloudtrail-anomalies).

## Key references
- https://attack.mitre.org/techniques/T1666/
- https://attack.mitre.org/detectionstrategies/DET0155
- https://mitre.ptsecurity.com/en-US/T1666 (verify against live MITRE page)
- https://redteam.y-security.de/MITRE/techniques/T1666/

## Open questions / scope boundaries
- Verify exact Azure operationNames for subscription transfer / "change directory" and the GCP Resource Manager method names before writing provider queries.
- Confirm GCP-specific DET0155 coverage (sources were AWS/Azure-leaning) — GCP equivalents (organizations/folders/projects) are inferred and must be verified.
- Must NOT cover compute-plane changes (T1578 — sibling skill), identity-only abuse (account manipulation skills), or tenant/domain *policy* modification without a structural move (T1484) beyond the correlation hook.
- Decide multi-cloud vs. per-provider; a multi-cloud skill fills the gap but each provider's query set should be verifiable independently.
