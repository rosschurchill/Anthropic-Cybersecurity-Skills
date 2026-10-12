---
name: detecting-azure-lateral-movement
description: >-
  Detects lateral movement in Azure AD/Entra ID using Microsoft Graph API audit logs, Azure
  Sentinel KQL hunting queries, and sign-in anomaly correlation to identify privilege escalation,
  token theft, and cross-tenant pivoting. Use when hunting cloud-identity lateral movement in
  Entra, correlating sign-in anomalies with privilege changes, or writing Sentinel KQL for
  token-theft and cross-tenant pivots. Keywords: Azure AD, Entra ID, Microsoft Graph, Sentinel
  KQL, token theft, cross-tenant, sign-in anomaly. Do not use for on-premises network
  lateral-movement detection - use detecting-lateral-movement-in-network.
domain: cybersecurity
subdomain: cloud-security
tags:
- azure
- entra-id
- lateral-movement
- sentinel
- kql
- graph-api
- cloud-security
- threat-hunting
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1078.004
- T1550.001
- T1021.007
- T1098.003
- T1528
---

# Detecting Azure Lateral Movement

## Overview

Lateral movement in Azure AD/Entra ID differs from on-premises environments. Attackers pivot through OAuth application consent grants, service principal abuse, cross-tenant access policies, and stolen refresh tokens rather than SMB/RDP connections. Detection requires correlating Microsoft Graph API audit logs, Azure AD sign-in logs, and Entra ID protection risk events using KQL queries in Microsoft Sentinel. This skill covers building detection analytics for common Azure lateral movement techniques including application impersonation, mailbox delegation abuse, and conditional access policy bypasses.


## When to Use

- Use when hunting cloud-identity lateral movement in Entra ID rather than on-prem SMB/RDP
- Use when writing Sentinel KQL for token replay, cross-tenant sign-ins, or OAuth consent grants
- Use when correlating sign-in anomalies with privilege or directory changes within a time window
- Use when detecting service principal credential additions or mailbox delegation (FullAccess, SendAs) abuse
- Use when building Sentinel playbooks to revoke suspicious OAuth grants or disable compromised service principals

## Prerequisites

- Azure subscription with Microsoft Sentinel workspace configured
- Azure AD P2 or Entra ID P2 license for risk-based sign-in detection
- Microsoft Graph API permissions: AuditLog.Read.All, Directory.Read.All, SecurityEvents.Read.All
- Log Analytics workspace ingesting AuditLogs, SigninLogs, and AADServicePrincipalSignInLogs
- Familiarity with KQL (Kusto Query Language)

## Steps

### Step 1: Configure Log Ingestion

Enable diagnostic settings to stream Azure AD logs to Log Analytics:
- Sign-in logs (interactive and non-interactive)
- Audit logs (directory changes, app consent)
- Service principal sign-in logs
- Provisioning logs
- Risky users and risk detections

### Step 2: Build Detection Queries

Create KQL analytics rules in Sentinel for:
- Unusual service principal credential additions
- OAuth application consent grants to unknown apps
- Cross-tenant sign-ins from new tenants
- Token replay from different IP/user-agent combinations
- Mailbox delegation changes (FullAccess, SendAs)

### Step 3: Correlate Events

Chain multiple low-confidence indicators into high-confidence lateral movement detections by correlating sign-in anomalies with directory changes within time windows.

### Step 4: Automate Response

Create Sentinel playbooks (Logic Apps) to automatically revoke suspicious OAuth grants, disable compromised service principals, and enforce step-up authentication.

## Expected Output

JSON report containing detected lateral movement indicators, correlated event chains, affected identities, and recommended containment actions with MITRE ATT&CK technique mappings.

## Detection Query

Correlate an OAuth app consent grant with a service principal credential addition on the same app (Step 2/3) using Sentinel KQL over the `AuditLogs` table:

```kql
// Consent to an application quickly followed by a new SP credential = likely persistence pivot
AuditLogs
| where OperationName in ("Consent to application", "Add OAuth2PermissionGrant")
| extend AppName = tostring(TargetResources[0].displayName)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project ConsentTime = TimeGenerated, Initiator, AppName, OperationName, CorrelationId
| join kind=inner (
    AuditLogs
    | where OperationName == "Add service principal credentials"
    | extend AppName = tostring(TargetResources[0].displayName)
    | project CredAddTime = TimeGenerated, AppName
  ) on AppName
| where CredAddTime between (ConsentTime .. (ConsentTime + 1h))
| project ConsentTime, CredAddTime, Initiator, AppName, CorrelationId
| sort by ConsentTime desc
```
