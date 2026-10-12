---
name: analyzing-azure-activity-logs-for-threats
description: Queries Azure Monitor activity logs and sign-in logs via azure-monitor-query
  to detect suspicious administrative operations, impossible travel, privilege escalation,
  and resource modifications. Builds KQL queries for threat hunting in Azure environments.
  Use when investigating suspicious Azure tenant activity or building cloud SIEM detections.
  Do not use for focused service-principal abuse detection - use detecting-azure-service-principal-abuse.
domain: cybersecurity
subdomain: soc-operations
tags:
- azure
- cloud-security
- azure-monitor
- kql
- threat-hunting
- activity-logs
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1078.004
- T1098.003
- T1538
- T1556.009
- T1580
---

# Analyzing Azure Activity Logs for Threats


## When to Use

- Use when you need a KQL query over AzureActivity for ROLEASSIGNMENTS/WRITE to catch privilege escalation in a tenant.
- Use when hunting "Add member to role" AuditLogs events that grant Global Administrator.
- Use when investigating impossible-travel or new-IP sign-ins via azure-monitor-query against a Log Analytics workspace.
- Use when a Key Vault secret is accessed from an unfamiliar IP, or NSG/conditional-access policies are modified unexpectedly.
- Use when asked to "threat hunt in Azure activity logs" or "build a cloud SIEM detection for suspicious admin operations."

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Use azure-monitor-query to execute KQL queries against Azure Log Analytics workspaces,
detecting suspicious admin operations and sign-in anomalies.

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="AzureActivity | where OperationNameValue has 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' | take 10",
    timespan=timedelta(hours=24),
)
```

Key detection queries:
1. Role assignment changes (privilege escalation)
2. Resource group and subscription modifications
3. Key vault secret access from new IPs
4. Network security group rule changes
5. Conditional access policy modifications

## Examples

```python
# Detect new Global Admin role assignments
query = '''
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue has "Global Administrator"
'''
```
