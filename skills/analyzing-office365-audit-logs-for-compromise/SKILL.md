---
name: analyzing-office365-audit-logs-for-compromise
description: >-
  Parses Office 365 Unified Audit Logs via the Microsoft Graph API to surface malicious email
  forwarding rules, inbox delegation, suspicious OAuth app grants, and other tenant-intrusion
  signals. Use when investigating a suspected O365 mailbox intrusion, hunting rogue forwarding or
  OAuth consent grants, or building detection content from the Unified Audit Log. Keywords:
  Office 365, Unified Audit Log, Microsoft Graph, forwarding rule, mailbox delegation, OAuth
  grant. Do not use for cross-platform email-account-compromise detection spanning Google
  Workspace - use detecting-email-account-compromise.
domain: cybersecurity
subdomain: cloud-security
tags:
- Office365
- Microsoft-Graph
- audit-logs
- email-compromise
- inbox-rules
- OAuth
- BEC
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1114.002
- T1098.002
- T1556.006
- T1078.004
---

# Analyzing Office 365 Audit Logs for Compromise

## Overview

Business Email Compromise (BEC) attacks often leave traces in Office 365 audit logs: suspicious inbox rule creation, email forwarding to external addresses, mailbox delegation changes, and unauthorized OAuth application consent grants. This skill uses the Microsoft Graph API to query the Unified Audit Log, enumerate inbox rules across mailboxes, detect forwarding configurations, and identify compromised account indicators.


## When to Use

- Use when investigating a suspected O365 mailbox intrusion or BEC and need to query the Unified Audit Log via Microsoft Graph for Set-Mailbox and New-InboxRule operations.
- Use when hunting for malicious inbox rules that forward or delete mail, especially forwarding to external addresses.
- Use when detecting mailbox delegation changes (Add-MailboxPermission) added by an attacker.
- Use when identifying suspicious OAuth application consent grants used for persistent mailbox access.
- Use when building a timeline of compromise indicators across affected mailboxes with risk scores.

## Prerequisites

- Azure AD app registration with `AuditLog.Read.All`, `MailboxSettings.Read`, `Mail.Read` (application permissions)
- Python 3.9+ with `msal`, `requests`
- Client secret or certificate for authentication
- Global Reader or Security Reader role

## Steps

1. Authenticate to Microsoft Graph using MSAL client credentials flow
2. Query Unified Audit Log for suspicious operations (Set-Mailbox, New-InboxRule)
3. Enumerate inbox rules across mailboxes and flag forwarding rules
4. Detect mailbox delegation changes (Add-MailboxPermission)
5. Identify OAuth consent grants to suspicious applications
6. Check for suspicious sign-in patterns from audit logs
7. Generate compromise indicator report with timeline

## Expected Output

- JSON report listing forwarding rules, delegation changes, OAuth grants, and suspicious audit events with risk scores
- Timeline of compromise indicators with affected mailboxes

## Example

Authenticate with MSAL (client credentials) and query the Unified Audit Log via Microsoft Graph for the inbox-rule and delegation operations named above:

```python
#!/usr/bin/env python3
"""Pull O365 Unified Audit Log events for BEC indicators via Microsoft Graph."""
import msal
import requests

TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-app-id"
CLIENT_SECRET = "your-client-secret"

SUSPICIOUS_OPS = {"New-InboxRule", "Set-InboxRule", "Set-Mailbox",
                  "Add-MailboxPermission", "Add-MailboxFolderPermission", "Consent to application"}


def get_token():
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    return result["access_token"]


def query_audit_log(token, start, end):
    """Query auditLogs/directoryAudits and the Office 365 management activity feed."""
    headers = {"Authorization": f"Bearer {token}"}
    url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
    params = {"$filter": f"activityDateTime ge {start} and activityDateTime le {end}", "$top": 999}

    findings = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        for event in data.get("value", []):
            op = event.get("activityDisplayName", "")
            if op in SUSPICIOUS_OPS:
                findings.append({
                    "operation": op,
                    "time": event.get("activityDateTime"),
                    "actor": event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName"),
                    "result": event.get("result"),
                })
        url = data.get("@odata.nextLink")
        params = None  # nextLink already encodes the query

    return findings


if __name__ == "__main__":
    token = get_token()
    for f in query_audit_log(token, "2024-01-01T00:00:00Z", "2024-01-31T23:59:59Z"):
        print(f"[!] {f['time']} {f['operation']} by {f['actor']} ({f['result']})")
```
