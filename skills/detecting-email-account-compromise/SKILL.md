---
name: detecting-email-account-compromise
description: >-
  Detect compromised O365 and Google Workspace email accounts by analyzing Unified Audit Logs and
  Azure AD sign-in logs for impossible travel, inbox rule creation/deletion (Set-InboxRule,
  New-InboxRule), external mail forwarding rules, and unusual Microsoft Graph API access or OAuth
  token use. Use when investigating suspected business email compromise (BEC), account takeover,
  or mailbox persistence via malicious inbox rules. Do not use for vendor or executive
  impersonation fraud without a compromised account - use detecting-business-email-compromise.
domain: cybersecurity
subdomain: incident-response
tags:
- email-compromise
- office365
- microsoft-graph
- bec
- inbox-rules
- sign-in-analysis
- account-takeover
mitre_attack:
- T1486
- T1490
- T1070
- T1078
- T1566
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
---
# Detecting Email Account Compromise

## Overview

Email account compromise (EAC) is a prevalent attack vector where adversaries gain unauthorized access to mailboxes to exfiltrate sensitive data, conduct business email compromise (BEC), or establish persistence through inbox rule manipulation. Attackers commonly create forwarding rules to siphon emails, delete rules to hide evidence, or use OAuth tokens for persistent access. Detection relies on analyzing Microsoft 365 Unified Audit Logs, Azure AD sign-in logs for impossible travel or suspicious locations, inbox rule creation events (Set-InboxRule, New-InboxRule), and Microsoft Graph API access patterns. Key indicators include forwarding rules to external addresses, rules that delete or move messages matching keywords like "invoice" or "payment", and sign-ins from unusual user agents such as python-requests.


## When to Use

- Use when investigating a suspected account takeover in Microsoft 365 or Google Workspace and need to pull inbox rules via Microsoft Graph
- Use when hunting malicious inbox rules (New-InboxRule, Set-InboxRule) that forward or delete mail matching "invoice" or "payment"
- Use when Azure AD sign-in logs show impossible travel or sign-ins from suspicious user agents like python-requests
- Use when auditing OAuth application consent grants for suspicious third-party apps with mailbox access
- Use when confirming mailbox persistence behind a BEC incident by correlating findings across multiple compromised users

## Prerequisites

- Microsoft 365 with Unified Audit Logging enabled
- Azure AD P1/P2 for risk detection APIs
- Python 3.9+ with `requests`, `msal` libraries
- Microsoft Graph API application registration with Mail.Read, AuditLog.Read.All permissions
- Understanding of OAuth2 client credential flows

## Steps

1. Export audit logs or connect to Microsoft Graph API using MSAL authentication
2. Query inbox rules for all monitored mailboxes via `/users/{id}/mailFolders/inbox/messageRules`
3. Analyze rules for external forwarding (ForwardTo, RedirectTo external addresses)
4. Detect suspicious rule patterns: deletion rules, keyword-matching rules targeting financial terms
5. Query sign-in logs via `/auditLogs/signIns` for unusual locations and impossible travel
6. Check for suspicious user agent strings (python-requests, PowerShell, curl)
7. Identify OAuth application consent grants for suspicious third-party apps
8. Correlate findings across users to detect campaign-level compromise
9. Generate compromise indicators report with severity scores

## Example

Steps 1-4 in code: authenticate with MSAL and pull each mailbox's inbox rules via Microsoft Graph, flagging external forwarding and deletion rules.

```python
import msal, requests

TENANT, CLIENT_ID, SECRET = "<tenant>", "<app-id>", "<secret>"
app = msal.ConfidentialClientApplication(
    CLIENT_ID, authority=f"https://login.microsoftonline.com/{TENANT}",
    client_credential=SECRET)
token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
hdr = {"Authorization": "Bearer " + token["access_token"]}

def suspicious_rules(user_id, internal_domain):
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/mailFolders/inbox/messageRules"
    for rule in requests.get(url, headers=hdr).json().get("value", []):
        acts = rule.get("actions", {})
        fwd = acts.get("forwardTo", []) + acts.get("redirectTo", [])
        ext = [a["emailAddress"]["address"] for a in fwd
               if not a["emailAddress"]["address"].endswith(internal_domain)]
        if ext or acts.get("delete"):
            yield {"rule": rule.get("displayName"), "forwardsTo": ext,
                   "deletes": bool(acts.get("delete"))}
```

## Expected Output

A JSON report listing compromised or suspicious accounts, malicious inbox rules detected, impossible travel events, suspicious OAuth grants, and recommended containment actions with severity ratings.
