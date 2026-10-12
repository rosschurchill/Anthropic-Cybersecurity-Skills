---
name: detecting-suspicious-oauth-application-consent
description: 'Detect risky OAuth application consent grants in Azure AD / Microsoft Entra ID using the Microsoft Graph API, audit logs, and permission analysis to identify illicit consent grant attacks. Use when investigating a suspected illicit consent grant, hunting over-privileged or attacker-registered applications, reviewing admin-consent and delegated permission grants, or validating detection coverage for consent phishing. Keywords: Entra ID, Microsoft Graph, OAuth consent, illicit consent grant, service principal, delegated permissions, admin consent, audit log. Do not use for detecting stolen or replayed OAuth tokens — use detecting-oauth-token-theft. Do not use for OAuth app-integration persistence across Microsoft 365, Google Workspace and SaaS - use detecting-malicious-cloud-app-integration.'
domain: cybersecurity
subdomain: cloud-security
tags:
- OAuth
- Azure-AD
- Entra-ID
- Microsoft-Graph
- illicit-consent
- cloud-security
- application-permissions
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1528
- T1550.001
- T1098.001
- T1566.002
---

# Detecting Suspicious OAuth Application Consent

## Overview

Illicit consent grant attacks trick users into granting excessive permissions to malicious OAuth applications in Azure AD / Microsoft Entra ID. This skill uses the Microsoft Graph API to enumerate OAuth2 permission grants, analyze application permissions for overly broad scopes, review directory audit logs for consent events, and flag high-risk applications based on publisher verification status and permission scope.


## When to Use

- Use when investigating a suspected illicit consent grant attack in Azure AD / Microsoft Entra ID.
- Use when enumerating OAuth2 permission grants via Microsoft Graph `/oauth2PermissionGrants` to hunt over-privileged or attacker-registered applications.
- Use when reviewing directory audit logs for `Consent to application` events and tying them to the granting user and IP.
- Use when flagging apps requesting high-risk scopes (Mail.Read, Files.ReadWrite.All) or published by unverified publishers.
- Use when validating detection coverage for consent phishing across your tenant's service principals.

## Prerequisites

- Azure AD / Entra ID tenant with Global Reader or Security Reader role
- Microsoft Graph API access with `Application.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`
- Python 3.9+ with `msal`, `requests`
- App registration with client secret or certificate for authentication

## Steps

1. Authenticate to Microsoft Graph using MSAL client credentials flow
2. Enumerate all OAuth2 permission grants via `/oauth2PermissionGrants`
3. List service principals and their assigned application permissions
4. Query directory audit logs for `Consent to application` events
5. Flag applications with high-risk scopes (Mail.Read, Files.ReadWrite.All, etc.)
6. Check publisher verification status for each application
7. Generate risk report with remediation recommendations

## Example

Authenticate with MSAL client credentials and enumerate OAuth2 permission grants,
flagging high-risk delegated scopes:

```python
import msal
import requests

TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-app-id"
CLIENT_SECRET = "your-client-secret"
GRAPH = "https://graph.microsoft.com/v1.0"

HIGH_RISK_SCOPES = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.ReadWrite.All", "Directory.ReadWrite.All",
    "User.Read.All", "offline_access",
}

app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    client_credential=CLIENT_SECRET,
)
token = app.acquire_token_for_client(
    scopes=["https://graph.microsoft.com/.default"]
)["access_token"]
headers = {"Authorization": f"Bearer {token}"}

grants = requests.get(f"{GRAPH}/oauth2PermissionGrants", headers=headers).json()
for grant in grants.get("value", []):
    scopes = set((grant.get("scope") or "").split())
    risky = scopes & HIGH_RISK_SCOPES
    if risky:
        # consentType "AllPrincipals" means tenant-wide admin consent
        print(f"clientId={grant['clientId']} consentType={grant['consentType']} "
              f"risky_scopes={sorted(risky)}")
```

## Expected Output

- JSON report listing all OAuth apps with granted permissions, risk scores, unverified publishers, and suspicious consent patterns
- Audit trail of consent grant events with user and IP details
