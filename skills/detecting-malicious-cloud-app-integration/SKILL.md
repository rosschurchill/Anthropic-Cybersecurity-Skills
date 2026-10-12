---
name: detecting-malicious-cloud-app-integration
description: 'Detects persistence via malicious cloud application integration (MITRE T1671) - rogue OAuth app registrations, illicit consent grants, admin-consent bypass, new app secrets/certs on service principals, and over-scoped third-party app authorizations across Microsoft 365/Entra ID, Google Workspace, and SaaS (Slack, Salesforce). Correlates app creation/consent events (Consent to application, Add delegated permission grant, Add app role assignment to service principal, Add service principal credentials) with the service-principal sign-ins and data access that follow. Use when hunting OAuth persistence, consent-grant attacks, or rogue enterprise apps. Keywords: OAuth consent, illicit consent grant, enterprise application, service principal, app registration, Graph permissions, domain-wide delegation, T1671. Do not use for credential/sign-in abuse of already-trusted apps - use detecting-azure-service-principal-abuse.'
domain: cybersecurity
subdomain: identity-access-management
tags:
- identity-access-management
- threat-detection
- persistence
- oauth
- consent-grant
- entra-id
- service-principal
- microsoft-365
- t1671
- cloud-security
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-06
- DE.CM-09
- PR.AA-01
- PR.AA-05
- ID.AM-04
mitre_attack:
- T1671
- T1098.003
- T1550.001
- T1528
- T1136.003
---

# Detecting Malicious Cloud Application Integration

## When to Use

Use this skill to detect adversaries establishing persistence by **abusing
OAuth / enterprise-app integrations** in SaaS and cloud identity platforms
(ATT&CK T1671): registering a custom application, adding a legitimate app into the
tenant, or co-opting an existing integration, then granting it broad delegated or
application permissions so it retains access **independent of any user credential
or MFA**. Reach for it when:

- Hunting OAuth persistence or consent-grant ("illicit consent") attacks.
- A new enterprise app or service-principal credential appears unexpectedly.
- An app with high-risk Graph scopes is consented by a privileged user.

For credential/sign-in abuse of already-trusted apps use
`detecting-azure-service-principal-abuse`; for broad O365 audit triage use
`analyzing-office365-audit-logs-for-compromise`.

## Prerequisites

- **Microsoft Entra ID audit / M365 unified audit log**: `Consent to
  application`, `Add service principal`, `Add service principal credentials`,
  `Add app role assignment to service principal`, `Add delegated permission grant`
  / `Add OAuth2PermissionGrant`, `Add application`. (Verify exact operation
  strings against a live tenant export.)
- **Microsoft Graph sign-in logs** (service-principal / non-interactive
  sign-ins).
- **Google Workspace** Admin / token audit logs (OAuth grants, domain-wide
  delegation); **SaaS** admin logs (Slack app install/approval, Salesforce
  Connected App creation).
- Context: consenting principal (privileged?), app publisher / verified-publisher
  status, app age, requested scopes.
- A **baseline of approved integrations**.

## Workflow

1. **Baseline approved integrations** (app IDs, publishers, scopes) and who may
   register apps / add SP credentials.
2. **Watch the consent/registration control plane.** Alert on new OAuth app
   registrations, unexpected consent grants, app-role assignments, and **new
   credentials added to an existing app** (a stealthy backdoor).
3. **Prioritize high-risk signals:** consent to apps requesting high-risk scopes
   (`Mail.ReadWrite`, `Directory.ReadWrite.All`, `full_access_as_app`), consent by
   privileged accounts, admin-consent bypass (app granted app-role assignments
   without standard admin consent), apps with no verified publisher, first-seen
   app IDs.
4. **Correlate to activity.** Join app creation/consent to the service-principal
   sign-ins and data access that follow — SP sign-ins from new ASNs/countries
   shortly after consent are high-signal.
5. **Multi-platform.** Apply the same pattern to Google Workspace OAuth grants /
   domain-wide delegation and SaaS connected-app installs.
6. **Respond** (see *Response*).

## Key Concepts

- **App identity outlives user creds:** an app/service principal with granted
  permissions keeps access through password resets and MFA — which is exactly why
  attackers use it for persistence.
- **Consent is the grant:** the `Consent to application` / `Add delegated
  permission grant` event is the moment access is established; scope + consenter
  decide severity.
- **New secret on an old app = backdoor:** `Add service principal credentials`
  on an existing trusted app is a quiet way to hijack it — watch it specifically.
- **Admin-consent bypass:** app-role assignments granted without the normal
  admin-consent workflow indicate the attacker already held privilege.

## Tools & Systems

Microsoft Entra ID / Entra admin center, M365 unified audit log + Purview,
Microsoft Graph API, Microsoft Sentinel (KQL), Microsoft Defender for Cloud Apps;
Splunk ESCU; Elastic Security prebuilt rules; Google Workspace Admin console +
Admin SDK Reports API; the Microsoft/CISA app-and-consent review toolkit.

## Detection Queries

### KQL -- illicit consent / SP credential add with high-risk scope

```kql
AuditLogs
| where OperationName in ("Consent to application","Add delegated permission grant",
    "Add app role assignment to service principal","Add service principal credentials")
| extend app = tostring(TargetResources[0].displayName)
| extend props = tostring(TargetResources[0].modifiedProperties)
| where props has_any ("ReadWrite","Directory.ReadWrite.All","Mail.Read","full_access")
    or OperationName == "Add service principal credentials"
| project TimeGenerated, OperationName, InitiatedBy, app, props
```

### KQL -- SP sign-in from new infrastructure shortly after consent

```kql
let consents = AuditLogs
| where OperationName == "Consent to application"
| project consentTime=TimeGenerated, app=tostring(TargetResources[0].displayName);
AADServicePrincipalSignInLogs
| join kind=inner consents on $left.AppDisplayName == $right.app
| where TimeGenerated between (consentTime .. consentTime + 24h)
| summarize asns=dcount(tostring(parse_json(tostring(Location)).countryOrRegion)) by AppDisplayName, consentTime
| where asns > 1
```

### Google Workspace -- third-party OAuth grant (concept)

```
# Admin SDK Reports: token audit — new client_id authorized with broad scopes
applicationName=token AND event.name=authorize
AND scope has_any ("https://mail.google.com/","https://www.googleapis.com/auth/admin")
```

## Common Scenarios

- **Illicit consent phish:** a user consents to a rogue app requesting
  `Mail.ReadWrite` — app then reads the mailbox via Graph with no further auth.
- **Old-app backdoor:** attacker adds a new client secret to a trusted SP
  (`Add service principal credentials`) and signs in as the app.
- **Domain-wide delegation (Google):** a service account granted broad delegation
  reads all mailboxes.
- **False positive:** IT onboarding an approved SaaS integration with admin
  consent in a change window — allowlisted.

## Output Format

```
CLOUD APP INTEGRATION DETECTION
  Platform:        <M365/Entra | Google Workspace | Slack/Salesforce>
  Verdict:         <confirmed | suspected | approved-integration>
  Event:           <consent | delegated grant | app-role assignment | new SP credential>
  App:             <display name / id>, publisher <verified?>, first-seen <y/n>
  Scopes:          <high-risk scopes granted>
  Consenter:       <user> (privileged: <y/n>)
  Follow-on:       <SP sign-in from new ASN/geo | mailbox/file access | none>
  ATT&CK:          T1671[, T1098.003, T1550.001, T1528, T1136.003]
  Actions taken:   <consent revoked | SP/secret deleted | tokens invalidated | accessed data scoped>
```

## Response

- **Revoke the illicit consent / delete the service principal and app secrets;
  invalidate issued refresh/access tokens.**
- Restrict user consent (Entra "Do not allow user consent" + admin-consent
  workflow), require verified publishers, and limit who can register apps / add
  SP credentials (NIST CSF PR.AA-05).
- Google Workspace: restrict third-party app access by scope and control
  domain-wide delegation.
- **Investigate what the app accessed** while authorized (mailboxes, files,
  directory) and hunt for data taken via the app token.
