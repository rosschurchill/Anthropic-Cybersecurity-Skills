# Detecting Malicious Cloud Application Integration — research notes

- **Proposed slug:** detecting-malicious-cloud-app-integration
- **ATT&CK:** T1671 Cloud Application Integration (tactic: persistence). Detection strategy: **DET0539** (analytics AN1487 for Microsoft 365 / Google Workspace, AN1488 for SaaS such as Slack/Salesforce). No sub-techniques as of v19.2 (verify — T1671 is a newer technique and sub-techniques may be added). Closely related: T1098.003 Additional Cloud Roles, T1550.001 Application Access Token, T1528 Steal Application Access Token, T1136.003 Create Cloud Account.
- **Status:** research (not yet a skill)

## Defensive goal
Detect adversaries establishing persistence by abusing OAuth/enterprise-app integrations in SaaS and cloud identity platforms: registering a custom application, adding a legitimate app into the tenant, or co-opting an existing integration, then granting it broad delegated or application permissions so it retains access independent of any user credential or MFA. The skill watches the app-registration and consent control plane for new or modified integrations and correlates them with the service principal / consumer activity that follows.

## Data sources / telemetry
- **Microsoft Entra ID audit logs / Microsoft 365 unified audit log:** `Consent to application`, `Add service principal`, `Add service principal credentials` (new client secret/certificate on an app), `Add app role assignment to service principal`, `Add delegated permission grant` / `Add OAuth2PermissionGrant`, `Add application`, `Update application – Certificates and secrets management`. (Verify exact operation strings against a live tenant export — Entra forwards audit data into the M365 unified log.)
- **Microsoft Graph sign-in logs (service principal sign-ins):** non-interactive app/SP sign-ins, token requests by the new app.
- **Google Workspace Admin audit / token audit logs:** OAuth token grants, third-party app authorizations, domain-wide delegation changes.
- **SaaS platform admin/audit logs (AN1488):** Slack app install/approval events, Salesforce Connected App creation and OAuth grants, unusual scope/permission grants.
- Context: identity of the consenting principal (privileged vs. regular user), app publisher/verified-publisher status, app age, requested scopes (e.g. `Mail.ReadWrite`, `Directory.ReadWrite.All`, `full_access_as_app`).

## Detection logic / approach
Per DET0539 (AN1487): alert on new OAuth app registrations, unexpected consent grants, and privilege assignments in O365/Google Workspace, correlating app creation/modification with the user or service principal activity that follows. Prioritise consent to apps requesting high-risk scopes, consent by privileged accounts, admin-consent bypass (app granted app-role assignments without standard admin consent), and new credentials added to an existing app.

Example KQL (Microsoft Sentinel, illicit consent / SP credential add):
```kql
AuditLogs
| where OperationName in ("Consent to application","Add delegated permission grant",
    "Add app role assignment to service principal","Add service principal credentials")
| extend app = tostring(TargetResources[0].displayName)
| extend scopes = tostring(parse_json(tostring(TargetResources[0].modifiedProperties)))
| where scopes has_any ("ReadWrite","Directory.ReadWrite.All","Mail.Read","full_access")
   or OperationName == "Add service principal credentials"
| project TimeGenerated, OperationName, InitiatedBy, app, scopes
```
Also: baseline the set of known approved integrations; flag first-seen app IDs, apps with no verified publisher, and SP sign-ins from new ASNs/countries shortly after consent. (See Splunk ESCU "O365 Admin Consent Bypassed by Service Principal" and Elastic "Possible Consent Grant Attack via Azure-Registered Application".)

## Response / mitigation
- Revoke the illicit consent grant / delete the service principal and any app secrets; invalidate issued refresh/access tokens.
- Restrict user consent (Entra: "Do not allow user consent" + admin-consent workflow); require verified publishers; limit who can register apps and add SP credentials.
- Google Workspace: restrict third-party app access by scope, control domain-wide delegation.
- Investigate what the app accessed while authorized (mailboxes, files, directory) and hunt for data accessed via the app token.

## Real tools
Microsoft Entra ID / Entra admin center, Microsoft 365 unified audit log + Microsoft Purview, Microsoft Graph API, Microsoft Sentinel (KQL), Microsoft Defender for Cloud Apps; Splunk ESCU (research.splunk.com); Elastic Security prebuilt rules; Google Workspace Admin console + Admin SDK Reports API; CISA/Microsoft "Osprey" (formerly Hawk) PowerShell toolkit for tenant app/consent review; CrowdStrike/Hunters SaaS detections.

## Draft frontmatter mappings
- mitre_attack: [T1671, T1098.003, T1550.001, T1528, T1136.003]
- nist_csf: [DE.CM-09, DE.CM-06, PR.AA-05, PR.AA-01, ID.AM-04]
- suggested subdomain: identity-access-management
- nearest existing sibling (for the negative trigger): detecting-azure-service-principal-abuse

## Draft description (<=1024 chars)
Detects persistence via malicious cloud application integration (T1671) — rogue OAuth app registrations, illicit consent grants, admin-consent bypass, new app secrets/certs on service principals, and over-scoped third-party app authorizations across Microsoft 365/Entra ID, Google Workspace, and SaaS (Slack, Salesforce). Correlates app creation/consent events (Consent to application, Add delegated permission grant, Add app role assignment to service principal, Add service principal credentials) with the service-principal sign-ins and data access that follow. Use when hunting OAuth persistence, consent-grant attacks, or rogue enterprise apps in cloud tenants. Keywords: OAuth consent, illicit consent grant, enterprise application, service principal, app registration, Graph permissions, domain-wide delegation, T1671, DET0539. Do not use for service-principal credential/sign-in abuse of already-trusted apps (use detecting-azure-service-principal-abuse) or broad O365 audit triage (use analyzing-office365-audit-logs-for-compromise).

## Key references
- https://attack.mitre.org/techniques/T1671/
- https://attack.mitre.org/detectionstrategies/DET0539
- https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth (OAuth app investigation)
- https://research.splunk.com/cloud/8a1b22eb-50ce-4e26-a691-97ff52349569/ (O365 Admin Consent Bypassed by Service Principal)
- https://www.elastic.co/guide/en/security/current/possible-consent-grant-attack-via-azure-registered-application.html
- https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants

## Open questions / scope boundaries
- Verify exact Entra/M365 unified-log operation strings ("Add delegated permission grant" vs "Add OAuth2PermissionGrant", "Add service principal") against a live tenant export before shipping queries.
- Verify whether T1671 has gained sub-techniques in v19.2 and whether DET0539's analytic IDs (AN1487/AN1488) are stable.
- Must NOT cover stolen/abused tokens of pre-existing trusted apps (T1550.001 / detecting-azure-service-principal-abuse) beyond the correlation hook, nor device-code / AiTM phishing to obtain consent (sibling OAuth-phishing skills).
- Author must decide multi-platform (M365 + Google + SaaS) vs. Microsoft-only scope, and how to source a reliable "approved integrations" baseline.
