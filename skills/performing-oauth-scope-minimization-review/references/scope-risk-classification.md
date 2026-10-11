# OAuth Scope Risk Classification

```python
"""
OAuth Scope Risk Classification
Maps API scopes to risk levels based on data sensitivity and access breadth.
"""

MICROSOFT_GRAPH_SCOPE_RISK = {
    # CRITICAL - Full administrative or unrestricted access
    "critical": {
        "scopes": [
            "Directory.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "Mail.ReadWrite",
            "Mail.Send",
            "Files.ReadWrite.All",
            "Sites.FullControl.All",
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "MailboxSettings.ReadWrite",
            "full_access_as_app",
        ],
        "risk_description": "Can read/write all data, modify directory, or impersonate users",
        "review_frequency": "Monthly",
        "requires_admin_consent": True
    },
    # HIGH - Broad read access or sensitive data write
    "high": {
        "scopes": [
            "Mail.Read",
            "Mail.Read.Shared",
            "Calendars.ReadWrite",
            "Contacts.ReadWrite",
            "Files.Read.All",
            "Sites.Read.All",
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "SecurityEvents.ReadWrite.All",
            "TeamSettings.ReadWrite.All",
        ],
        "risk_description": "Broad read access to sensitive organizational data",
        "review_frequency": "Quarterly",
        "requires_admin_consent": True
    },
    # MEDIUM - Scoped data access
    "medium": {
        "scopes": [
            "Calendars.Read",
            "Contacts.Read",
            "Files.ReadWrite",
            "Sites.ReadWrite.All",
            "Tasks.ReadWrite",
            "Notes.ReadWrite.All",
            "Chat.ReadWrite",
            "ChannelMessage.Send",
            "Team.ReadBasic.All",
        ],
        "risk_description": "Scoped access to specific data types with write capability",
        "review_frequency": "Semi-annually"
    },
    # LOW - Minimal or user-profile only access
    "low": {
        "scopes": [
            "User.Read",
            "openid",
            "profile",
            "email",
            "offline_access",
            "Calendars.Read.Shared",
            "People.Read",
            "User.ReadBasic.All",
        ],
        "risk_description": "Basic user profile or minimal scoped access",
        "review_frequency": "Annually"
    }
}

def classify_scope_risk(scope):
    """Classify a single OAuth scope by risk level."""
    for risk_level, config in MICROSOFT_GRAPH_SCOPE_RISK.items():
        if scope in config["scopes"]:
            return {
                "scope": scope,
                "risk_level": risk_level,
                "description": config["risk_description"],
                "review_frequency": config["review_frequency"]
            }
    # Unknown scopes default to HIGH risk
    return {
        "scope": scope,
        "risk_level": "high",
        "description": "Unknown scope - requires manual classification",
        "review_frequency": "Quarterly"
    }

def analyze_app_risk(app_permissions):
    """Calculate aggregate risk score for an application's permissions."""
    risk_weights = {"critical": 40, "high": 20, "medium": 10, "low": 2}
    total_score = 0
    classified_scopes = []

    for perm in app_permissions:
        classification = classify_scope_risk(perm["scope"])
        classified_scopes.append(classification)
        total_score += risk_weights.get(classification["risk_level"], 10)

    # Bonus risk for application (vs delegated) permissions
    app_type_permissions = [p for p in app_permissions if p["permission_type"] == "Application"]
    total_score += len(app_type_permissions) * 15

    # Bonus risk for admin-consented broad access
    admin_consent = [p for p in app_permissions if p["consent_type"] == "AllPrincipals"]
    total_score += len(admin_consent) * 10

    if total_score >= 100:
        aggregate_risk = "CRITICAL"
    elif total_score >= 60:
        aggregate_risk = "HIGH"
    elif total_score >= 30:
        aggregate_risk = "MEDIUM"
    else:
        aggregate_risk = "LOW"

    return {
        "total_score": total_score,
        "aggregate_risk": aggregate_risk,
        "scope_count": len(app_permissions),
        "critical_scopes": len([s for s in classified_scopes if s["risk_level"] == "critical"]),
        "high_scopes": len([s for s in classified_scopes if s["risk_level"] == "high"]),
        "classified_scopes": classified_scopes
    }
```
