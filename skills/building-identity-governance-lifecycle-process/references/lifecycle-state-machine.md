# Identity Lifecycle State Machine

```python
"""
Identity Lifecycle State Machine
Defines all identity states and valid transitions with automated actions.
"""

IDENTITY_LIFECYCLE = {
    "states": {
        "PRE_HIRE": {
            "description": "Identity created from HR feed before start date",
            "automated_actions": [
                "Create identity record in IGA platform",
                "Generate unique employee ID",
                "Create mailbox reservation",
                "Assign birthright roles based on job code",
                "Initiate background check workflow"
            ],
            "valid_transitions": ["ACTIVE", "CANCELLED"]
        },
        "ACTIVE": {
            "description": "Employee has started, full access provisioned",
            "automated_actions": [
                "Create Active Directory account",
                "Create email mailbox",
                "Provision birthright application access",
                "Assign department-specific roles",
                "Add to distribution groups",
                "Issue MFA token/security key",
                "Create VPN account if remote worker"
            ],
            "valid_transitions": ["ROLE_CHANGE", "LEAVE_OF_ABSENCE", "TERMINATED"]
        },
        "ROLE_CHANGE": {
            "description": "Employee transferred, promoted, or changed departments",
            "automated_actions": [
                "Recalculate role assignments based on new job code",
                "Remove access from previous department applications",
                "Provision access for new department applications",
                "Update group memberships",
                "Transfer manager in directory",
                "Trigger access review for retained entitlements",
                "Notify new manager of inherited access"
            ],
            "valid_transitions": ["ACTIVE", "LEAVE_OF_ABSENCE", "TERMINATED"]
        },
        "LEAVE_OF_ABSENCE": {
            "description": "Employee on extended leave (medical, parental, sabbatical)",
            "automated_actions": [
                "Disable interactive login (preserve account)",
                "Suspend VPN access",
                "Set out-of-office auto-reply",
                "Delegate mailbox to manager",
                "Preserve all role assignments for return",
                "Set reactivation date from HR feed"
            ],
            "valid_transitions": ["ACTIVE", "TERMINATED"]
        },
        "TERMINATED": {
            "description": "Employee has left the organization",
            "automated_actions": [
                "Disable AD account immediately",
                "Revoke all application access",
                "Revoke VPN and remote access",
                "Convert mailbox to shared (manager access for 90 days)",
                "Transfer OneDrive files to manager",
                "Remove from all security and distribution groups",
                "Revoke OAuth tokens and API keys",
                "Wipe corporate data from mobile devices",
                "Archive identity record",
                "Schedule account deletion after retention period"
            ],
            "valid_transitions": ["REHIRE", "DELETED"]
        },
        "REHIRE": {
            "description": "Previously terminated employee returning",
            "automated_actions": [
                "Reactivate existing identity record",
                "Reset credentials and require MFA re-enrollment",
                "Provision based on new job code (not previous access)",
                "Flag for enhanced access review in first 30 days"
            ],
            "valid_transitions": ["ACTIVE"]
        },
        "DELETED": {
            "description": "Account permanently removed after retention period",
            "automated_actions": [
                "Delete AD account",
                "Delete email mailbox archive",
                "Remove identity record from IGA",
                "Generate deletion audit log"
            ],
            "valid_transitions": []
        }
    },
    "retention_periods": {
        "terminated_to_deleted": "90 days (default)",
        "mailbox_retention": "90 days as shared mailbox",
        "onedrive_retention": "30 days manager access, then archived",
        "audit_log_retention": "7 years for compliance"
    }
}
```
