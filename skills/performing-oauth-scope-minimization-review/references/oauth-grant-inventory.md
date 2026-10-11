# OAuth Grant Inventory - Microsoft Entra ID

```python
"""
OAuth Grant Inventory - Microsoft Entra ID
Enumerates all application registrations, service principals,
and delegated/application permission grants.
"""
import requests
import json
from collections import defaultdict

class EntraOAuthAuditor:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.token = self._get_token(client_id, client_secret)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _get_token(self, client_id, client_secret):
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        response = requests.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default"
        })
        return response.json()["access_token"]

    def get_all_service_principals(self):
        """Get all service principals (enterprise applications)."""
        apps = []
        url = f"{self.base_url}/servicePrincipals?$top=999&$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,createdDateTime"

        while url:
            response = requests.get(url, headers=self.headers)
            data = response.json()
            apps.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        return apps

    def get_oauth2_permission_grants(self):
        """Get all delegated permission grants (user consent)."""
        grants = []
        url = f"{self.base_url}/oauth2PermissionGrants?$top=999"

        while url:
            response = requests.get(url, headers=self.headers)
            data = response.json()
            grants.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        return grants

    def get_app_role_assignments(self, sp_id):
        """Get application permission assignments for a service principal."""
        url = f"{self.base_url}/servicePrincipals/{sp_id}/appRoleAssignments"
        response = requests.get(url, headers=self.headers)
        return response.json().get("value", [])

    def build_permission_inventory(self):
        """Build comprehensive OAuth permission inventory."""
        service_principals = self.get_all_service_principals()
        delegated_grants = self.get_oauth2_permission_grants()

        # Map service principal IDs to names
        sp_map = {sp["id"]: sp for sp in service_principals}

        inventory = []

        # Process delegated permissions
        for grant in delegated_grants:
            sp = sp_map.get(grant["clientId"], {})
            scopes = grant.get("scope", "").split()

            for scope in scopes:
                if not scope:
                    continue
                inventory.append({
                    "app_name": sp.get("displayName", "Unknown"),
                    "app_id": grant.get("clientId"),
                    "publisher_tenant": sp.get("appOwnerOrganizationId"),
                    "is_third_party": sp.get("appOwnerOrganizationId") != self.tenant_id,
                    "permission_type": "Delegated",
                    "scope": scope,
                    "consent_type": grant.get("consentType"),  # AllPrincipals or Principal
                    "principal_id": grant.get("principalId"),
                    "granted_date": sp.get("createdDateTime"),
                    "is_enabled": sp.get("accountEnabled", True)
                })

        # Process application permissions
        for sp in service_principals:
            app_roles = self.get_app_role_assignments(sp["id"])
            for role in app_roles:
                inventory.append({
                    "app_name": sp.get("displayName"),
                    "app_id": sp.get("id"),
                    "publisher_tenant": sp.get("appOwnerOrganizationId"),
                    "is_third_party": sp.get("appOwnerOrganizationId") != self.tenant_id,
                    "permission_type": "Application",
                    "scope": role.get("appRoleId"),
                    "consent_type": "AdminConsent",
                    "granted_date": role.get("createdDateTime"),
                    "is_enabled": sp.get("accountEnabled", True)
                })

        return inventory
```
