# Application Integration with Vault (Python)

```python
"""
Application integration with HashiCorp Vault for dynamic database credentials.
Uses the hvac Python client with automatic lease renewal.
"""
import hvac
import threading
import time
import logging

class VaultDynamicCredentialManager:
    def __init__(self, vault_addr, role_id, secret_id):
        self.client = hvac.Client(url=vault_addr)
        self.role_id = role_id
        self.secret_id = secret_id
        self.logger = logging.getLogger("vault_credentials")
        self._current_creds = None
        self._lease_id = None
        self._renewal_thread = None
        self._stop_event = threading.Event()

    def authenticate(self):
        """Authenticate to Vault using AppRole."""
        response = self.client.auth.approle.login(
            role_id=self.role_id,
            secret_id=self.secret_id
        )
        self.client.token = response["auth"]["client_token"]
        self.logger.info("Authenticated to Vault via AppRole")

    def get_database_credentials(self, role="app-readonly"):
        """Request dynamic database credentials from Vault."""
        self.authenticate()

        response = self.client.secrets.database.generate_credentials(
            name=role
        )

        self._current_creds = {
            "username": response["data"]["username"],
            "password": response["data"]["password"],
        }
        self._lease_id = response["lease_id"]
        lease_duration = response["lease_duration"]

        self.logger.info(
            f"Obtained dynamic credentials: user={self._current_creds['username']}, "
            f"lease={self._lease_id}, ttl={lease_duration}s"
        )

        # Start background lease renewal
        self._start_renewal(lease_duration)

        return self._current_creds

    def _start_renewal(self, lease_duration):
        """Start background thread to renew lease before expiration."""
        if self._renewal_thread and self._renewal_thread.is_alive():
            self._stop_event.set()
            self._renewal_thread.join()

        self._stop_event.clear()
        renewal_interval = lease_duration * 0.7  # Renew at 70% of TTL

        def renew_loop():
            while not self._stop_event.wait(renewal_interval):
                try:
                    self.client.sys.renew_lease(
                        lease_id=self._lease_id,
                        increment=lease_duration
                    )
                    self.logger.info(f"Renewed lease: {self._lease_id}")
                except hvac.exceptions.InvalidRequest:
                    self.logger.warning("Lease expired, obtaining new credentials")
                    self.get_database_credentials()
                    break
                except Exception as e:
                    self.logger.error(f"Lease renewal failed: {e}")

        self._renewal_thread = threading.Thread(target=renew_loop, daemon=True)
        self._renewal_thread.start()

    def revoke_credentials(self):
        """Explicitly revoke current dynamic credentials."""
        if self._lease_id:
            self._stop_event.set()
            self.client.sys.revoke_lease(self._lease_id)
            self.logger.info(f"Revoked lease: {self._lease_id}")
            self._current_creds = None
            self._lease_id = None

    def get_aws_credentials(self, role="s3-readonly"):
        """Request dynamic AWS credentials from Vault."""
        self.authenticate()

        response = self.client.secrets.aws.generate_credentials(
            name=role
        )

        return {
            "access_key": response["data"]["access_key"],
            "secret_key": response["data"]["secret_key"],
            "security_token": response["data"].get("security_token"),
            "lease_id": response["lease_id"],
            "ttl": response["lease_duration"]
        }

# Usage example
vault_mgr = VaultDynamicCredentialManager(
    vault_addr="https://vault.corp.local:8200",
    role_id="<approle-role-id>",
    secret_id="<approle-secret-id>"
)

db_creds = vault_mgr.get_database_credentials("app-readonly")
# Use db_creds["username"] and db_creds["password"] for database connection
```
