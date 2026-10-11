# Monitoring Vault Operations and Lease Management

```bash
# Monitor active leases
vault list sys/leases/lookup/database/creds/app-readonly
vault list sys/leases/lookup/aws/creds/s3-readonly

# Check lease details
vault write sys/leases/lookup lease_id="database/creds/app-readonly/abcd1234"

# Revoke all leases for a specific path (emergency credential rotation)
vault lease revoke -prefix database/creds/app-readonly

# Vault metrics for monitoring (Prometheus format)
# Key metrics to monitor:
# vault.expire.num_leases - Total active leases
# vault.expire.revoke - Lease revocations per second
# vault.secret.kv.count - Total stored secrets
# vault.runtime.alloc_bytes - Memory allocation

# Configure Vault audit log analysis
cat > vault_audit_monitor.sh << 'SCRIPT'
#!/bin/bash
# Monitor Vault audit logs for suspicious activity

AUDIT_LOG="/var/log/vault/audit.log"

# Count credential requests per hour
echo "=== Dynamic Credential Requests (Last Hour) ==="
jq -r 'select(.type == "response" and .request.path | startswith("database/creds/")) |
    "\(.time) \(.request.path) \(.auth.display_name)"' \
    "$AUDIT_LOG" | tail -100

# Detect unusual credential request patterns
echo ""
echo "=== High-Volume Credential Consumers ==="
jq -r 'select(.type == "request" and .request.path | startswith("database/creds/")) |
    .auth.display_name' \
    "$AUDIT_LOG" | sort | uniq -c | sort -rn | head -10

# Check for failed authentication attempts
echo ""
echo "=== Failed Auth Attempts ==="
jq -r 'select(.type == "response" and .error != null and
    .request.path | startswith("auth/")) |
    "\(.time) \(.request.path) \(.error)"' \
    "$AUDIT_LOG" | tail -20
SCRIPT
chmod +x vault_audit_monitor.sh
```
