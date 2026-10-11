---
name: implementing-hashicorp-vault-dynamic-secrets
description: 'Configures HashiCorp Vault dynamic secrets engines for database credentials, AWS IAM
  keys, and PKI certificates, with automatic generation, lease management, and rotation to eliminate
  static secrets in application configuration. Use when eliminating long-lived static credentials, configuring
  a Vault secrets engine, generating ephemeral database or cloud credentials, or automating credential
  rotation for compliance (PCI-DSS, NIST 800-53 IA-5). Do not use for a commercial PAM vault with session
  recording - use implementing-delinea-secret-server-for-pam.'
domain: cybersecurity
subdomain: identity-access-management
tags:
- HashiCorp-Vault
- dynamic-secrets
- secrets-management
- database-credentials
- AWS-secrets
- PKI
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1078
- T1110
- T1556
- T1098
- T1003
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - positioning
  - stealth
  - resource-development
  techniques:
  - id: F1006.001
    name: 'Account Takeover: Exposed API Key'
    tactic: initial-access
    source: f3
  - id: F1006.002
    name: 'Account Takeover: Exposed Login Credential'
    tactic: initial-access
    source: f3
  - id: T1586
    name: Compromise Accounts
    tactic: resource-development
    source: attack
  - id: T1555
    name: Credentials from Password Stores
    tactic: reconnaissance
    source: attack
  - id: F1005.004
    name: 'Account Manipulation: Change Account Details'
    tactic: positioning
    source: f3
  - id: F1033
    name: Insider Access Abuse
    tactic: initial-access
    source: f3
---

# Implementing HashiCorp Vault Dynamic Secrets

## When to Use

- Applications use static database credentials stored in configuration files or environment variables
- AWS IAM access keys are long-lived and shared across services
- Need to eliminate credential sprawl by generating short-lived, per-request secrets
- Compliance requirements mandate credential rotation (PCI-DSS Requirement 8, NIST 800-53 IA-5)
- Implementing zero-trust secret management where credentials are never stored at rest
- Migrating from manual credential management to automated secrets lifecycle

**Do not use** for storing static secrets that cannot be dynamically generated (use Vault's KV secrets engine instead); dynamic secrets are for credentials that can be programmatically created and revoked on target systems.

## Prerequisites

- HashiCorp Vault 1.15+ (Community or Enterprise edition)
- Vault server initialized and unsealed with auto-unseal configured (AWS KMS, Azure Key Vault, or Transit)
- Target database systems with admin credentials for Vault to create/revoke dynamic accounts
- AWS IAM account with permissions to create/delete IAM users and access keys
- Network connectivity from Vault to all target systems
- Vault policies and authentication methods configured for consuming applications

## Workflow

### Step 1: Deploy and Configure Vault Server

Initialize Vault with production-grade configuration:

```hcl
# vault-config.hcl - Production Vault server configuration
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-1"

  retry_join {
    leader_api_addr = "https://vault-2.corp.local:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-3.corp.local:8200"
  }
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault-cert.pem"
  tls_key_file  = "/opt/vault/tls/vault-key.pem"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal-key"
}

api_addr      = "https://vault-1.corp.local:8200"
cluster_addr  = "https://vault-1.corp.local:8201"

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}

ui = true
```

```bash
# Initialize Vault cluster
vault operator init -key-shares=5 -key-threshold=3

# Enable audit logging
vault audit enable file file_path=/var/log/vault/audit.log

# Enable AppRole authentication for applications
vault auth enable approle

# Create policy for database secret consumers
vault policy write db-consumer - <<EOF
# Allow reading dynamic database credentials
path "database/creds/app-readonly" {
  capabilities = ["read"]
}
path "database/creds/app-readwrite" {
  capabilities = ["read"]
}

# Allow renewing and revoking own leases
path "sys/leases/renew" {
  capabilities = ["update"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}

# Allow reading own token info
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

# Create AppRole for application
vault write auth/approle/role/webapp \
    token_policies="db-consumer" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=720h \
    secret_id_num_uses=0
```

### Step 2: Configure Database Secrets Engine

Set up dynamic credential generation for PostgreSQL and MySQL:

```bash
# Enable the database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/production-postgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="app-readonly,app-readwrite,app-admin" \
    connection_url="postgresql://{{username}}:{{password}}@db-primary.corp.local:5432/appdb?sslmode=verify-full" \
    username="vault_admin" \
    password="$VAULT_DB_PASSWORD" \
    password_authentication="scram-sha-256"

# Rotate the root credentials so Vault manages them exclusively
vault write -force database/rotate-root/production-postgres

# Create read-only role (TTL: 1 hour, max 24 hours)
vault write database/roles/app-readonly \
    db_name=production-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";" \
    revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; \
        DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Create read-write role (TTL: 30 minutes, max 8 hours)
vault write database/roles/app-readwrite \
    db_name=production-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\";" \
    revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; \
        DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl="30m" \
    max_ttl="8h"

# Configure MySQL connection
vault write database/config/production-mysql \
    plugin_name=mysql-database-plugin \
    allowed_roles="mysql-readonly,mysql-readwrite" \
    connection_url="{{username}}:{{password}}@tcp(mysql-primary.corp.local:3306)/" \
    username="vault_admin" \
    password="$VAULT_MYSQL_PASSWORD"

vault write database/roles/mysql-readonly \
    db_name=production-mysql \
    creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; \
        GRANT SELECT ON appdb.* TO '{{name}}'@'%';" \
    revocation_statements="DROP USER IF EXISTS '{{name}}'@'%';" \
    default_ttl="1h" \
    max_ttl="24h"

# Test dynamic credential generation
echo "Testing PostgreSQL dynamic credentials:"
vault read database/creds/app-readonly
# Returns: username=v-approle-app-read-xxxxx, password=<random>, lease_id=database/creds/app-readonly/xxxxx
```

### Step 3: Configure AWS Secrets Engine

Generate ephemeral AWS IAM credentials:

```bash
# Enable the AWS secrets engine
vault secrets enable aws

# Configure the AWS secrets engine with root credentials
vault write aws/config/root \
    access_key="$AWS_ACCESS_KEY_ID" \
    secret_key="$AWS_SECRET_ACCESS_KEY" \
    region="us-east-1"

# Configure lease settings
vault write aws/config/lease \
    lease="30m" \
    lease_max="1h"

# Create IAM User role for S3 read-only access
vault write aws/roles/s3-readonly \
    credential_type=iam_user \
    policy_document=-<<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::app-data-bucket",
        "arn:aws:s3:::app-data-bucket/*"
      ]
    }
  ]
}
EOF

# Create Assumed Role for EC2 management (preferred over IAM users)
vault write aws/roles/ec2-admin \
    credential_type=assumed_role \
    role_arns="arn:aws:iam::123456789012:role/VaultEC2AdminRole" \
    default_sts_ttl="30m" \
    max_sts_ttl="1h"

# Create Federation Token role for cross-account access
vault write aws/roles/cross-account-readonly \
    credential_type=federation_token \
    policy_document=-<<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::987654321098:role/CrossAccountReadOnly"
    }
  ]
}
EOF

# Test AWS dynamic credentials
echo "Testing AWS STS credentials:"
vault read aws/creds/ec2-admin
# Returns: access_key, secret_key, security_token with 30-minute TTL
```

### Step 4: Configure PKI Secrets Engine for Dynamic Certificates

Generate short-lived TLS certificates on demand:

```bash
# Enable PKI secrets engine for root CA
vault secrets enable -path=pki pki
vault secrets tune -max-lease-ttl=87600h pki

# Generate root CA certificate
vault write pki/root/generate/internal \
    common_name="Corp Internal Root CA" \
    ttl=87600h \
    key_type=ec \
    key_bits=384

# Enable PKI for intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

# Generate intermediate CA CSR
vault write pki_int/intermediate/generate/internal \
    common_name="Corp Intermediate CA" \
    key_type=ec \
    key_bits=256

# Sign intermediate CA with root CA
vault write pki/root/sign-intermediate \
    csr=@intermediate.csr \
    format=pem_bundle \
    ttl=43800h

# Configure issuing URLs
vault write pki_int/config/urls \
    issuing_certificates="https://vault.corp.local:8200/v1/pki_int/ca" \
    crl_distribution_points="https://vault.corp.local:8200/v1/pki_int/crl"

# Create role for web server certificates (TTL: 30 days)
vault write pki_int/roles/web-server \
    allowed_domains="corp.local,internal.corp.com" \
    allow_subdomains=true \
    max_ttl=720h \
    key_type=ec \
    key_bits=256 \
    require_cn=true \
    enforce_hostnames=true

# Create role for service mesh certificates (TTL: 24 hours)
vault write pki_int/roles/service-mesh \
    allowed_domains="service.consul" \
    allow_subdomains=true \
    max_ttl=24h \
    key_type=ec \
    key_bits=256 \
    allow_ip_sans=true \
    server_flag=true \
    client_flag=true

# Issue a certificate
vault write pki_int/issue/web-server \
    common_name="api.corp.local" \
    alt_names="api.internal.corp.com" \
    ttl=720h
```

### Step 5: Integrate Applications with Vault

Configure applications to consume dynamic secrets:

See [references/python-integration.md](references/python-integration.md) for the full hvac Python client with automatic lease renewal.

### Step 6: Monitor Vault Operations and Lease Management

Track dynamic secret usage and lease lifecycle:

See [references/monitoring-leases.md](references/monitoring-leases.md) for lease monitoring commands, Prometheus metrics, and the audit-log analysis script.

## Key Concepts

| Term | Definition |
|------|------------|
| **Dynamic Secrets** | Credentials generated on-demand by Vault with automatic expiration, ensuring each consumer receives unique short-lived credentials |
| **Lease** | Time-bound agreement where Vault guarantees the credential is valid; consumers must renew before expiration or request new credentials |
| **Secrets Engine** | Vault plugin that generates, stores, or encrypts data; database, AWS, PKI, and KV are common engines |
| **AppRole** | Vault authentication method designed for machine-to-machine authentication using role ID and secret ID pairs |
| **Root Credential Rotation** | Process of having Vault take exclusive ownership of the admin credential used to create dynamic secrets, eliminating human knowledge of the root password |
| **Lease Revocation** | Immediate invalidation of dynamic credentials, used during incident response to revoke all credentials for compromised paths |

## Tools & Systems

- **HashiCorp Vault**: Secrets management platform providing dynamic secrets, encryption as a service, and identity-based access control
- **Vault Agent**: Sidecar process that handles Vault authentication, token renewal, and secret caching for applications
- **Vault Secrets Operator**: Kubernetes operator that syncs Vault secrets into Kubernetes Secrets for pod consumption
- **hvac**: Python client library for HashiCorp Vault API operations

## Common Scenarios

### Scenario: Eliminating Static Database Credentials in Microservices

**Context**: 50 microservices share 3 static PostgreSQL credentials stored in environment variables across Kubernetes deployments. A credential leak requires rotating all 50 services simultaneously.

**Approach**:
1. Deploy Vault with Raft storage in a 3-node HA cluster within Kubernetes
2. Configure database secrets engine with PostgreSQL connection using admin credentials
3. Create per-service Vault roles with least-privilege SQL grants
4. Deploy Vault Secrets Operator to inject dynamic credentials into pod environment variables
5. Update application connection logic to handle credential rotation via lease renewal
6. Rotate the Vault root credential to remove human knowledge of the admin password
7. Monitor lease lifecycle and set alerts for renewal failures

**Pitfalls**:
- Not handling credential rotation in application connection pools (connections using expired credentials fail)
- Setting TTLs too short causes excessive credential generation load on the database
- Not configuring proper revocation statements leaves orphaned database users after lease expiration
- Running Vault without HA causes single point of failure for all application authentication

## Output Format

```
HASHICORP VAULT DYNAMIC SECRETS REPORT
=========================================
Vault Version:     1.16.2 Enterprise
Cluster Status:    HA Active (3 nodes)
Seal Type:         AWS KMS (auto-unseal)

SECRETS ENGINES
database/:         PostgreSQL, MySQL (2 connections)
aws/:              IAM User, Assumed Role, Federation Token
pki_int/:          Internal CA (EC P-256)

DYNAMIC CREDENTIAL METRICS (Last 24 Hours)
Total Credentials Generated:    4,287
  Database (PostgreSQL):        2,891
  Database (MySQL):             543
  AWS STS:                      612
  PKI Certificates:             241

ACTIVE LEASES
Total Active:                   387
  database/creds/app-readonly:  198
  database/creds/app-readwrite: 89
  aws/creds/s3-readonly:        67
  pki_int/issue/web-server:     33

LEASE LIFECYCLE
Average TTL:                    45 minutes
Renewals (24h):                 12,847
Revocations (24h):              3,901
Expired (not renewed):          12

SECURITY
Failed Auth Attempts (24h):     3
Root Credential Rotated:        YES (all databases)
Audit Logging:                  ENABLED (file + syslog)
Policy Violations (24h):        7 (permission denied)
```
