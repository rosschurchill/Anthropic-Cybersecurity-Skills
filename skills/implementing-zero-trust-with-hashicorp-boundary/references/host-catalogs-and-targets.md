# Boundary Host Catalogs and Targets (Terraform)

```hcl
# Static host catalog for known infrastructure
resource "boundary_host_catalog_static" "production_servers" {
  name     = "production-servers"
  scope_id = boundary_scope.production.id
}

resource "boundary_host_static" "web_server" {
  name            = "web-server-1"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  address         = "10.0.1.10"
}

resource "boundary_host_static" "db_server" {
  name            = "db-server-1"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  address         = "10.0.2.20"
}

# Host set grouping
resource "boundary_host_set_static" "web_servers" {
  name            = "web-servers"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  host_ids        = [boundary_host_static.web_server.id]
}

resource "boundary_host_set_static" "db_servers" {
  name            = "database-servers"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  host_ids        = [boundary_host_static.db_server.id]
}

# SSH target
resource "boundary_target" "ssh_production" {
  name         = "ssh-production-servers"
  description  = "SSH access to production servers"
  type         = "ssh"
  scope_id     = boundary_scope.production.id
  default_port = 22

  host_source_ids = [
    boundary_host_set_static.web_servers.id
  ]

  session_max_seconds          = 3600  # 1 hour max session
  session_connection_limit     = 1
  enable_session_recording     = true
  storage_bucket_id            = boundary_storage_bucket.sessions.id

  injected_application_credential_source_ids = [
    boundary_credential_library_vault_ssh_certificate.ssh_cert.id
  ]
}

# Database target with Vault credential brokering
resource "boundary_target" "postgres_production" {
  name         = "postgres-production"
  description  = "PostgreSQL production database"
  type         = "tcp"
  scope_id     = boundary_scope.production.id
  default_port = 5432

  host_source_ids = [
    boundary_host_set_static.db_servers.id
  ]

  session_max_seconds      = 1800  # 30 min max
  session_connection_limit = 5

  brokered_credential_source_ids = [
    boundary_credential_library_vault.postgres_creds.id
  ]
}
```
