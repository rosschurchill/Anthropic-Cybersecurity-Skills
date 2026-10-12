---
name: detecting-azure-storage-account-misconfigurations
description: >-
  Audit Azure Blob and ADLS storage accounts for public access exposure, weak or long-lived SAS
  tokens, missing encryption at rest, disabled HTTPS-only traffic, and outdated TLS versions,
  using the azure-mgmt-storage Python SDK to generate a risk-scored report. Use when assessing an
  Azure subscription's storage accounts for misconfiguration, building cloud security posture
  checks, or investigating a suspected data exposure via public blob access. Do not use for CLI,
  PowerShell, or Defender for Storage audits - use detecting-misconfigured-azure-storage.
domain: cybersecurity
subdomain: cloud-security
tags:
- Azure
- storage-accounts
- blob-storage
- ADLS
- SAS-tokens
- encryption
- public-access
- cloud-misconfiguration
- azure-mgmt-storage
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1530
- T1078.004
- T1619
- T1580
---

# Detecting Azure Storage Account Misconfigurations

## Overview

Azure Storage accounts are a frequent target for attackers due to misconfigured public access, long-lived SAS tokens, missing encryption, and outdated TLS versions. This skill uses the azure-mgmt-storage Python SDK with StorageManagementClient to enumerate all storage accounts in a subscription, inspect their security properties, list blob containers for public access settings, and generate a risk-scored audit report identifying critical misconfigurations.


## When to Use

- Use when auditing an Azure subscription's storage accounts for public blob exposure with azure-mgmt-storage
- Use when checking for disabled HTTPS-only traffic or outdated minimum TLS (1.0/1.1) settings
- Use when flagging storage accounts with network default action Allow or missing encryption at rest
- Use when investigating a suspected data exposure via public blob/container access level
- Use when producing a risk-scored posture report aligned to CIS Azure Benchmark controls

## Prerequisites

- Python 3.9+ with `azure-mgmt-storage`, `azure-identity`
- Azure service principal with Reader role on target subscription
- Environment variables: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID

## Key Detection Areas

1. **Public blob access** — `allow_blob_public_access` enabled on storage account or individual containers set to Blob/Container access level
2. **HTTPS enforcement** — `enable_https_traffic_only` disabled, allowing unencrypted HTTP traffic
3. **Minimum TLS version** — accounts accepting TLS 1.0 or TLS 1.1 instead of minimum TLS 1.2
4. **Encryption at rest** — storage service encryption not enabled or missing customer-managed keys
5. **Network rules** — default action set to Allow instead of Deny, exposing storage to all networks
6. **SAS token risks** — account-level SAS with overly broad permissions or excessive lifetime

## Output

JSON report with per-account findings, severity ratings (Critical/High/Medium/Low), and remediation recommendations aligned with CIS Azure Benchmark controls.

## Example

Enumerate storage accounts with the azure-mgmt-storage `StorageManagementClient` and inspect the key detection areas:

```python
import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

sub_id = os.environ["AZURE_SUBSCRIPTION_ID"]
client = StorageManagementClient(DefaultAzureCredential(), sub_id)

for acct in client.storage_accounts.list():
    findings = []
    if acct.allow_blob_public_access:
        findings.append(("HIGH", "public blob access enabled"))
    if not acct.enable_https_traffic_only:
        findings.append(("HIGH", "HTTPS-only traffic disabled"))
    if acct.minimum_tls_version in ("TLS1_0", "TLS1_1"):
        findings.append(("MEDIUM", f"weak minimum TLS: {acct.minimum_tls_version}"))
    if acct.network_rule_set and acct.network_rule_set.default_action == "Allow":
        findings.append(("MEDIUM", "network default action = Allow"))
    for severity, msg in findings:
        print(f"[{severity}] {acct.name}: {msg}")
```
