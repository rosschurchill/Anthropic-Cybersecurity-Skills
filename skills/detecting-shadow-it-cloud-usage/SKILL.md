---
name: detecting-shadow-it-cloud-usage
description: >-
  Detect unauthorized SaaS and cloud service usage (shadow IT) by parsing proxy access logs, DNS
  query logs, and firewall/netflow data with Python pandas to aggregate traffic by domain,
  classify domains against known SaaS categories, and score risk by data volume and user count.
  Use when auditing an organization for unsanctioned cloud/SaaS usage or generating a shadow IT
  discovery report with remediation recommendations. Do not use for authorized cloud
  infrastructure asset inventory and mapping - use
  performing-cloud-asset-inventory-with-cartography.
domain: cybersecurity
subdomain: cloud-security
tags:
- shadow-IT
- SaaS-discovery
- proxy-logs
- DNS-analysis
- netflow
- cloud-security
- pandas
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1567.002
- T1526
- T1078.004
- T1213
---

# Detecting Shadow IT Cloud Usage

## Overview

Shadow IT refers to unauthorized SaaS applications and cloud services used without IT approval. This skill analyzes proxy logs, DNS query logs, and firewall/netflow data to identify unauthorized cloud service usage, classify discovered domains against known SaaS categories, measure data transfer volumes, and flag high-risk services based on security posture and compliance requirements.


## When to Use

- Use when auditing an organization for unsanctioned SaaS/cloud usage by aggregating proxy logs (Squid, Zscaler, Palo Alto) or DNS query logs with pandas.
- Use when ranking discovered cloud services by data-transfer volume and unique-user count to find the top data-exfiltration risks.
- Use when classifying destination domains against known SaaS categories (storage, email, dev tools, AI) and flagging those not on the approved application list.
- Use when generating a shadow IT discovery report with per-service risk scores and remediation recommendations.
- Use when enriching netflow/firewall FQDN data to measure egress to unauthorized cloud destinations.

## Prerequisites

- Python 3.9+ with `pandas`, `tldextract`
- Proxy logs (Squid, Zscaler, or Palo Alto format) or DNS query logs
- SaaS application catalog/blocklist for classification
- Network firewall logs with FQDN resolution (optional)

## Steps

1. Parse proxy access logs and extract destination domains with traffic volumes
2. Parse DNS query logs to identify resolved cloud service domains
3. Aggregate traffic by domain using pandas — total bytes, request counts, unique users
4. Classify domains against known SaaS categories (storage, email, dev tools, AI)
5. Flag unauthorized services not on the approved application list
6. Calculate risk scores based on data volume, user count, and service category
7. Generate shadow IT discovery report with remediation recommendations

## Example

Aggregate proxy access logs by registered domain, classify against approved SaaS, and
rank unauthorized services by egress volume:

```python
import pandas as pd
import tldextract

# Proxy log columns: timestamp, user, dest_domain, bytes_sent, bytes_recv
df = pd.read_csv("proxy_access.csv", parse_dates=["timestamp"])

# Reduce each destination to its registered domain (e.g. files.dropbox.com -> dropbox.com)
df["registered"] = df["dest_domain"].apply(
    lambda d: ".".join(p for p in [tldextract.extract(d).domain,
                                    tldextract.extract(d).suffix] if p)
)

APPROVED = {"microsoft.com", "office.com", "github.com", "okta.com"}
SAAS_CATEGORY = {
    "dropbox.com": "storage", "box.com": "storage", "wetransfer.com": "storage",
    "mega.nz": "storage", "openai.com": "ai", "anthropic.com": "ai",
    "mailchimp.com": "email", "pastebin.com": "dev-tools",
}

agg = (df.groupby("registered")
         .agg(total_bytes=("bytes_sent", "sum"),
              requests=("dest_domain", "size"),
              users=("user", "nunique"))
         .reset_index())

agg["approved"] = agg["registered"].isin(APPROVED)
agg["category"] = agg["registered"].map(SAAS_CATEGORY).fillna("uncategorized")

# Risk score: upload volume (MB) + user spread, doubled for storage/AI egress channels
mb = agg["total_bytes"] / 1_000_000
agg["risk"] = (mb.clip(upper=500) / 50 + agg["users"].clip(upper=100) / 10)
agg.loc[agg["category"].isin(["storage", "ai"]), "risk"] *= 2

shadow = agg[~agg["approved"]].sort_values("risk", ascending=False)
print(shadow[["registered", "category", "total_bytes", "users", "risk"]].head(20))
```

## Expected Output

- JSON report listing discovered cloud services with traffic volumes, user counts, risk scores, and approval status
- Top unauthorized services ranked by data exfiltration risk
