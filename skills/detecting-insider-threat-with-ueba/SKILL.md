---
name: detecting-insider-threat-with-ueba
description: >-
  Implement User and Entity Behavior Analytics (UEBA) using Elasticsearch/OpenSearch to build
  behavioral baselines, calculate anomaly scores, perform peer group analysis, and alert on
  insider threat indicators such as data exfiltration, privilege abuse, and unauthorized access.
  Use when building or tuning a UEBA pipeline rather than a one-off manual hunt. Do not use for a
  one-off manual insider behavioral hunt - use detecting-insider-threat-behaviors.
domain: cybersecurity
subdomain: threat-detection
tags:
- ueba
- insider-threat
- anomaly-detection
- elasticsearch
- behavior-analytics
- machine-learning
- siem
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
mitre_attack:
- T1078
- T1190
- T1059
- T1048
- T1041
---

# Detecting Insider Threat with UEBA

## Overview

User and Entity Behavior Analytics (UEBA) moves beyond static rule-based detection to model normal behavior for users, hosts, and applications, then flag statistically significant deviations that may indicate insider threats. Using Elasticsearch as the analytics backend, this skill covers building behavioral baselines from authentication logs, file access events, and network activity, computing risk scores using statistical deviation and peer group comparison, and correlating multiple low-confidence indicators into high-confidence insider threat alerts.


## When to Use

- Use when building or tuning a UEBA pipeline on Elasticsearch/OpenSearch rather than running a one-off manual hunt
- Use when you need per-user behavioral baselines (login times, data volume, app usage) over a rolling 30-day window
- Use when computing z-score deviation and peer-group comparison to turn raw activity into risk scores
- Use when correlating multiple low-confidence signals (odd hours + large downloads + new system access) into one composite insider-threat alert
- Use when ingesting AD authentication, VPN, DLP, and file-server logs into a unified user-identity field for analytics

## Prerequisites

- Elasticsearch 8.x or OpenSearch 2.x cluster with security audit data
- Log sources: Active Directory authentication, VPN, DLP, file server access, email
- Python 3.9+ with elasticsearch client library
- Baseline period of 30+ days of normal user activity data
- Defined peer groups based on department, role, or job function

## Steps

### Step 1: Ingest and Normalize Activity Logs
Configure log pipelines to ingest authentication, file access, email, and network logs into Elasticsearch with a unified user identity field.

### Step 2: Build Behavioral Baselines
Calculate per-user baselines for login times, data volume, application usage, and access patterns over a rolling 30-day window using Elasticsearch aggregations.

### Step 3: Calculate Anomaly Scores
Compare current activity against baselines using z-score deviation and peer group comparison to generate per-user risk scores.

### Step 4: Correlate and Alert
Combine multiple anomalous indicators (unusual hours + large downloads + new system access) into composite risk scores that trigger SOC investigation workflows.

## Example

Steps 2-3 in code: compute the z-score of today's outbound data volume against a user's 30-day baseline built from Elasticsearch aggregations.

```python
from elasticsearch import Elasticsearch
import statistics

es = Elasticsearch("https://localhost:9200")

def daily_bytes(user, days="30d"):
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"user.name": user}},
            {"range": {"@timestamp": {"gte": f"now-{days}/d", "lt": "now/d"}}}]}},
        "aggs": {"per_day": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"},
                             "aggs": {"vol": {"sum": {"field": "network.bytes_out"}}}}},
    }
    buckets = es.search(index="file-access-*", body=body)["aggregations"]["per_day"]["buckets"]
    return [b["vol"]["value"] for b in buckets]

def zscore_today(user, today_bytes):
    hist = daily_bytes(user)
    mu, sd = statistics.mean(hist), statistics.pstdev(hist) or 1.0
    return (today_bytes - mu) / sd   # z > 3 => flag for peer-group review
```

## Expected Output

JSON report containing per-user risk scores, anomalous activity details, peer group deviations, and recommended investigation actions.
