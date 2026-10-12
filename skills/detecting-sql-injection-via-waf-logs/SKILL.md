---
name: detecting-sql-injection-via-waf-logs
description: >-
  Analyze WAF (ModSecurity/AWS WAF/Cloudflare) logs to detect SQL injection attack campaigns.
  Parses ModSecurity audit logs and JSON WAF event logs to identify SQLi patterns (UNION
  SELECT, OR 1=1, SLEEP(), BENCHMARK()), tracks attack sources, correlates multi-stage
  injection attempts, and generates incident reports with OWASP classification. Use when
  triaging SQLi alerts in WAF logs, scoping an injection campaign across sources, or
  validating WAF detection coverage during SOC monitoring. Keywords: ModSecurity, AWS WAF,
  Cloudflare, UNION SELECT, OR 1=1, SLEEP, BENCHMARK, CRS, OWASP. Do not use for actively
  exploiting SQL injection during a penetration test — use
  exploiting-sql-injection-vulnerabilities.
domain: cybersecurity
subdomain: security-operations
tags:
- waf-log-analysis
- sql-injection-detection
- modsecurity
- aws-waf
- cloudflare-waf
- web-application-security
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1190
- T1505.003
- T1059.007
---


# Detecting SQL Injection via WAF Logs


## When to Use

- Use when triaging SQLi alerts in ModSecurity audit logs, AWS WAF JSON logs, or Cloudflare firewall events (e.g. CRS rule 942100 / libinjection hits).
- Use when scoping an injection campaign across sources by clustering persistent attacker IPs and correlating multi-request attempts.
- Use when classifying payloads by OWASP injection type (classic `OR 1=1`, UNION SELECT, blind, time-based `SLEEP()`/`BENCHMARK()`).
- Use when estimating attack success from WAF response codes and producing an incident report with OWASP classification.
- Use when validating WAF detection coverage against known SQLi patterns during SOC monitoring.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Collect WAF logs (ModSecurity audit log, AWS WAF JSON logs, or Cloudflare firewall events).
3. Run the agent to parse and analyze:
   - Detect SQLi payloads via 15+ regex patterns
   - Classify attacks by OWASP injection type (classic, blind, time-based, UNION-based)
   - Identify persistent attackers by IP clustering
   - Correlate multi-request injection campaigns
   - Calculate attack success probability based on response codes

```bash
python scripts/agent.py --log-file /var/log/modsec_audit.log --format modsecurity --output sqli_report.json
```

## Examples

### ModSecurity SQLi Detection
```
Rule 942100 triggered: SQL Injection Attack Detected via libinjection
URI: /api/users?id=1' UNION SELECT username,password FROM users--
Source IP: 203.0.113.42 (47 requests in 5 minutes)
Classification: UNION-based SQLi campaign
```
