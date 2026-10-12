---
name: analyzing-web-server-logs-for-intrusion
description: >-
  Parses Apache and Nginx access logs to detect SQL injection, local file inclusion, directory
  traversal, web-scanner fingerprints, and brute-force patterns using regex matching against
  OWASP attack signatures, GeoIP enrichment, and statistical anomaly detection on request
  frequency and response size. Use when hunting web attacks in access logs, attributing scanner
  or brute-force activity, or building log-based web-intrusion detections. Keywords: Apache,
  Nginx, access log, SQLi, LFI, directory traversal, GeoIP, OWASP signatures. Do not use for
  WAF-log-driven SQL injection detection specifically - use detecting-sql-injection-via-waf-logs.
domain: cybersecurity
subdomain: security-operations
tags:
- web-log-analysis
- apache-logs
- nginx-logs
- sql-injection-detection
- lfi-detection
- directory-traversal
- intrusion-detection
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
- T1059.007
- T1110
- T1595.002
- T1505.003
---


# Analyzing Web Server Logs for Intrusion


## When to Use

- Use when hunting SQL injection, LFI, or directory traversal attempts in Apache/Nginx access logs
- Use when identifying scanner activity (nikto, sqlmap, dirbuster, gobuster) by user-agent fingerprint
- Use when detecting login brute-force patterns (>50 POST requests to login endpoints from one IP)
- Use when enriching suspicious source IPs with GeoIP and producing a prioritized web-intrusion report
- Use when building regex detections from OWASP attack signatures against Combined Log Format logs

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install geoip2 user-agents`
2. Collect web server access logs in Combined Log Format (Apache) or Nginx default format.
3. Parse each log entry extracting: IP, timestamp, method, URI, status code, response size, user-agent, referer.
4. Apply detection rules:
   - SQL injection: `UNION SELECT`, `OR 1=1`, `' OR '`, hex encoding patterns
   - LFI/Path traversal: `../`, `/etc/passwd`, `/proc/self`, `php://filter`
   - XSS: `<script>`, `javascript:`, `onerror=`, `onload=`
   - Scanner signatures: nikto, sqlmap, dirbuster, gobuster, wfuzz user-agents
   - Brute force: >50 POST requests to login endpoints from same IP in 5 minutes
5. Enrich with GeoIP data and generate a prioritized findings report.

```bash
python scripts/agent.py --log-file /var/log/nginx/access.log --geoip-db GeoLite2-City.mmdb --output web_intrusion_report.json
```

## Examples

### Detect SQLi in URI
```
192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /products?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 4532
```

### Scanner User-Agent Detection
```
Nikto/2.1.6, sqlmap/1.7, DirBuster-1.0-RC1, gobuster/3.1.0
```
