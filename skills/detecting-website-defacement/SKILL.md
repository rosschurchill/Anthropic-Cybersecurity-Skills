---
name: detecting-website-defacement
description: 'Detects website and internal-system defacement (MITRE T1491) - unauthorized changes to served HTML/templates/images, injected hacktivist messages, and swapped login portals - by combining file integrity monitoring of web roots (Wazuh/AIDE/Tripwire), web-server and CMS log analysis for the write path, external content-change diffing, and cloud object-store audit logs (S3 PutObject/CloudTrail) for static sites. Correlates the defacement artifact with the access that produced it. Use when triaging suspected defacement, content-integrity alerts, or unexplained web-root changes. Keywords: defacement, website hacked, file integrity monitoring, web root, CMS compromise, S3 static site, CloudTrail PutObject, T1491, content integrity. Do not use for hunting web-shell persistence and execution internals - use hunting-for-webshell-activity.'
domain: cybersecurity
subdomain: incident-response
tags:
- incident-response
- threat-detection
- defacement
- file-integrity-monitoring
- web-security
- cms-compromise
- content-integrity
- wazuh
- cloudtrail
- t1491
- dfir
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- RS.MI-02
- RC.RP-01
mitre_attack:
- T1491
- T1491.001
- T1491.002
- T1505.003
---

# Detecting Website Defacement

## When to Use

Use this skill to detect and respond to **unauthorized modification of visual
content** on web properties and internal systems — defaced home pages, injected
hacktivist messages, swapped images, replaced login portals (ATT&CK T1491).
Defacement affects content integrity and usually signals a completed intrusion,
so the detection goal is to catch both the **defacement artifact** and the
**access that produced it**. Reach for it when:

- A content-integrity or FIM alert fires on a web root.
- A public or intranet page is reported changed / shows attacker messaging.
- You are hardening a web estate and need the detection + response playbook.

For the mechanics of hunting web-shell persistence/execution, use
`hunting-for-webshell-activity`; this skill detects the defacement *outcome* and
its access path.

## Prerequisites

- **File Integrity Monitoring** on web document roots (`/var/www`, `wwwroot`,
  CMS upload dirs) — Wazuh/OSSEC syscheck, AIDE, or Tripwire — with a clean
  baseline.
- **Web-server + CMS logs**: Apache/Nginx/IIS access and error logs, plus CMS
  audit logs (WordPress/Drupal/Joomla).
- For static sites: object-store audit logs (AWS CloudTrail **S3 data events**,
  Azure Storage logs, GCS access logs) and CDN origin/purge events.
- Optional: an external synthetic monitor that fetches the public URL for diffing.

## Workflow

1. **Baseline the known-good content.** Snapshot/hash the web root and capture a
   reference copy of each public page. Record approved deploy windows and the
   deploy principal (CI service account, admin).
2. **Integrity detection.** Alert on any hash/content change or new file in the
   web root outside an approved deploy window (FIM). New files that are scripts
   masquerading as images are high-signal.
3. **Content/availability detection.** Periodically fetch the public URL, diff
   against the known-good snapshot, and keyword-match common defacement markers
   ("hacked by", "pwned", "owned by", political slogans).
4. **Find the write path.** In web/CMS logs, look for POST/PUT to admin or upload
   endpoints, suspicious 200s to newly created paths, abnormal user-agents, or
   admin logins from new IPs just before the content change.
5. **Static-site path.** For S3/Azure/GCS-hosted sites, the key event is a
   `PutObject` (CloudTrail data event) to the website bucket by an unexpected
   principal, or an unexpected CI deploy/commit.
6. **Correlate and respond.** Tie artifact → access within a short window, then
   restore and hunt the initial access (see *Response*).

## Key Concepts

- **Two complementary detectors:** integrity (the file changed) and content (the
  rendered page changed). Running both catches in-place edits and
  origin/bucket swaps alike.
- **Internal vs external (T1491.001 / .002):** internal defacement targets
  intranet systems and login banners; external targets public sites. FIM scope
  and monitoring differ but the logic is the same.
- **Access path:** defacement is downstream of initial access — commonly an
  uploaded web shell (T1505.003), stolen CMS/admin credentials, or an exploited
  upload vulnerability. The write event in logs is what ties it together.
- **Deploy-window discipline:** legitimate deploys change the web root; an
  approved-window + known-principal allowlist keeps FIM noise down.

## Tools & Systems

Wazuh/OSSEC, AIDE, Tripwire, osquery (`file`/`hash` tables), Zeek
(`http.log`/`files.log`), Nginx/Apache/IIS logs, WordPress/Drupal audit-log
plugins, AWS CloudTrail (S3 data events), Azure Monitor/Storage logs, GCP Cloud
Audit Logs, CDN (Cloudflare/Akamai) logs, Sigma web rules, self-hosted synthetic
content-change monitors.

## Detection Queries

### Wazuh -- real-time FIM on the web root

```xml
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>
  <directories check_all="yes" realtime="yes">/var/www/html/wp-content/uploads</directories>
  <nodiff>/var/www/html/config.php</nodiff>
</syscheck>
<!-- Wazuh rules 550 (file modified) / 554 (new file) in the web root fire here -->
```

### Splunk -- upload/admin write preceding a web-root change

```spl
`web_logs` (method IN ("POST","PUT")) (uri_path="*/upload*" OR uri_path="*/admin*" OR status=201)
| stats count values(uri_path) as paths min(_time) as webWriteTime by src_ip, host, http_user_agent
| join host [ search `wazuh` rule_id IN (550,554) location="/var/www*"
             | stats min(_time) as fimTime values(location) as changedFiles by host ]
| where fimTime>=webWriteTime AND (fimTime-webWriteTime) < 600
| table host, src_ip, paths, changedFiles, webWriteTime, fimTime
```

### KQL -- S3 static-site defacement (CloudTrail data events)

```kql
AWSCloudTrail
| where EventName in ("PutObject","DeleteObject","CopyObject")
| where tostring(RequestParameters.bucketName) == "my-website-bucket"
| extend principal = tostring(UserIdentity.arn)
| where principal !has "arn:aws:iam::ACCOUNT:role/site-deploy-ci"
| project TimeGenerated, principal, EventName, key = tostring(RequestParameters.key), SourceIpAddress
```

### Content diff (concept)

```bash
curl -s https://example.com/ | sha256sum | awk '{print $1}' > /tmp/cur.sha
if ! diff -q /var/lib/webmon/index.golden.sha /tmp/cur.sha >/dev/null; then
  curl -s https://example.com/ | grep -Ei "hacked by|pwned|owned by" \
    && echo "ALERT: likely defacement on example.com"
fi
```

## Common Scenarios

- **Web-shell → defacement:** upload POST drops `shell.php`, then `index.php` is
  rewritten — web log + FIM correlate within seconds.
- **Static-site bucket swap:** `PutObject` to the website bucket by a non-deploy
  principal replaces `index.html`.
- **CMS admin abuse:** stolen WordPress admin edits the active theme — caught by
  CMS audit log + FIM on `wp-content/themes`.
- **False positive:** a scheduled CI deploy — resolved by deploy-window and
  known-principal context.

## Output Format

```
DEFACEMENT DETECTION
  Property:        <site / host / bucket>
  Verdict:         <confirmed | suspected | approved-deploy>
  Artifact:        <changed file(s) or page>, markers: <"hacked by ..." | none>
  Access path:     <upload POST | CMS admin | S3 PutObject | stolen creds>
  Principal/IP:    <who / from where>
  ATT&CK:          T1491(.001/.002)[, T1505.003]
  Window:          access <t0> -> change <t1>
  Actions taken:   <restored from backup | node pulled behind maintenance | creds rotated>
```

## Response

- **Restore from known-good backup / redeploy from version control** rather than
  editing in place (NIST CSF RC.RP-01; ATT&CK M1053).
- Pull the affected node behind maintenance/CDN while investigating.
- **Rotate CMS/admin and cloud credentials**; hunt the initial access (web shell,
  stolen creds, upload vuln).
- Harden: WAF, least-privilege web-root and bucket write, read-only/immutable
  deploys, MFA on CMS admin, remove upload-to-exec paths, enable object-store
  versioning + CloudTrail data events.
