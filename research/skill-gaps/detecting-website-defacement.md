# Detecting Website Defacement — research notes

- **Proposed slug:** detecting-website-defacement
- **ATT&CK:** T1491 Defacement (tactic: impact) — sub-techniques T1491.001 Internal Defacement and T1491.002 External Defacement
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to unauthorized modification of visual content on web
properties and internal systems — defaced home pages, injected hacktivist
messages, swapped images, replaced login portals — which affects content
integrity and often signals a completed intrusion. The skill combines file
integrity monitoring of web roots, web-server log analysis for the write path,
and external content-change monitoring so defenders catch both the defacement
artifact and the access that produced it.

## Data sources / telemetry
- **File creation/modification (DS0022)** — FIM on web document roots
  (`/var/www`, `wwwroot`, CMS upload dirs): hashes/mtime changes to
  `index.html`, `index.php`, template files, and new/unexpected files
  (web shells, `.jpg` that is really a script).
- **Application / web-server logs (DS0015)** — Apache/Nginx/IIS access + error
  logs: POST/PUT to admin or upload endpoints, suspicious 200s to newly created
  paths, abnormal user-agents, admin logins from new IPs preceding content
  change; CMS audit logs (WordPress/Drupal/Joomla) for unexpected
  edits/plugin/theme changes.
- **Network traffic content (DS0029)** — IDS/proxy capture of outbound page
  content; synthetic HTTP monitoring of the public page body.
- **Cloud/IaaS** — object-store audit logs (S3 `PutObject`/CloudTrail,
  Azure Storage/static website, GCS access logs) for writes to the bucket
  serving a static site; CDN purge/origin events.
- **Version control / CI** — unexpected commits/deploys to the site repo.

## Detection logic / approach
Two complementary detectors:

1. **Integrity detection** — FIM baseline of the web root; alert on any
   hash/content change to served files outside an approved deploy window.
   OSSEC/Wazuh syscheck, AIDE, or Tripwire:
   ```
   # Wazuh ossec.conf
   <syscheck><directories check_all="yes" realtime="yes">/var/www/html</directories></syscheck>
   # alerts rule 550/554 on modified/new file in web root
   ```
2. **Content/availability detection** — periodic fetch of the public URL,
   diff against a known-good snapshot and/or keyword match for common
   defacement markers ("hacked by", "pwned", "owned by", political slogans).
   osquery `file`/`hash` table for deployed hosts; Zeek `http.log` +
   `files.log` to flag content-type anomalies.

Correlate (1)/(2) with the *access* that caused it: web log POST to upload/admin
endpoint → new file in web root → content change, within a short window. Sigma
web-log rules for web-shell drops and admin-panel abuse are reusable here.
For S3/static sites: CloudTrail `PutObject` to the website bucket by an
unexpected principal is the key event.

## Response / mitigation
Restore from known-good backup/golden image (M1053); redeploy from version
control rather than editing in place. Pull the affected node behind
maintenance/CDN while investigating. Rotate CMS/admin and cloud credentials;
hunt for the initial access (web shell, stolen creds, vuln). Harden: WAF,
least-privilege on web-root and bucket write, read-only/immutable deploys,
MFA on CMS admin, remove upload-to-exec paths, enable object-store versioning
+ CloudTrail data events.

## Real tools
Wazuh/OSSEC, AIDE, Tripwire, osquery, Zeek, Nginx/Apache/IIS logs, WordPress
audit log plugins, AWS CloudTrail (S3 data events), Azure Monitor/Storage logs,
GCP Cloud Audit Logs, CDN (Cloudflare/Akamai) logs, Sigma web rules,
external uptime/content-change monitors (self-hosted synthetic checks).

## Draft frontmatter mappings
- mitre_attack: [T1491, T1491.001, T1491.002, T1505.003]
- nist_csf: [DE.CM-01, DE.CM-09, PR.DS-06, RS.MI-02, RC.RP-01]
- d3fend (optional): D3-FIM (File Integrity Monitoring style), D3-MFA for admin hardening, D3-NTA (Network Traffic Analysis)
- suggested subdomain: incident-response
- nearest existing sibling (for the negative trigger): detecting-stuxnet-style-attacks

## Draft description (<=1024 chars)
Detects website and internal-system defacement — unauthorized changes to
served HTML/templates/images, injected hacktivist messages, and swapped portals
— by combining file integrity monitoring of web roots (Wazuh/AIDE/Tripwire),
web-server and CMS log analysis for the write path, external content-change
diffing, and cloud object-store audit logs (S3 PutObject/CloudTrail) for static
sites. Correlates the defacement artifact with the access that produced it
(ATT&CK T1491). Use when triaging suspected defacement, content-integrity
alerts, or unexplained web-root changes. Keywords: defacement, website hacked,
file integrity monitoring, web root, CMS compromise, web shell, S3 static site,
T1491, content integrity. Do not use for detecting web-shell persistence
mechanics in depth — pair with a web-shell detection skill.

## Key references
- MITRE ATT&CK T1491 (+ .001/.002) and DET0238: https://attack.mitre.org/techniques/T1491/
- Wazuh File Integrity Monitoring docs: https://documentation.wazuh.com/
- AIDE: https://aide.github.io/ ; Tripwire: https://github.com/Tripwire/tripwire-open-source
- AWS CloudTrail S3 data events: https://docs.aws.amazon.com/
- OWASP guidance on web defacement / unrestricted file upload: https://owasp.org/

## Open questions / scope boundaries
- Decide split between host-served and cloud/static-site defacement; both fit
  but the telemetry differs — may need a references file per platform.
- Boundary with web-shell detection (T1505.003): this skill detects the
  *defacement outcome + access path*, not web-shell internals exclusively.
- Must NOT include instructions for performing defacement. Confirm whether
  "internal" defacement (intranet, login banners) needs separate FIM scope.
