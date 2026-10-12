# Detecting Endpoint Denial of Service — research notes

- **Proposed slug:** detecting-endpoint-denial-of-service
- **ATT&CK:** T1499 Endpoint Denial of Service (tactic: impact) — sub-techniques T1499.001 OS Exhaustion Flood, T1499.002 Service Exhaustion Flood, T1499.003 Application Exhaustion Flood, T1499.004 Application or System Exploitation
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to DoS aimed at a specific endpoint/service rather than the
network pipe: exhausting host resources (CPU, memory, file descriptors, TCP
connection tables, thread pools) or triggering a persistent crash by exploiting
a vulnerability. The skill catches resource-exhaustion patterns and
crash/restart loops on servers and applications (web, DNS, DB, app servers), and
distinguishes a targeted endpoint DoS from an organic traffic spike.

## Data sources / telemetry
- **Host performance metrics** — CPU %, memory/commit, open file descriptors,
  socket/connection table size (`netstat`/`ss` SYN_RECV, TIME_WAIT growth),
  thread counts, run queue, disk I/O. Collected via node_exporter/Telegraf,
  Windows perfmon, CloudWatch/Azure Monitor.
- **Service/application logs** — web server 503/504, connection-pool-exhausted
  errors, worker-saturation (Apache mpm, Nginx worker_connections, Tomcat
  thread pool), DB max-connections errors, DNS SERVFAIL/response-time; crash
  logs and core dumps.
- **Crash / restart telemetry** — Windows WER / Event ID 1000 (Application
  Error), 1001 (WER), 7031/7034 (service crashed), 41 (Kernel-Power unexpected
  shutdown); Linux `systemd` unit restart loops, `dmesg` OOM-killer, segfaults;
  Sysmon process-terminate churn.
- **Local network view** — per-service connection rate, slow-loris style
  half-open/long-lived connections (low bytes, held open), Zeek `conn.log`
  with long duration + tiny payload.
- **Exploitation path (T1499.004)** — IDS/WAF alerts for the triggering
  payload preceding the crash; EDR correlating exploit attempt → crash.

## Detection logic / approach
Two detector families:

1. **Resource-exhaustion / flood on the host** — baseline + anomaly on host
   metrics and connection state; alert on sustained saturation with concurrent
   service errors:
   ```
   # pseudo-KQL / metric rule
   Perf | where CounterName in ("% Processor Time","Available MBytes") 
   | summarize avg(value) by Computer, bin(TimeGenerated, 1m)
   | where cpu_sat and mem_low  // + join service 503 spike
   ```
   Slow-loris / service-exhaustion: many concurrent connections per src with
   minimal bytes and long duration (Zeek `conn.log`:
   `duration>Xs AND orig_bytes<Y AND count per src > N`).
2. **Crash/restart-loop detection** — correlate repeated WER/1000, service
   crash 7031/7034, systemd restart, or OOM within a short window on the same
   process → likely T1499.004 exploitation or application-exhaustion crash.
   Join with WAF/IDS hit on the same service immediately prior.

Key discriminator vs network DoS (T1498): the bottleneck is host/service
resources or a crash, often achievable at *low* traffic volume (algorithmic
complexity, slow-loris, a single exploit packet).

## Response / mitigation
Rate limiting, connection limits, timeouts (mod_reqtimeout / Nginx
`client_body_timeout`, `limit_conn`), request-size and complexity caps; WAF
rules for the exhaustion/exploit pattern (M1037). Autoscaling and circuit
breakers for critical services. Patch the crashing vulnerability (M1051);
enable automatic service restart with backoff plus alerting so a restart loop
is visible. Isolate the source; for exploitation, capture the payload for IR.

## Real tools
Prometheus/node_exporter, Telegraf/InfluxDB, Windows Perfmon + Event Log,
Sysmon, Zeek, Suricata, ModSecurity/WAF, systemd journal, `ss`/`netstat`,
osquery, Splunk/Elastic/Sentinel (KQL), CloudWatch/Azure Monitor.

## Draft frontmatter mappings
- mitre_attack: [T1499, T1499.001, T1499.002, T1499.003, T1499.004]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-03, RS.MI-01, PR.IR-04]
- d3fend (optional): D3-RAM adjacent resource monitoring, D3-PM (Process Monitoring), D3-ITF (Inbound Traffic Filtering)
- suggested subdomain: soc-operations
- nearest existing sibling (for the negative trigger): detecting-network-denial-of-service

## Draft description (<=1024 chars)
Detects endpoint denial-of-service — host resource exhaustion (CPU, memory,
file descriptors, connection tables, thread pools), service/application
exhaustion (slow-loris, connection-pool starvation), and crash/restart loops
from application-or-system exploitation — using host performance metrics,
service 503/504 and crash logs (WER/EventID 1000, systemd restarts, OOM
killer), and Zeek connection analysis. Distinguishes targeted endpoint DoS
from organic load (ATT&CK T1499). Use when a specific server or service is
unavailable, crash-looping, or saturated, or when building service-availability
detection. Keywords: endpoint DoS, resource exhaustion, slow loris, connection
pool, crash loop, OOM, 503, T1499, service availability. Do not use for
volumetric network-layer floods or DDoS against the network — use
detecting-network-denial-of-service.

## Key references
- MITRE ATT&CK T1499 (+ .001–.004): https://attack.mitre.org/techniques/T1499/
- OWASP Denial of Service / Slow HTTP attacks: https://owasp.org/
- CISA / US-CERT DoS guidance: https://www.cisa.gov/
- Nginx/Apache rate-limiting & timeout docs: https://nginx.org/ , https://httpd.apache.org/
- Microsoft Windows Error Reporting / Event ID references (verify): https://learn.microsoft.com/

## Open questions / scope boundaries
- Baselines are per-service; ship a method not fixed thresholds.
- Clarify overlap of T1499.004 (exploit-to-crash) with vuln-exploitation
  detection skills — here the *impact signal* (crash/availability) is the focus.
- Must NOT include DoS-generation procedures. Decide depth of per-app-server
  tuning (likely a references file).
