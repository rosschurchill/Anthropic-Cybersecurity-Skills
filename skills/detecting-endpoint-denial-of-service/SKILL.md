---
name: detecting-endpoint-denial-of-service
description: 'Detects endpoint denial-of-service (MITRE T1499) - host resource exhaustion (CPU, memory, file descriptors, connection tables, thread pools), service/application exhaustion (slow-loris, connection-pool starvation), and crash/restart loops from application-or-system exploitation - using host performance metrics, service 503/504 and crash logs (Windows WER/Event ID 1000, service crash 7031/7034, systemd restarts, OOM killer), and Zeek connection analysis. Distinguishes a targeted endpoint DoS from organic load. Use when a specific server or service is unavailable, crash-looping, or saturated, or when building service-availability detection. Keywords: endpoint DoS, resource exhaustion, slow loris, connection pool, crash loop, OOM killer, 503, Event ID 7031, T1499. Do not use for volumetric network-layer floods or DDoS against the network pipe - use detecting-network-denial-of-service.'
domain: cybersecurity
subdomain: soc-operations
tags:
- soc-operations
- threat-detection
- denial-of-service
- resource-exhaustion
- slow-loris
- crash-loop
- availability
- web-security
- t1499
- monitoring
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-03
- RS.MI-01
- PR.IR-04
mitre_attack:
- T1499
- T1499.001
- T1499.002
- T1499.003
- T1499.004
---

# Detecting Endpoint Denial of Service

## When to Use

Use this skill to detect and respond to DoS aimed at a **specific
endpoint/service** rather than the network pipe (ATT&CK T1499): exhausting host
resources (CPU, memory, file descriptors, TCP connection tables, thread pools)
or triggering a persistent crash by exploiting a vulnerability. Reach for it
when:

- A specific server or service is unavailable, saturated, or crash-looping.
- Web/app/DB logs fill with 503/504, connection-pool-exhausted, or
  worker-saturation errors.
- You need to tell a **targeted endpoint DoS** apart from an organic traffic
  spike.

For bandwidth-saturating volumetric floods and DDoS against the network, use
`detecting-network-denial-of-service`.

## Prerequisites

- **Host performance metrics**: CPU%, memory/commit, open file descriptors,
  socket/connection-table state (`ss`/`netstat` SYN_RECV, TIME_WAIT), thread
  counts, run queue — via Prometheus/node_exporter, Telegraf, Windows Perfmon,
  CloudWatch/Azure Monitor.
- **Service/application logs**: web 503/504, connection-pool errors, worker
  saturation (Apache mpm, Nginx `worker_connections`, Tomcat thread pool), DB
  max-connections, DNS SERVFAIL/response-time.
- **Crash/restart telemetry**: Windows WER / Event ID 1000 (Application Error),
  7031/7034 (service crashed), 41 (Kernel-Power); Linux `systemd` restart loops,
  `dmesg` OOM-killer, segfaults; Sysmon process-terminate churn.
- Local network view (Zeek `conn.log`) for slow-loris patterns; WAF/IDS for the
  exploitation path.

## Workflow

1. **Baseline per service** (CPU/mem, connection counts, error rates, restart
   frequency). Ship a method (percentile/stddev), not fixed numbers.
2. **Resource-exhaustion detection.** Alert on sustained host saturation (CPU
   high + memory low, FD/connection-table near limit) **concurrent with** a
   service-error spike (503/504, pool exhausted).
3. **Service-exhaustion / slow-loris detection.** In Zeek `conn.log`, flag many
   concurrent connections per source with long duration and minimal bytes
   (`duration > Xs AND orig_bytes < Y AND count per src > N`).
4. **Crash/restart-loop detection.** Correlate repeated WER/1000, service crash
   7031/7034, systemd restarts, or OOM within a short window on the same process
   — likely application-exhaustion or T1499.004 exploitation.
5. **Tie to an exploit (T1499.004).** Join a crash with a WAF/IDS hit on the same
   service immediately prior — exploit attempt → crash.
6. **Discriminate and respond.** Low traffic + host/service bottleneck or crash =
   endpoint DoS (not network flood). Apply limits and patch (see *Response*).

## Key Concepts

- **The bottleneck is the host/service, not the link.** Endpoint DoS is often
  achievable at **low** traffic volume — algorithmic complexity, slow-loris, or a
  single exploit packet — which is the key discriminator from T1498.
- **Sub-techniques:** OS exhaustion (.001), service exhaustion (.002),
  application exhaustion (.003), application-or-system exploitation (.004).
- **Crash loops are a signal, not just an ops issue:** repeated unexpected
  restarts of the same service, especially after an inbound request pattern, can
  be a deliberate availability attack.
- **Correlate metric + log + crash:** any one alone is noisy; together they are a
  confident endpoint-DoS verdict.

## Tools & Systems

Prometheus/node_exporter, Telegraf/InfluxDB, Windows Perfmon + Event Log,
Sysmon, Zeek, Suricata, ModSecurity/WAF, `systemd` journal, `ss`/`netstat`,
osquery, Splunk/Elastic/Microsoft Sentinel, CloudWatch/Azure Monitor.

## Detection Queries

### KQL -- host saturation concurrent with service 503 spike

```kql
let sat = Perf
| where CounterName in ("% Processor Time","Available MBytes")
| summarize cpu=avgif(CounterValue, CounterName=="% Processor Time"),
            memMB=avgif(CounterValue, CounterName=="Available MBytes")
          by Computer, bin(TimeGenerated, 1m)
| where cpu > 90 and memMB < 256;
let errs = W3CIISLog
| where scStatus in (503,504)
| summarize err=count() by Computer, bin(TimeGenerated, 1m)
| where err > 100;
sat | join kind=inner errs on Computer, TimeGenerated
| project TimeGenerated, Computer, cpu, memMB, err
```

### Zeek -- slow-loris / service exhaustion (concept)

```
# Many long, low-byte connections from one source to one service port
event connection_state_remove(c: connection) {
  if (c$duration > 60sec && c$orig$size < 200 && c$id$resp_p == 443/tcp)
    SumStats... # count per orig_h; alert when > 100 concurrent held-open
}
```

### Splunk -- crash/restart loop correlated with a prior WAF hit

```spl
(`wineventlog` EventCode IN (1000,7031,7034)) OR (source="systemd" "Scheduled restart")
| stats count as crashes min(_time) as firstCrash by host, process
| where crashes >= 5
| join host [ search `waf` action=alert | stats max(_time) as wafTime by host, uri ]
| where wafTime <= firstCrash AND (firstCrash - wafTime) < 300
| table host, process, crashes, uri, wafTime, firstCrash
```

## Common Scenarios

- **Slow-loris:** hundreds of half-open, byte-starved connections exhaust the web
  worker pool at trivial bandwidth → `limit_conn` + `client_body_timeout`.
- **Connection-pool starvation:** a client opens and holds all DB connections →
  pool-exhausted errors, high TIME_WAIT.
- **Exploit-to-crash (T1499.004):** a malformed request crashes the app
  repeatedly → WER/7034 loop correlated with a WAF hit → patch.
- **False positive:** a legitimate traffic surge (launch/marketing) saturates CPU
  — resolved by traffic-source diversity and absence of crash/exploit signal.

## Output Format

```
ENDPOINT DOS DETECTION
  Host/service:    <computer / service>
  Verdict:         <confirmed | suspected | organic-load>
  Pattern:         <resource-exhaustion | slow-loris | pool-starvation | crash-loop/exploit>
  Evidence:        <CPU/mem sat | 503 spike | conn-state | crash EIDs | prior WAF hit>
  Source:          <src ip(s) if identifiable>
  ATT&CK:          T1499(.001-.004)
  Actions taken:   <rate/conn limits | timeouts | WAF rule | patched | source blocked>
```

## Response

- Apply **rate limiting, connection limits, and timeouts** (Apache
  `mod_reqtimeout`, Nginx `client_body_timeout` + `limit_conn`), request-size and
  complexity caps, and WAF rules for the exhaustion/exploit pattern (ATT&CK
  M1037).
- Add **autoscaling and circuit breakers** for critical services (NIST CSF
  PR.IR-04).
- **Patch the crashing vulnerability** (M1051) and configure automatic restart
  with backoff **plus alerting** so a restart loop is visible, not silent.
- Isolate/block the source; for exploitation, capture the triggering payload for
  IR.
