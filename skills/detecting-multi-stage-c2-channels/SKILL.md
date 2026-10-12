---
name: detecting-multi-stage-c2-channels
description: 'Detects multi-stage command-and-control (MITRE T1104) - a first-stage callback that downloads or launches a later stage on separate, non-overlapping infrastructure - by correlating process lineage with cross-destination network activity: Process A beacons to Dest1, spawns or injects into Process B, which beacons to an unrelated Dest2 within a short window, often with a T1105 ingress download between them. Implemented as a SIEM correlation keyed on Sysmon ProcessGuid across Event ID 1/3/22/8/10 plus Zeek. Use when hunting staged C2 where a loader hands off to a more capable second-stage channel. Keywords: multi-stage channels, first-stage C2, stager, second stage, ingress tool transfer, infrastructure diversity, T1104. Do not use for single-channel beacon periodicity hunts - use hunting-for-command-and-control-beaconing.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- command-and-control
- multi-stage-channels
- stager
- process-lineage
- sysmon
- zeek
- t1104
- ingress-tool-transfer
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-09
- DE.AE-02
- DE.AE-03
- RS.MI-01
mitre_attack:
- T1104
- T1105
- T1071.001
- T1568
- T1008
---

# Detecting Multi-Stage C2 Channels

## When to Use

Use this skill to detect command-and-control implemented in **multiple stages
hosted on separate, non-overlapping infrastructure** (ATT&CK T1104) — a
first-stage callback that collects host info / updates tooling / downloads a
second stage, followed by a more capable later-stage channel to a different
destination. The detection target is the **stage transition**: the
process-lineage and cross-destination pivot that distinguishes staged C2 from a
single beacon, since the staging is precisely what makes each stage individually
quieter. Reach for it when:

- Hunting staged C2 where a loader hands off to a second stage.
- One host contacts two unrelated rare destinations in sequence.

For single-channel beacon periodicity use
`hunting-for-command-and-control-beaconing`; for encoded C2 payloads use
`detecting-encoded-c2-channels`.

## Prerequisites

- **Host**: Sysmon Event ID 1 (process creation + parent lineage), 3 (network),
  22 (DNS), and 8/10 (CreateRemoteThread / process access) for injection-based
  handoff; Security 4688. ProcessGuid must be logged (Sysmon ties EID 1/3/22 by
  it).
- **Network**: Zeek `conn.log`/`http.log`/`dns.log`/`ssl.log`, proxy logs,
  NetFlow — to see two distinct destinations contacted in sequence and an ingress
  download between them.
- Threat-intel / newly-registered-domain / JA3 enrichment.
- A SIEM capable of **stateful cross-event correlation** (this is not a
  single-event rule).

## Workflow

1. **Baseline legitimate multi-host chains** (software updaters, CDNs, OS
   telemetry) and allowlist them by domain / signed binary.
2. **Stage-handoff correlation (core logic).** Within a 1–5 min window:
   - Process A (Sysmon EID 1) makes an outbound conn/DNS (EID 3/22) to **Dest1**,
   - A **spawns** child B **or injects** (EID 8/10) into B,
   - B makes an outbound conn/DNS to **Dest2**, where Dest2 ≠ Dest1 and the two
     share **no infrastructure** (different domain/ASN/cert).
   Implement as a Splunk transaction / KQL join on ProcessGuid + host.
3. **Ingress between stages (T1105).** A download (`certutil`/`bitsadmin`/`curl`/
   PowerShell `DownloadFile`) landing a new exe/DLL that then beacons to the
   second destination.
4. **Infrastructure-diversity signal.** One host contacting two newly-seen,
   unrelated rare destinations in sequence — enrich with NRD/JA3/threat intel.
5. **Confirm C2 nature.** Run beaconing periodicity (RITA/Zeek) per destination;
   but the **distinguishing** feature is the staged pivot, not the beacon.
6. **Respond** (see *Response*) — enumerate all stages' infrastructure fully.

## Key Concepts

- **The pivot is the point:** each stage alone may look benign; the
  **A→Dest1, A spawns/injects B, B→Dest2** chain across unrelated infrastructure
  is the signal that single-beacon hunts miss.
- **ProcessGuid is the join key:** Sysmon ties process creation to its network
  connections, letting you attribute Dest1 and Dest2 to a lineage, not just a
  host.
- **Non-overlapping by design:** staged C2 deliberately uses separate
  infrastructure per stage — so on confirmation, **enumerate fully**; blocking
  one stage leaves the others live.
- **Ingress often sits between stages:** a LOLBin download landing a new binary
  that then beacons elsewhere is the classic handoff.

## Tools & Systems

Sysmon, Zeek, RITA, Suricata/Arkime, Splunk / Microsoft Sentinel (KQL
correlation), Sigma (correlation rules), newly-registered-domain / threat-intel
feeds.

## Detection Queries

### Splunk -- stage handoff: A->Dest1, A spawns B, B->Dest2 (cross-destination)

```spl
`sysmon` EventCode=3
| rename ProcessGuid as guidA, DestinationIp as dest1, Image as imgA
| join host [ search `sysmon` EventCode=1
    | rename ProcessGuid as guidB, ParentProcessGuid as guidA, Image as imgB ]
| join guidB host [ search `sysmon` EventCode=3
    | rename ProcessGuid as guidB, DestinationIp as dest2 ]
| where dest1!=dest2
| lookup asn_domain ip AS dest1 OUTPUT org AS org1 | lookup asn_domain ip AS dest2 OUTPUT org AS org2
| where org1!=org2
| search NOT [ | inputlookup updater_cdn_allowlist | fields dest1 ]
| table _time, host, imgA, dest1, org1, imgB, dest2, org2
```

### KQL -- injection-based handoff to a second destination

```kql
let inj = DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall","ProcessInjection")
| project host=DeviceName, injector=InitiatingProcessId, target=ProcessId, t=Timestamp;
let net = DeviceNetworkEvents
| project host=DeviceName, pid=InitiatingProcessId, RemoteUrl, RemoteIP, nt=Timestamp;
inj
| join kind=inner (net | project host, injector=pid, dest1=RemoteIP, t1=nt) on host, injector
| join kind=inner (net | project host, target=pid, dest2=RemoteIP, t2=nt) on host, target
| where dest1 != dest2 and t2 between (t .. t + 5m)
| project host, injector, dest1, target, dest2, t
```

### Ingress-between-stages (concept)

```spl
`sysmon` EventCode=1 (Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR CommandLine="*DownloadFile*")
| `comment("new binary landed here; correlate its ProcessGuid to a subsequent EID 3 to a new dest")`
```

## Common Scenarios

- **Loader → beacon:** a phishing macro process calls Dest1 (stager), drops and
  runs `beacon.exe` which calls an unrelated Dest2 — the SPL join fires.
- **Injection handoff:** stage-1 injects into `explorer.exe` (EID 8/10) which
  then beacons to a second ASN.
- **Ingress pivot:** `certutil` downloads a DLL that beacons elsewhere.
- **False positive:** an installer that contacts a CDN then a license server —
  allowlisted multi-host chain.

## Output Format

```
MULTI-STAGE C2 DETECTION
  Host:            <host>
  Verdict:         <confirmed | suspected | benign-updater-chain>
  Stage 1:         <processA> -> <dest1> (<org/ASN1>)
  Handoff:         <spawn | injection EID 8/10 | ingress download T1105>
  Stage 2:         <processB> -> <dest2> (<org/ASN2>), window <t1..t2>
  Infra diversity: <different domain/ASN/cert? y>
  ATT&CK:          T1104[, T1105, T1071.001, T1568, T1008]
  Actions taken:   <host isolated | all-stage IOCs captured | env swept for stage-1 | infra fully blocked>
```

## Response

- Deploy **egress IPS / allowlisting** (ATT&CK M1031); block newly-registered /
  rare destinations; restrict LOLBins used for ingress (`certutil`/`bitsadmin`).
- **On detection:** isolate the host, capture **both stages' infrastructure** as
  IOCs, identify first- and later-stage implant binaries via Sysmon lineage,
  sweep the environment for the same stage-1 indicator, and **block all
  discovered infrastructure** — it is intentionally non-overlapping, so enumerate
  fully.
