# Integrated DNS C2 Detection Pipeline Architecture

```
DNS C2 Detection Pipeline Architecture:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┌────────────────────────────────────────────────────────┐
  │                  DATA SOURCES                          │
  │  Zeek dns.log  |  Suricata EVE  |  Recursive Resolver │
  │  Passive DNS   |  PCAP capture  |  EDR DNS telemetry  │
  └───────────────────────┬────────────────────────────────┘
                          │
  ┌───────────────────────▼────────────────────────────────┐
  │              PREPROCESSING                             │
  │  Parse timestamps | Extract subdomains | Normalize     │
  │  FQDN | Resolve base domain | Lookup in whitelist     │
  └───────────────────────┬────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
  ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
  │  ENTROPY     │ │  BEACONING  │ │  DGA        │
  │  ANALYSIS    │ │  DETECTION  │ │  CLASSIFIER │
  │              │ │             │ │             │
  │ Shannon ent. │ │ Interval    │ │ ML model    │
  │ Subdomain    │ │ analysis    │ │ Random      │
  │ length       │ │ Jitter/CV   │ │ Forest or   │
  │ Encoding     │ │ Duration    │ │ Gradient    │
  │ patterns     │ │ Periodicity │ │ Boosting    │
  └───────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
  ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
  │ TXT RECORD   │ │  TOOL       │ │  PASSIVE    │
  │ PAYLOAD      │ │  SIGNATURE  │ │  DNS        │
  │ ANALYSIS     │ │  MATCHING   │ │  ENRICHMENT │
  │              │ │             │ │             │
  │ Base64 decode│ │ Iodine      │ │ First seen  │
  │ PE/ELF detect│ │ dnscat2     │ │ Registrar   │
  │ PS stager    │ │ dns2tcp     │ │ Age check   │
  │ Size anomaly │ │ Cobalt DNS  │ │ Reputation  │
  └───────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
  ┌───────▼───────────────▼───────────────▼────────────────┐
  │                CORRELATION ENGINE                       │
  │  Combine scores from all detectors                     │
  │  Weighted scoring: entropy(30%) + beacon(25%) +        │
  │    DGA(20%) + TXT payload(15%) + signature(10%)        │
  │  Threshold: score > 60 = alert, > 40 = investigate     │
  └───────────────────────┬────────────────────────────────┘
                          │
  ┌───────────────────────▼────────────────────────────────┐
  │                ALERTING & RESPONSE                     │
  │  Generate SIEM alert with all evidence                 │
  │  Block domain in DNS firewall / RPZ                    │
  │  Isolate endpoint via EDR                              │
  │  Create incident ticket with IOCs                      │
  └────────────────────────────────────────────────────────┘
```
