# Detecting AI Service Denial and Cost Harvesting — research notes

- **Proposed slug:** detecting-ai-service-denial-and-cost-harvesting
- **ATLAS:** AML.T0029 Denial of AI Service — plus folded-in AML.T0034 Cost Harvesting
  (sub-technique AML.T0034.000 Excessive Queries) and AML.T0046 Spamming AI System with
  Chaff Data
- **Status:** research (not yet a skill)

## Defensive goal
Detect resource/compute exhaustion and economic abuse of AI inference services: flooding a
model to degrade/shut it down (denial of AI service), crafted worst-case-compute inputs
(sponge examples), and high-volume or high-complexity querying that runs up the bill
("denial of wallet" / cost harvesting). Also detect chaff spamming — junk inputs that inflate
detections or low-severity events to drown monitoring and exhaust human-in-the-loop review.
Distinguish an attack from an organic traffic/cost spike.

## Data sources / telemetry
- **Inference-API gateway logs** — per-principal/per-key request rate, concurrency, input
  size and token count, and billed cost per request; 429/503 rates and queue depth.
- **Model-serving / GPU metrics** — GPU utilization, compute-time and memory per request,
  output-token count and generation length, batch latency. From Triton/vLLM/TGI metrics,
  DCGM GPU exporter, Prometheus; surfaced in Arize/WhyLabs/Langfuse (LLM token+cost traces).
- **Cost/billing telemetry** — provider usage/billing stream and anomaly alerts (e.g. Palo
  Alto Cortex "Potential Denial of Wallet abusing AI services" analytics alert — **verify**
  exact name), per-tenant spend-rate.
- **Guardrail / moderation logs** — volume of flagged events per principal (chaff inflates
  these), and the human-review/HITL queue backlog as a drown-the-SOC signal.

## Detection logic / approach
Three detector families keyed to the folded techniques:

1. **Flood / DoS (AML.T0029)** — sustained per-principal request rate or concurrency far over
   baseline with rising 429/503 and queue depth → availability attack.
2. **Sponge / cost harvesting (AML.T0034)** — anomalous *compute per request*, not just count.
   Flag inputs driving worst-case latency/energy/token generation, and sustained high spend-rate:
   ```
   # pseudo-rule
   if gpu_time_per_req > p99_baseline  and output_tokens near max_tokens
      and principal_spend_rate > K * baseline
   -> alert: cost harvesting / sponge inputs (AML.T0034)
   # high-volume variant (Excessive Queries, T0034.000):
   if request_rate > N/min sustained and low input complexity -> excessive-queries
   ```
   Sponge examples push models to worst-case energy/latency (Shumailov et al. report up to
   ~10–200x energy on some tasks) — monitor compute from a worst-case, not average, view.
3. **Chaff spamming (AML.T0046)** — spike in low-severity/benign-but-flagged events or
   agentic HITL approvals from one source that inflates the detection/alert queue without
   corresponding genuine findings → drown-the-monitoring signal; correlate flagged-event
   volume against confirmed-true-positive rate (precision collapse = chaff).

Discriminator vs network/endpoint DoS: the exhausted resource is **model compute / inference
budget / the analyst queue**, often at low request volume (one sponge input, algorithmic blowup).

## Response / mitigation
Per-principal rate limits, concurrency caps, and token/compute budgets (max_tokens, max
input length, request-complexity caps); spend-rate circuit breakers and per-tenant quotas to
cap denial-of-wallet. Admission control / request prioritization and autoscaling with a hard
ceiling. Reject or down-rank worst-case-compute inputs; cache. For chaff, deduplicate and
cluster flagged events, rate-limit the alert pipeline per source, and gate HITL with
reputation so junk cannot exhaust reviewers. Reference worst-case energy analysis as a
hardening measure (per the sponge-examples paper).

## Real tools
Cloud AI gateway logs and usage/billing APIs; Palo Alto Cortex AI analytics (denial-of-wallet
alert — verify); NVIDIA DCGM exporter + Prometheus/Grafana; vLLM / TGI / Triton serving
metrics; Arize, WhyLabs, Fiddler, Langfuse (token/cost/latency observability); NeMo Guardrails
and LLM Guard (input gating / rate control); Kubernetes HPA + API-gateway (Kong/Envoy) rate
limiting.

## Draft frontmatter mappings
- atlas: [AML.T0029, AML.T0034, AML.T0046]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, RS.MI-01, PR.PS-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-model-extraction-attacks

## Draft description (<=1024 chars)
Detects denial of AI service, sponge/compute-exhaustion inputs, denial-of-wallet cost
harvesting, and chaff spamming against inference services. Uses inference-API gateway rate and
per-request cost logs, GPU/compute and token-count serving metrics (DCGM, vLLM/Triton,
Arize/WhyLabs/Langfuse), billing anomaly streams, and guardrail/HITL-queue volume. Flags
compute-per-request and spend-rate anomalies (not just request count), excessive-query floods,
and flagged-event spikes whose true-positive precision collapses. Use when an AI model is
being overloaded, running up unexpected inference cost, hit with worst-case-latency inputs, or
spammed with junk that floods monitoring. Keywords: denial of AI service, sponge examples,
denial of wallet, cost harvesting, chaff, AML.T0029, AML.T0034, AML.T0046, token budget, GPU
exhaustion, rate limit. Do not use for query-based model theft - use
detecting-model-extraction-attacks.

## Key references
- MITRE ATLAS AML.T0029 Denial of AI Service; AML.T0034 Cost Harvesting (+.000 Excessive
  Queries); AML.T0046 Spamming AI System with Chaff Data: https://atlas.mitre.org/
- Shumailov et al., "Sponge Examples: Energy-Latency Attacks on Neural Networks" (arXiv
  2006.03463)
- OWASP LLM Top 10 — LLM10 Unbounded Consumption / Model Denial of Service: https://owasp.org/
- Palo Alto Cortex "Potential Denial of Wallet abusing AI services" alert (verify naming)
- NIST AI RMF (availability/robustness) / NIST AI 100-2: https://csrc.nist.gov/

## Open questions / scope boundaries
- Confirm AML.T0034 sub-technique set (Excessive Queries high-volume vs resource-intensive
  high-complexity) and the Palo Alto alert name — **verify**.
- Baselines are per-model/per-tenant and cost-model-specific; ship a method, not thresholds.
- Overlap with extraction: many queries can serve either theft or cost abuse — separate on
  *intent signal* (output reconstruction vs pure compute/cost burn) and cross-reference.
