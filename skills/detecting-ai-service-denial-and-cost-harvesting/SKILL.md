---
name: detecting-ai-service-denial-and-cost-harvesting
description: 'Detects denial of AI service, sponge and compute-exhaustion inputs, denial-of-wallet cost harvesting, and chaff spamming against inference services. Uses inference-API gateway rate and per-request cost logs, GPU and token-count serving metrics (NVIDIA DCGM, vLLM, Triton, Arize, WhyLabs, Langfuse), provider billing anomaly streams, and guardrail and human-in-the-loop queue volume. Flags compute-per-request and spend-rate anomalies (not just request count), excessive-query floods, and flagged-event spikes whose true-positive precision collapses. Use when an AI model is being overloaded, running up unexpected inference cost, hit with worst-case-latency inputs, or spammed with junk that floods monitoring. Keywords: denial of AI service, sponge examples, denial of wallet, cost harvesting, chaff, AML.T0029, AML.T0034, AML.T0046, token budget, GPU exhaustion, rate limit, OWASP LLM10. Do not use for query-based model theft or extraction - use detecting-model-extraction-attacks.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- denial-of-service
- cost-harvesting
- denial-of-wallet
- sponge-examples
- llm
- gpu-exhaustion
- rate-limiting
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0029
- AML.T0034
- AML.T0046
---
# Detecting AI Service Denial and Cost Harvesting

## Overview

This skill detects resource, compute, and economic abuse of AI inference services. MITRE ATLAS covers three related techniques:

- **AML.T0029 (Denial of AI Service)** — flooding a model to degrade or shut it down (an availability attack).
- **AML.T0034 (Cost Harvesting)** — high-volume or high-complexity querying that runs up the inference bill ("denial of wallet"), including crafted worst-case-compute inputs.
- **AML.T0046 (Spamming AI System with Chaff Data)** — junk inputs that inflate detections or low-severity events to drown monitoring and exhaust human-in-the-loop (HITL) review.

The exhausted resource is **model compute, inference budget, or the analyst queue** — not network bandwidth or endpoint CPU — and the attack often lands at *low request volume* (a single sponge input or an algorithmic blowup). The central task is to separate an attack from an organic traffic or cost spike by watching compute-per-request and spend-rate, not request count alone. This maps to OWASP LLM Top 10 **LLM10 (Unbounded Consumption)**. Distinguish this from query-based model theft, where the goal is reconstructing the model rather than burning compute — that is detecting-model-extraction-attacks.

## When to Use

- An inference endpoint is degraded or returning rising 429/503 under sustained load.
- Inference spend or token usage spikes with no matching business driver (possible denial of wallet).
- Latency or GPU time per request jumps while request volume stays flat (possible sponge inputs).
- A guardrail/alert pipeline or HITL review queue is flooded with low-value flagged events (possible chaff).
- You are setting budgets, quotas, and circuit breakers for a model-serving platform.

## Prerequisites

- Access to inference-API gateway logs: per-principal/per-key request rate, concurrency, input size and token count, billed cost per request, and 429/503 and queue-depth counters.
- Model-serving and GPU metrics: GPU utilization, compute time and memory per request, output-token count and generation length, batch latency. Sources include vLLM / TGI / Triton serving metrics, the NVIDIA DCGM exporter, and Prometheus/Grafana.
- Observability for token/cost/latency traces (Arize, WhyLabs, Fiddler, Langfuse).
- Provider usage/billing stream and per-tenant spend-rate (cloud AI-gateway and billing APIs).
- Guardrail/moderation logs and the HITL queue backlog.

## Workflow

### 1. Baseline normal cost and compute per tenant
Establish per-principal and per-tenant baselines for request rate, concurrency, GPU time per request, output tokens, and spend-rate. Baselines are model- and cost-model-specific; compute p50/p99 from a known-good window rather than hard-coding thresholds.

### 2. Flood / denial-of-service detection (AML.T0029)
Alert when a principal sustains request rate or concurrency far over baseline while 429/503 and queue depth rise together — the signature of an availability attack rather than a healthy burst.

### 3. Sponge / cost-harvesting detection (AML.T0034)
Watch *compute per request*, not just count. Sponge examples push a model to worst-case energy and latency (sponge examples, Shumailov et al.), so a single crafted input can dominate GPU time. Combine compute and spend signals.

```python
def cost_harvesting_flags(req, base):
    """req: this request's metrics; base: per-tenant baselines (p99 etc.). Tune all thresholds."""
    sponge = req["gpu_time_ms"] > base["gpu_time_p99"] and req["output_tokens"] >= 0.95 * req["max_tokens"]
    denial_of_wallet = req["principal_spend_rate"] > base["spend_rate_mult"] * base["spend_rate_base"]
    excessive_queries = req["req_rate_per_min"] > base["rate_floor"] and req["input_complexity"] == "low"
    return {"sponge_or_resource_intensive": sponge,
            "denial_of_wallet": denial_of_wallet,
            "excessive_queries": excessive_queries}
```

### 4. Chaff-spam detection (AML.T0046)
Correlate flagged-event volume against the confirmed-true-positive rate per source. A spike in low-severity or benign-but-flagged events (or agentic HITL approvals) from one source whose **precision collapses** is the drown-the-monitoring signal.

```python
def chaff_score(flagged_events, confirmed_true_positives):
    precision = confirmed_true_positives / max(flagged_events, 1)
    return {"flagged": flagged_events, "precision": round(precision, 3),
            "suspected_chaff": flagged_events > 0 and precision < 0.05}  # tune precision floor
```

### 5. Correlate and classify
A finding is an attack when the resource signal (compute/spend/queue) is anomalous and sustained. Separate from extraction by intent: cost/compute burn versus output reconstruction (unique-input ratio, full-confidence-vector requests point to extraction — cross-reference the sibling).

### 6. Enforce controls and re-validate
Apply the Response controls, then confirm spend-rate and compute anomalies return to baseline.

## Key Concepts

- **Denial of wallet.** Economic denial of service: the service stays up but attacker-driven usage runs the bill past budget.
- **Sponge example.** An input crafted to trigger worst-case compute (long generation, pathological branching), measured by GPU time and energy, not request count.
- **Excessive queries.** A high-volume, low-complexity flood aimed at exhausting the inference budget or capacity.
- **Chaff.** Junk inputs that inflate the detection/alert queue so genuine findings are buried and human reviewers are exhausted.
- **Worst-case view.** Monitor compute from a p99/worst-case perspective; averages hide single-input blowups.

## Tools & Systems

| Tool / system | Role |
|---------------|------|
| Cloud AI-gateway logs and usage/billing APIs | Request rate, per-request cost, spend-rate, billing anomalies |
| NVIDIA DCGM exporter + Prometheus/Grafana | GPU utilization, compute time, memory per request |
| vLLM / TGI / Triton serving metrics | Token counts, generation length, batch latency |
| Arize, WhyLabs, Fiddler, Langfuse | Token/cost/latency observability traces |
| NeMo Guardrails, LLM Guard | Input gating, length/complexity rate control |
| API gateway (Kong/Envoy), Kubernetes HPA | Rate limiting, concurrency caps, autoscaling with a ceiling |

Vendor AI-security analytics (for example Palo Alto Cortex) ship denial-of-wallet and AI-abuse detections; confirm the exact alert name in your tenant before relying on it.

## Detection Queries

```kusto
// Availability flood: sustained rate with rising error/queue (AML.T0029)
InferenceGateway
| where Timestamp > ago(5m)
| summarize rps=count()/300.0, err=countif(Status in (429,503)), maxq=max(QueueDepth) by Principal
| where rps > BaselineRps * 10 and err > 0 and maxq > QueueFloor
```

```kusto
// Cost/compute anomaly: spend and GPU time per request (AML.T0034)
ServingMetrics
| summarize gpu_p99=percentile(GpuTimeMs,99), spend=sum(CostUsd),
            near_max=countif(OutputTokens >= 0.95*MaxTokens) by Principal, bin(Timestamp,15m)
| where gpu_p99 > BaselineGpuP99 or spend > BaselineSpend * SpendMult
```

```kusto
// Chaff: flagged-event spike with collapsing precision (AML.T0046)
GuardrailEvents
| summarize flagged=count(), tp=countif(ConfirmedTruePositive) by Source, bin(Timestamp,1h)
| extend precision = todouble(tp)/flagged
| where flagged > FlagFloor and precision < 0.05
```

## Common Scenarios

- **Token-flood denial of wallet:** one API key drives millions of max-length generations overnight; spend-rate circuit breaker and token-budget cap contain it.
- **Single sponge input:** a crafted prompt forces pathological generation length; GPU-time p99 alert fires at near-zero request volume.
- **Capacity flood:** a botnet saturates concurrency, 429/503 climb, legitimate users are denied.
- **SOC drowning:** an attacker spams benign-but-suspicious inputs so the HITL queue backs up and a real alert is missed; precision-collapse detector flags the source.

## Output Format

Report per finding:
- Technique: denial of service (AML.T0029), cost harvesting/sponge (AML.T0034), or chaff (AML.T0046).
- Principal/tenant, time window, and the anomalous resource signal (rps and error/queue, GPU-time p99, spend-rate, or flagged-volume/precision).
- Baseline vs observed values and the sustained duration.
- Estimated cost or availability impact and recommended control (rate limit, budget cap, circuit breaker, HITL reputation gate).

## Response

- Enforce per-principal rate limits, concurrency caps, and token/compute budgets (max_tokens, max input length, request-complexity caps).
- Add spend-rate circuit breakers and per-tenant quotas to cap denial of wallet; use admission control and autoscaling with a hard ceiling.
- Reject or down-rank worst-case-compute inputs and cache repeat requests.
- For chaff, deduplicate and cluster flagged events, rate-limit the alert pipeline per source, and gate HITL with source reputation so junk cannot exhaust reviewers.
- Route findings to the SIEM and re-validate that spend-rate and compute return to baseline after controls are applied.
