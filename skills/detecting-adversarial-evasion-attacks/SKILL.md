---
name: detecting-adversarial-evasion-attacks
description: 'Detects inference-time adversarial evasion against deployed AI models: crafted adversarial examples and boundary-probing query sequences that flip a classifier prediction while the input still reads as benign to a human. Uses inference-API gateway logs (per-principal query rate, input entropy, near-duplicate deltas), model-serving confidence and top-1-minus-top-2 margin telemetry, out-of-distribution and confidence-anomaly scores, and IBM ART adversarial detectors plus feature-squeezing ensemble disagreement. Covers white-box, black-box optimization, transfer, and manual modification. Use when a classifier, a malware, network or fraud model, or a content filter is being fooled by perturbed inputs, or when building adversarial-input detection. Keywords: adversarial example, evasion, AML.T0015, AML.T0043, IBM ART, feature squeezing, OOD, HopSkipJump, boundary attack, confidence anomaly, OWASP ML01. Do not use for training-time data tampering or model poisoning - use detecting-data-and-model-poisoning.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- adversarial-evasion
- adversarial-example
- inference-time
- adversarial-robustness-toolbox
- feature-squeezing
- ood-detection
- model-serving
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0015
- AML.T0043
---
# Detecting Adversarial Evasion Attacks

> **Authorized use only:** The detectors and reference attacks here are for defenders hardening their own models and for red teams operating under written authorization. This skill is detection-and-response focused; it does not ship working adversarial-example generators.

## Overview

Adversarial evasion is an **inference-time** attack: an adversary perturbs an input just enough that a deployed model misclassifies or fails to detect it, while a human still reads the input as benign. MITRE ATLAS catalogs the goal as **AML.T0015 (Evade AI Model)** and the input crafting as **AML.T0043 (Craft Adversarial Data)**, which spans white-box optimization, black-box optimization, black-box transfer, and manual modification.

The key discriminator versus the sibling poisoning skill: evasion tampers with the *serving/inference path* to flip one prediction, not with the *training data or weights*. This skill targets image, malware, network-traffic and fraud classifiers and content-moderation filters, and it catches two things — the attack **process** (iterative query probing to craft a black-box example) and the **artifact** (a single transferred or manually crafted adversarial input). It maps to OWASP Machine Learning Security Top 10 ML01 (Input Manipulation) and the evasion class in the NIST AI 100-2 adversarial ML taxonomy.

## When to Use

- A production classifier (image, malware, network, fraud, content moderation) is being fooled by inputs that look benign to a reviewer.
- You see sequences of near-identical queries from one principal with tiny input deltas and oscillating predictions.
- You are building an adversarial-input detection layer in front of a model-serving endpoint.
- You are running a pre-deployment red-team exercise to measure how easily your own model is evaded.
- You need to distinguish a crafted adversarial query from organic misclassification during an incident.

## Prerequisites

- Python 3.9+ environment.
- Access to inference-API gateway logs (per-principal query counts, timestamps, input size/entropy or input hashes) and model-serving outputs (per-request confidence vector, predicted class, top-1/top-2 margin).
- ML observability for drift and confidence anomalies (Arize, WhyLabs, or Fiddler; Langfuse for LLM I/O).
- For self-assessment red-teaming and inline detectors, install IBM Adversarial Robustness Toolbox (ART):
  ```bash
  pip install adversarial-robustness-toolbox numpy scikit-learn
  ```
- Authorization to test the target model.

## Workflow

### 1. Instrument the serving path
Log per request: principal, timestamp, an input fingerprint (hash) and input entropy, the predicted class, and the full confidence vector so you can compute the top-1-minus-top-2 margin. These fields feed both the query-pattern and single-input detectors below.

### 2. Detect boundary-probing query sequences (black-box crafting)
Black-box optimization attacks (HopSkipJump / Boundary / ZOO style) send many near-duplicate inputs whose predicted class flips while the decision margin shrinks. Group by principal in a short window and score that pattern.

```python
import itertools, numpy as np

def score_boundary_probing(events, eps=0.01, min_pairs=20):
    """events: list of {input_vec, pred_class, margin} for one principal in a window."""
    near_pairs = flips = 0
    for a, b in itertools.combinations(events, 2):
        if np.linalg.norm(a["input_vec"] - b["input_vec"]) < eps:   # eps: tune per feature space
            near_pairs += 1
            if a["pred_class"] != b["pred_class"]:
                flips += 1
    margins = [e["margin"] for e in events]
    margin_decreasing = len(margins) > 2 and np.polyfit(range(len(margins)), margins, 1)[0] < 0
    suspicious = near_pairs > min_pairs and flips > 0 and margin_decreasing
    return {"near_pairs": near_pairs, "class_flips": flips,
            "margin_decreasing": bool(margin_decreasing), "suspected_crafting": suspicious}
```

### 3. Detect single adversarial inputs (transfer / manual)
Transfer and manually crafted examples arrive with no preceding probing, so rely on per-input scoring. Combine two independent signals: feature-squeezing disagreement and an out-of-distribution / confidence anomaly.

```python
import numpy as np

def feature_squeeze_disagreement(model, x, squeezers, tau=0.3):
    """squeezers: list of callables (e.g. bit-depth reduction, median/spatial smoothing).
    Large prediction change under a benign transform is an adversarial-example signal
    (feature squeezing, Xu et al. 2017)."""
    base = model.predict_proba(x[None])[0]
    gaps = [np.abs(base - model.predict_proba(s(x)[None])[0]).sum() for s in squeezers]
    max_gap = float(max(gaps))
    return {"max_l1_gap": max_gap, "flagged": max_gap > tau}   # tau: calibrate on clean data
```

ART ships production detectors you can run inline or on sampled traffic instead of hand-rolling: `art.defences.detector.evasion.SubsetScanningDetector` (Fast Generalized Subset Scan on activations) and `art.defences.detector.evasion.BinaryInputDetector` (a detector model trained on known-clean vs known-adversarial sets). Wrap your model with the matching ART estimator (`PyTorchClassifier`, `TensorFlowV2Classifier`, `KerasClassifier`) and score traffic.

### 4. Corroborate with OOD and confidence anomaly
Compute an out-of-distribution score in feature space (Mahalanobis distance, energy/ODIN, or max-softmax) plus prediction entropy. An input with a *low* OOD score but *anomalously low or odd* confidence is a classic adversarial signature — it looks in-distribution yet the model is uneasy. Pull drift and confidence-anomaly series from your observability platform (Arize / WhyLabs / Fiddler).

### 5. Measure your own evadability (self red-team)
Under authorization, use ART and Foolbox / CleverHans to generate adversarial examples against your own model in an isolated environment, then confirm your detectors fire. Report the detection rate and the perturbation budget needed to evade, not the attack payloads.

### 6. Route, rate-limit, and harden
Flagged principals get step-up auth and rate limiting; flagged single inputs route to a stricter reference model or human review (detector-gated serving). Hardening (see Response) is validated by re-running step 5.

## Key Concepts

- **Evasion vs poisoning.** Evasion perturbs inputs at inference to flip one prediction; poisoning corrupts training data/weights. Backdoor-trigger inputs blur the line — keep the inference-side *trigger-activation* signal here and cross-reference detecting-data-and-model-poisoning for the train-time planting.
- **Decision margin.** The gap between the top-1 and top-2 class probabilities. Boundary attacks drive it toward zero across near-duplicate queries.
- **Feature squeezing.** Applying a benign, information-reducing transform (bit-depth reduction, smoothing) should barely change a clean prediction but sharply changes an adversarial one; disagreement above a calibrated threshold flags the input.
- **Transfer attack.** An example crafted against a surrogate model that evades the target with no probing of the target — detectable only per input, never by query pattern.
- **Gradient masking caveat.** Defenses that merely hide gradients give false robustness; prefer adversarial training and detector-gated serving over obfuscation.

## Tools & Systems

| Tool / system | Role |
|---------------|------|
| IBM Adversarial Robustness Toolbox (ART) | Evasion detectors (SubsetScanning, BinaryInput), robustness training, red-team attacks |
| Foolbox, CleverHans | Adversarial-example robustness evaluation (defensive red-teaming) |
| Arize, WhyLabs, Fiddler | ML observability: drift, OOD and confidence-anomaly telemetry |
| Langfuse | LLM input/output tracing |
| KServe / Triton / TorchServe | Model-serving logs (confidence vectors, latency) |
| Cloud AI-gateway logs | Per-principal request and input telemetry |

## Detection Queries

KQL-style (adapt field names to your gateway/observability schema; verify and tune thresholds):

```kusto
// Near-duplicate boundary-probing bursts per principal
InferenceLogs
| where Timestamp > ago(10m)
| summarize queries=count(), distinct_classes=dcount(PredictedClass),
            avg_margin=avg(Top1Prob - Top2Prob) by Principal
| where queries > 200 and distinct_classes > 1 and avg_margin < 0.05
| order by queries desc
```

```kusto
// Single inputs flagged by feature-squeezing disagreement or OOD anomaly
InferenceLogs
| where SqueezeL1Gap > 0.3 or (OODScore < OODFloor and PredictionEntropy > EntropyHigh)
| project Timestamp, Principal, InputHash, PredictedClass, Top1Prob, SqueezeL1Gap, OODScore
```

## Common Scenarios

- **Malware classifier evasion:** a sample is minimally mutated until the model scores it benign; feature-squeezing disagreement and byte-level near-duplicate bursts fire.
- **Content-filter bypass:** perturbed image/text slips past moderation while reading as policy-violating to a human reviewer; OOD-low/confidence-odd signal flags it.
- **Fraud-model evasion:** a transaction is nudged across the decision boundary with no probing — caught per input by the reference-model disagreement, not by query pattern.
- **Boundary probing against a public API:** oscillating predictions over thousands of near-identical queries from one key trip the step-2 detector.

## Output Format

Report per finding:
- Finding type: query-crafting (process) or adversarial-input (artifact).
- Principal / API key, time window, query volume, near-duplicate and class-flip counts, margin trend.
- Per-input signals: feature-squeeze L1 gap, OOD score, prediction entropy, reference-model disagreement.
- ATLAS mapping: AML.T0015 (Evade AI Model), AML.T0043 (Craft Adversarial Data).
- Confidence and recommended routing (block, step-up auth, human review).

## Response

- Rate-limit and apply step-up auth to probing principals; quarantine and replay suspected adversarial inputs for triage.
- Route flagged inputs to a stricter reference model or human review via detector-gated serving.
- Reduce output information leakage: return top-k labels without raw confidence to blunt boundary probing.
- Harden the model: adversarial training, input preprocessing (bit-depth reduction, smoothing, randomized smoothing), and ensemble/reference comparison. Avoid gradient-masking-only defenses.
- Wire detector findings into the SIEM with a playbook (throttle, revoke key, preserve evidence) and re-validate detection rate after each hardening change.
