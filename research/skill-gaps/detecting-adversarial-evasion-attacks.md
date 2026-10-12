# Detecting Adversarial Evasion Attacks — research notes

- **Proposed slug:** detecting-adversarial-evasion-attacks
- **ATLAS:** AML.T0015 Evade AI Model — plus folded-in AML.T0043 Craft Adversarial Data
  (sub-techniques White-Box Optimization, Black-Box Optimization, Black-Box Transfer,
  Manual Modification, Insert Backdoor Trigger — sub-technique numbering to **verify**)
- **Status:** research (not yet a skill)

## Defensive goal
Detect inference-time evasion: inputs perturbed by an attacker so a deployed AI model
misclassifies or fails to detect them (adversarial examples), while a human still reads the
input as benign. Scope is the serving/inference path — image/malware/network classifiers,
content-moderation and fraud models — distinguishing a crafted adversarial query from
organic misclassification. Catch both the attack *process* (iterative query probing to
craft a black-box example) and the *artifact* (a single transferred/manual adversarial input).

## Data sources / telemetry
- **Inference-API gateway logs** — per-principal query rate and burst shape, input
  size/entropy, and sequences of near-duplicate inputs with tiny pixel/byte deltas (the
  signature of black-box optimization probing a decision boundary).
- **Model-serving outputs** — per-request softmax/confidence vector, predicted class, and
  margin between top-1 and top-2. Logged via the serving layer (TorchServe/Triton/KServe)
  and captured by MLOps observability (Arize, WhyLabs, Fiddler, Langfuse for LLM I/O).
- **Adversarial-robustness detectors** — IBM ART detectors run inline or on sampled traffic:
  activation-based / Fast Generalized Subset Scan, and binary-input detectors trained on
  known adversarial sets.
- **OOD / confidence-anomaly telemetry** — out-of-distribution scores (Mahalanobis distance
  in feature space, energy/ODIN scores, max-softmax), prediction-entropy, and
  embedding-drift metrics from the observability platform.

## Detection logic / approach
Two complementary detector families:

1. **Query-pattern (black-box crafting) detection** — many near-identical queries from one
   principal with small perturbations and oscillating/decreasing decision margin indicates a
   boundary-probing attack (HopSkipJump/Boundary/ZOO style):
   ```
   # pseudo-rule
   group queries by principal, 10m window
   if count(pairwise_input_distance < epsilon) > N
      and predicted_class flips across near-duplicates
      and mean(top1_minus_top2_margin) decreasing
   -> alert: adversarial query crafting (AML.T0043 Black-Box Optimization)
   ```
2. **Single-input adversarial detection** — score each input at inference with an ART
   detector + OOD/confidence anomaly; flag inputs with low OOD score but anomalously
   low/odd confidence, or disagreement between the production model and a hardened reference
   model (ensemble/feature-squeezing comparison):
   ```
   if abs(pred_model - pred_squeezed) > tau   # feature-squeezing disagreement
      or ood_score anomalous
   -> flag likely adversarial example
   ```

Key discriminator vs siblings: this is **inference-time** input perturbation to flip a
prediction, not training-data tampering (poisoning) and not many queries aimed at copying the
model (extraction). Transfer attacks (AML.T0043 Black-Box Transfer) show as adversarial inputs
with *no* preceding probing — rely on the single-input detector.

## Response / mitigation
Rate-limit and step-up-auth probing principals; quarantine/replay suspected adversarial inputs
for triage. Harden the model: adversarial training, input preprocessing (JPEG compression,
feature squeezing, randomized smoothing), and gradient masking caveats noted. Reduce output
information leakage — return top-k labels without raw confidence to blunt boundary probing.
Deploy an ensemble or detector-gated serving path so flagged inputs route to a stricter model
or human review. Reference IBM ART for both robustness training and the detectors.

## Real tools
IBM Adversarial Robustness Toolbox (ART) — attack/detector/defense suite; CleverHans and
Foolbox (adversarial-example robustness evaluation, used defensively for red-teaming); Arize,
WhyLabs, Fiddler (ML observability / drift + confidence anomaly); Langfuse (LLM I/O); KServe /
Triton / TorchServe serving logs; cloud AI gateway logs.

## Draft frontmatter mappings
- atlas: [AML.T0015, AML.T0043]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, RS.MI-01, PR.PS-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-data-and-model-poisoning

## Draft description (<=1024 chars)
Detects inference-time adversarial evasion against deployed AI models — crafted adversarial
examples and boundary-probing query sequences that flip a classifier's prediction while the
input looks benign to a human. Uses inference-API gateway logs (per-principal query rate,
input entropy, near-duplicate deltas), model-serving confidence/margin telemetry, OOD and
confidence-anomaly scores, and IBM ART adversarial detectors plus feature-squeezing ensemble
disagreement. Covers white-box, black-box optimization, transfer, and manual modification.
Use when a classifier, malware/network/fraud model or content filter is being fooled by
perturbed inputs, or when building adversarial-input detection. Keywords: adversarial example,
evasion, AML.T0015, AML.T0043, IBM ART, feature squeezing, OOD, HopSkipJump, boundary attack,
confidence anomaly. Do not use for training-time data tampering - use
detecting-data-and-model-poisoning.

## Key references
- MITRE ATLAS AML.T0015 Evade AI Model; AML.T0043 Craft Adversarial Data: https://atlas.mitre.org/
- ATLAS case studies (verify IDs): AML.CS0000 evasion of deep-learning malware C2 detector;
  AML.CS0001 DGA detection evasion; AML.CS0014 confusing antimalware neural networks
- IBM Adversarial Robustness Toolbox: https://github.com/Trusted-AI/adversarial-robustness-toolbox
- NIST AI 100-2 Adversarial ML taxonomy (evasion): https://csrc.nist.gov/
- OWASP ML Security Top 10 — ML01 Input Manipulation / adversarial attacks: https://owasp.org/
- Goodfellow et al., "Explaining and Harnessing Adversarial Examples" (FGSM, 2015)

## Open questions / scope boundaries
- Confirm ATLAS sub-technique IDs/names under AML.T0043 (White/Black-box, Transfer, Manual,
  Insert Backdoor Trigger) — **verify** against the live ATLAS page.
- Inline ART detection adds inference latency; ship sampling/async-scoring guidance, not a
  fixed inline mandate. Thresholds (epsilon, tau, OOD cutoffs) are per-model — ship a method.
- Backdoor-trigger inputs blur toward poisoning (trigger planted at train time); keep this
  skill to the *inference-side* trigger-activation signal and cross-reference poisoning.
