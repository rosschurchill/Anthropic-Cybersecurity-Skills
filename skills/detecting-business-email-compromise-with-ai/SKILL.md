---
name: detecting-business-email-compromise-with-ai
description: >-
  Deploys AI and NLP-powered detection to identify business email compromise by analyzing writing
  style, behavioral patterns, and contextual anomalies that evade rule-based filters. Use when
  building ML/NLP BEC detection, catching invoice-fraud or executive-impersonation emails that
  bypass signature rules, or scoring messages by stylometric and behavioral anomaly. Keywords:
  BEC, NLP, writing style, stylometry, behavioral anomaly, executive impersonation, invoice
  fraud, ML detection. Do not use for rule- and header-based BEC detection - use
  detecting-business-email-compromise.
domain: cybersecurity
subdomain: phishing-defense
tags:
- bec
- ai
- nlp
- machine-learning
- email-security
- behavioral-analytics
- impersonation
- fraud-detection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- GOVERN-6.2
- MAP-5.2
- GOVERN-6.1
- MEASURE-2.7
- MEASURE-2.5
d3fend_techniques:
- Sender MTA Reputation Analysis
- Email Filtering
- Sender Reputation Analysis
- Homoglyph Detection
- Message Analysis
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
mitre_attack:
- T1566.002
- T1534
- T1114.002
- T1657
- T1078.004
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - stealth
  - positioning
  - monetization
  techniques:
  - id: T1660
    name: Phishing
    tactic: initial-access
    source: attack
  - id: T1672
    name: Email Spoofing
    tactic: stealth
    source: attack
  - id: F1032
    name: Impersonate Official
    tactic: initial-access
    source: f3
  - id: F1005.006
    name: 'Account Manipulation: Change of Payment Details'
    tactic: positioning
    source: f3
  - id: F1022
    name: Delete Relevant Emails
    tactic: stealth
    source: f3
  - id: F1025.003
    name: 'Electronic Funds Transfer: Wire Transfer'
    tactic: monetization
    source: f3
---
# Detecting Business Email Compromise with AI

## Overview
AI-powered BEC detection uses machine learning, NLP, and behavioral analytics to identify sophisticated impersonation attacks that contain no malicious links or attachments. Traditional rule-based filters miss these attacks because BEC relies purely on social engineering. Modern AI approaches analyze writing style, tone, vocabulary, grammatical patterns, and behavioral context to determine if an email genuinely comes from the stated sender. BERT-based models achieve 98.65% accuracy in BEC detection, and AI-enhanced platforms show a 25% increase in phishing identification over keyword-based rules.


## When to Use

- Use when deploying an API-based AI email platform (Abnormal Security, Tessian, Ironscales) to catch BEC that bypasses signature rules
- Use when scoring messages by stylometry and writing-style deviation to flag executive impersonation
- Use when building NLP/transformer (BERT) models to detect urgency and manipulation language in payment requests
- Use when behavioral baselines must flag a sudden change in a compromised employee's sending patterns
- Use when tuning confidence thresholds for auto-quarantine vs. warning banner vs. analyst review

## Prerequisites
- AI-powered email security platform (Abnormal Security, Tessian, Microsoft Defender)
- Historical email data for baseline training (minimum 30 days)
- Integration with email platform (Microsoft 365 or Google Workspace)
- SIEM for alert correlation and investigation
- Understanding of BEC attack types (FBI IC3 classification)

## Workflow

### Step 1: Deploy AI Email Security Platform
- Select API-based solution (Abnormal Security, Tessian, Ironscales) or enhance existing SEG
- Connect to Microsoft Graph API or Google Workspace API
- Allow 48-hour baseline learning period on historical email data
- Configure integration to scan inbound, outbound, and internal email
- Verify API permissions for message access and remediation

### Step 2: Configure Behavioral Baselines
- AI learns normal communication patterns: who emails whom, frequency, tone
- Establish writing style profiles for each user (vocabulary, sentence structure)
- Map typical request types per role (finance processes payments, HR handles PII)
- Baseline email metadata: typical sending times, devices, locations
- Flag deviations from established baselines as anomalous

### Step 3: Train NLP Models for BEC Detection
- Deploy transformer-based models (BERT, GPT) for email content analysis
- Detect urgency and manipulation language patterns
- Identify mismatches between sender identity and writing style
- Analyze sentiment shifts indicating social engineering pressure
- Classify email intent: information request, payment request, credential request

### Step 4: Configure Detection Policies
- VIP impersonation: AI compares new email against known executive communication patterns
- Vendor impersonation: detect payment change requests from vendor lookalike domains
- Account compromise: detect sudden changes in employee email behavior
- Supply chain BEC: monitor for impersonation of trusted partners
- Configure confidence thresholds for auto-block vs. warning banner vs. analyst review

### Step 5: Integrate with Response Workflow
- Auto-quarantine high-confidence BEC detections
- Add warning banners for moderate-confidence detections
- Route suspicious emails to SOC analyst queue for review
- Integrate with SOAR for automated response playbooks
- Feed BEC verdicts back into training data for model improvement

## Example

Stylometric anomaly scoring (Step 3): compare a new message against a sender's historical writing profile to catch executive-impersonation BEC that carries no malicious link or attachment.

```python
# Max per-feature z-score of a message's writing style vs. the sender's baseline.
import numpy as np

def style_features(text: str) -> np.ndarray:
    words = text.split()
    sents = [s for s in text.replace("!", ".").replace("?", ".").split(".") if s.strip()]
    avg_word_len = np.mean([len(w) for w in words]) if words else 0.0
    avg_sent_len = np.mean([len(s.split()) for s in sents]) if sents else 0.0
    type_token = len(set(w.lower() for w in words)) / len(words) if words else 0.0
    exclaim = text.count("!") / max(len(words), 1)
    return np.array([avg_word_len, avg_sent_len, type_token, exclaim])

def anomaly_score(new_msg: str, baseline_msgs: list) -> float:
    base = np.vstack([style_features(m) for m in baseline_msgs])
    mu, sigma = base.mean(axis=0), base.std(axis=0) + 1e-6
    z = np.abs((style_features(new_msg) - mu) / sigma)
    return float(z.max())  # > 3 => route to analyst review as possible impersonation
```

## Tools & Resources
- **Abnormal Security**: API-based AI email security with behavioral analysis
- **Microsoft Defender for O365**: Built-in AI anti-BEC with Impostor Classifier
- **Tessian (Proofpoint)**: AI-powered email security with human layer protection
- **Ironscales**: AI + human-in-the-loop BEC detection
- **Darktrace Email**: Self-learning AI for email threat detection

## Validation
- AI detects test BEC email with no malicious indicators (pure social engineering)
- Writing style analysis identifies impersonation of known executive
- Behavioral baseline flags unusual payment request from compromised account
- NLP correctly classifies urgency manipulation in test scenario
- False positive rate below 0.05% after baseline training
- Detection rate exceeds traditional rule-based filters by 25%+
