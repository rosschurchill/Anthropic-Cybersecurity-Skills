# DGA Domain Classification with Machine Learning

```python
#!/usr/bin/env python3
"""
DGA domain classification using character-level feature extraction and ML.

Features extracted per domain:
  - Shannon entropy of the domain string
  - Domain length
  - Digit ratio, consonant ratio, vowel ratio
  - Longest consecutive consonant sequence
  - N-gram frequency deviation from English
  - Number of distinct characters
  - Presence of dictionary words
"""

import math
import re
import string
from collections import Counter

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# English language character bigram frequencies (normalized, top bigrams)
# Source: Peter Norvig's English letter frequency analysis
ENGLISH_BIGRAMS = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205,
    "an": 0.0199, "re": 0.0185, "on": 0.0176, "at": 0.0149,
    "en": 0.0145, "nd": 0.0135, "ti": 0.0134, "es": 0.0134,
    "or": 0.0128, "te": 0.0120, "of": 0.0117, "ed": 0.0117,
    "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
    "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095,
    "se": 0.0093, "ha": 0.0093, "as": 0.0087, "ou": 0.0087,
    "io": 0.0083, "le": 0.0083, "ve": 0.0083, "co": 0.0079,
    "me": 0.0079, "de": 0.0076, "hi": 0.0076, "ri": 0.0073,
    "ro": 0.0073, "ic": 0.0070, "ne": 0.0069, "ea": 0.0069,
}

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def extract_domain_features(domain):
    """Extract numerical features from a domain name for ML classification."""
    domain = domain.lower().strip(".")

    # Remove TLD for analysis (focus on SLD + subdomain)
    parts = domain.split(".")
    if len(parts) > 1:
        analysis_str = ".".join(parts[:-1])  # Drop TLD
    else:
        analysis_str = domain

    # Remove dots for character analysis
    flat = analysis_str.replace(".", "")
    length = len(flat)

    if length == 0:
        return None

    # 1. Shannon entropy
    entropy = 0.0
    counter = Counter(flat)
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    # 2. Character ratios
    digit_count = sum(1 for c in flat if c.isdigit())
    vowel_count = sum(1 for c in flat if c in VOWELS)
    consonant_count = sum(1 for c in flat if c in CONSONANTS)
    special_count = sum(1 for c in flat if c == '-')

    digit_ratio = digit_count / length
    vowel_ratio = vowel_count / length
    consonant_ratio = consonant_count / length

    # 3. Longest consecutive consonant run
    max_consonant_run = 0
    current_run = 0
    for c in flat:
        if c in CONSONANTS:
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0

    # 4. Distinct character count and ratio
    distinct_chars = len(set(flat))
    distinct_ratio = distinct_chars / length

    # 5. Bigram frequency deviation from English
    bigrams = [flat[i:i+2] for i in range(len(flat) - 1)]
    if bigrams:
        english_score = sum(
            ENGLISH_BIGRAMS.get(bg, 0) for bg in bigrams
        ) / len(bigrams)
    else:
        english_score = 0

    # 6. Number of labels (dots + 1)
    label_count = len(parts)

    # 7. Hex character ratio (common in DGA)
    hex_chars = set("0123456789abcdef")
    hex_ratio = sum(1 for c in flat if c in hex_chars) / length

    # 8. Digit-letter transitions (DGA domains mix digits and letters)
    transitions = 0
    for i in range(1, len(flat)):
        if (flat[i].isdigit() != flat[i-1].isdigit()):
            transitions += 1
    transition_ratio = transitions / max(length - 1, 1)

    # 9. Repeated character ratio
    if length > 1:
        repeats = sum(1 for i in range(1, len(flat)) if flat[i] == flat[i-1])
        repeat_ratio = repeats / (length - 1)
    else:
        repeat_ratio = 0

    return {
        "domain": domain,
        "length": length,
        "entropy": round(entropy, 4),
        "digit_ratio": round(digit_ratio, 4),
        "vowel_ratio": round(vowel_ratio, 4),
        "consonant_ratio": round(consonant_ratio, 4),
        "max_consonant_run": max_consonant_run,
        "distinct_chars": distinct_chars,
        "distinct_ratio": round(distinct_ratio, 4),
        "english_bigram_score": round(english_score, 6),
        "label_count": label_count,
        "hex_ratio": round(hex_ratio, 4),
        "transition_ratio": round(transition_ratio, 4),
        "repeat_ratio": round(repeat_ratio, 4),
        "special_count": special_count,
    }


FEATURE_COLUMNS = [
    "length", "entropy", "digit_ratio", "vowel_ratio", "consonant_ratio",
    "max_consonant_run", "distinct_chars", "distinct_ratio",
    "english_bigram_score", "label_count", "hex_ratio",
    "transition_ratio", "repeat_ratio", "special_count",
]


def features_to_vector(features):
    """Convert feature dict to numpy array."""
    return np.array([features[col] for col in FEATURE_COLUMNS])


def train_dga_classifier(legitimate_domains, dga_domains, model_type="random_forest"):
    """
    Train a DGA classifier on labeled domain lists.

    Args:
        legitimate_domains: list of known-good domain strings
        dga_domains: list of known DGA domain strings
        model_type: 'random_forest' or 'gradient_boosting'

    Returns:
        trained model, scaler, and evaluation metrics
    """
    if not HAS_SKLEARN:
        print("[ERROR] scikit-learn required: pip install scikit-learn")
        return None, None, None

    # Extract features
    X_legit = []
    X_dga = []

    for d in legitimate_domains:
        feats = extract_domain_features(d)
        if feats:
            X_legit.append(features_to_vector(feats))

    for d in dga_domains:
        feats = extract_domain_features(d)
        if feats:
            X_dga.append(features_to_vector(feats))

    if not X_legit or not X_dga:
        print("[ERROR] Insufficient feature data")
        return None, None, None

    X = np.vstack([np.array(X_legit), np.array(X_dga)])
    y = np.array([0] * len(X_legit) + [1] * len(X_dga))

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train model
    if model_type == "gradient_boosting":
        model = GradientBoostingClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            min_samples_split=10, random_state=42,
        )
    else:
        model = RandomForestClassifier(
            n_estimators=200, max_depth=15, min_samples_split=5,
            random_state=42, n_jobs=-1,
        )

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["legitimate", "dga"],
                                   output_dict=True)
    cm = confusion_matrix(y_test, y_pred)

    # Cross-validation
    cv_scores = cross_val_score(model, X_scaled, y, cv=5, scoring="f1")

    metrics = {
        "accuracy": report["accuracy"],
        "precision_dga": report["dga"]["precision"],
        "recall_dga": report["dga"]["recall"],
        "f1_dga": report["dga"]["f1-score"],
        "precision_legit": report["legitimate"]["precision"],
        "recall_legit": report["legitimate"]["recall"],
        "confusion_matrix": cm.tolist(),
        "cv_f1_mean": cv_scores.mean(),
        "cv_f1_std": cv_scores.std(),
        "feature_importance": dict(zip(
            FEATURE_COLUMNS,
            [round(float(x), 4) for x in model.feature_importances_]
        )),
    }

    print(f"[+] Model trained: {model_type}")
    print(f"    Accuracy:     {metrics['accuracy']:.4f}")
    print(f"    DGA F1:       {metrics['f1_dga']:.4f}")
    print(f"    DGA Recall:   {metrics['recall_dga']:.4f}")
    print(f"    CV F1 (5-fold): {metrics['cv_f1_mean']:.4f} +/- {metrics['cv_f1_std']:.4f}")
    print(f"    Top features: ", end="")
    top_feats = sorted(metrics["feature_importance"].items(), key=lambda x: x[1], reverse=True)[:5]
    print(", ".join(f"{k}={v:.3f}" for k, v in top_feats))

    return model, scaler, metrics


def classify_domains(domains, model, scaler):
    """Classify a list of domains as legitimate or DGA using a trained model."""
    results = []
    for domain in domains:
        feats = extract_domain_features(domain)
        if feats is None:
            continue

        vec = features_to_vector(feats).reshape(1, -1)
        vec_scaled = scaler.transform(vec)

        prediction = model.predict(vec_scaled)[0]
        probability = model.predict_proba(vec_scaled)[0]

        results.append({
            "domain": domain,
            "prediction": "dga" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)), 4),
            "dga_probability": round(float(probability[1]), 4),
            "features": feats,
        })

    return results
```
