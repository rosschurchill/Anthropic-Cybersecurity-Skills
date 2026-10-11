# Shannon Entropy Analysis of DNS Queries

```python
#!/usr/bin/env python3
"""Shannon entropy analysis for DNS query subdomains."""

import math
import csv
import sys
from collections import Counter

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False


def shannon_entropy(data):
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return entropy


def extract_subdomain(fqdn):
    """Extract the subdomain portion from a fully qualified domain name."""
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(fqdn)
        if ext.subdomain:
            return ext.subdomain, f"{ext.domain}.{ext.suffix}"
        return "", f"{ext.domain}.{ext.suffix}"
    else:
        # Fallback: assume last two labels are domain + TLD
        parts = fqdn.rstrip(".").split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2]), ".".join(parts[-2:])
        return "", fqdn


def analyze_dns_entropy(queries, entropy_threshold=3.5, length_threshold=30):
    """
    Analyze DNS queries for tunneling indicators using entropy.

    Thresholds (tunable per environment):
      - entropy_threshold: Shannon entropy above this flags as suspicious (3.5-4.0 typical)
      - length_threshold: Subdomain length above this flags as suspicious (30-50 chars)

    Returns list of flagged queries with scores.
    """
    results = []

    for query_record in queries:
        fqdn = query_record.get("query", "").lower().rstrip(".")
        if not fqdn:
            continue

        subdomain, base_domain = extract_subdomain(fqdn)
        if not subdomain:
            continue

        # Remove dots from subdomain for entropy calculation
        subdomain_flat = subdomain.replace(".", "")
        if not subdomain_flat:
            continue

        entropy = shannon_entropy(subdomain_flat)
        length = len(subdomain_flat)
        label_count = subdomain.count(".") + 1

        # Scoring: higher = more suspicious
        score = 0.0
        flags = []

        if entropy > entropy_threshold:
            score += (entropy - entropy_threshold) * 25
            flags.append(f"high_entropy:{entropy:.2f}")

        if length > length_threshold:
            score += (length - length_threshold) * 0.5
            flags.append(f"long_subdomain:{length}")

        if label_count > 4:
            score += label_count * 2
            flags.append(f"many_labels:{label_count}")

        # Check for hex/base32/base64 encoding patterns
        hex_ratio = sum(1 for c in subdomain_flat if c in "0123456789abcdef") / max(len(subdomain_flat), 1)
        if hex_ratio > 0.85 and length > 20:
            score += 20
            flags.append("hex_encoded")

        b32_chars = set("abcdefghijklmnopqrstuvwxyz234567")
        b32_ratio = sum(1 for c in subdomain_flat if c in b32_chars) / max(len(subdomain_flat), 1)
        if b32_ratio > 0.95 and length > 20:
            score += 15
            flags.append("base32_encoded")

        # Only report if at least one flag triggered
        if flags:
            results.append({
                "fqdn": fqdn,
                "subdomain": subdomain,
                "base_domain": base_domain,
                "entropy": round(entropy, 4),
                "subdomain_length": length,
                "label_count": label_count,
                "score": round(score, 2),
                "flags": flags,
                "src_ip": query_record.get("src_ip", ""),
                "timestamp": query_record.get("timestamp", ""),
                "qtype": query_record.get("qtype", ""),
            })

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# Thresholds for known tunneling tools
TOOL_SIGNATURES = {
    "iodine": {
        "subdomain_pattern": r"^[a-z0-9]{50,}$",  # Long hex-like subdomains
        "common_qtypes": ["NULL", "TXT", "CNAME", "MX", "A"],
        "typical_entropy": (3.8, 4.2),
        "description": "Iodine DNS tunnel - IPv4 over DNS, uses NULL/TXT records",
    },
    "dnscat2": {
        "subdomain_pattern": r"^dnscat\.|^[a-f0-9]{16,}",
        "common_qtypes": ["TXT", "CNAME", "MX", "A"],
        "typical_entropy": (3.5, 4.5),
        "description": "dnscat2 encrypted C2 channel over DNS",
    },
    "dns2tcp": {
        "subdomain_pattern": r"^[a-z2-7]{20,}",  # Base32 encoding
        "common_qtypes": ["TXT", "KEY"],
        "typical_entropy": (3.6, 4.0),
        "description": "dns2tcp tunnel - TCP over DNS using TXT/KEY records",
    },
    "cobalt_strike_dns": {
        "subdomain_pattern": r"^[a-f0-9]{12,}\.",
        "common_qtypes": ["A", "AAAA", "TXT"],
        "typical_entropy": (3.2, 4.0),
        "description": "Cobalt Strike DNS beacon - encoded commands in A/TXT records",
    },
}


def print_entropy_report(results, top_n=25):
    """Print formatted entropy analysis report."""
    print("=" * 80)
    print("  DNS ENTROPY ANALYSIS - TUNNELING DETECTION")
    print("=" * 80)
    print(f"  Suspicious queries found: {len(results)}")
    print()

    if not results:
        print("  No suspicious queries detected.")
        return

    # Group by base domain
    domain_groups = {}
    for r in results:
        bd = r["base_domain"]
        if bd not in domain_groups:
            domain_groups[bd] = {"count": 0, "max_entropy": 0, "max_score": 0, "queries": []}
        domain_groups[bd]["count"] += 1
        domain_groups[bd]["max_entropy"] = max(domain_groups[bd]["max_entropy"], r["entropy"])
        domain_groups[bd]["max_score"] = max(domain_groups[bd]["max_score"], r["score"])
        domain_groups[bd]["queries"].append(r)

    # Sort domains by total suspicious query count
    sorted_domains = sorted(domain_groups.items(), key=lambda x: x[1]["count"], reverse=True)

    print("  TOP SUSPICIOUS BASE DOMAINS")
    print("  " + "-" * 76)
    print(f"  {'Domain':<35} {'Queries':>8} {'Max Ent':>8} {'Max Score':>10}")
    print("  " + "-" * 76)
    for domain, data in sorted_domains[:20]:
        print(f"  {domain:<35} {data['count']:>8} {data['max_entropy']:>8.3f} {data['max_score']:>10.1f}")
    print()

    print(f"  TOP {top_n} HIGHEST-SCORING QUERIES")
    print("  " + "-" * 76)
    for r in results[:top_n]:
        print(f"  Score: {r['score']:.1f}  Entropy: {r['entropy']:.3f}  Len: {r['subdomain_length']}")
        print(f"    FQDN:   {r['fqdn'][:75]}")
        print(f"    Flags:  {', '.join(r['flags'])}")
        print(f"    Source: {r['src_ip']}  Type: {r['qtype']}")
        print()
```
