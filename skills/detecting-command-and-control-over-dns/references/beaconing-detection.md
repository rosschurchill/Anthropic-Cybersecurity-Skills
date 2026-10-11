# DNS Beaconing Pattern Detection

```python
#!/usr/bin/env python3
"""DNS beaconing detection - identifies periodic C2 check-in patterns."""

import math
from collections import defaultdict
from datetime import datetime, timedelta

import numpy as np


def parse_timestamp(ts_str):
    """Parse various timestamp formats to datetime."""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue

    # Try epoch timestamp
    try:
        ts_float = float(ts_str)
        return datetime.utcfromtimestamp(ts_float)
    except (ValueError, OverflowError, OSError):
        pass

    return None


def detect_beaconing(dns_queries, min_queries=10, max_jitter_pct=25,
                     min_interval_sec=10, max_interval_sec=7200):
    """
    Detect DNS beaconing by analyzing inter-query timing intervals.

    Beaconing indicators:
      - Regular inter-query intervals (low standard deviation)
      - Consistent query sizes
      - Single source IP to single domain over extended period
      - Low jitter (variation in timing)

    Args:
        dns_queries: list of dicts with 'src_ip', 'query', 'timestamp'
        min_queries: minimum queries to analyze (default 10)
        max_jitter_pct: maximum coefficient of variation for beacon (default 25%)
        min_interval_sec: minimum beacon interval to detect (default 10s)
        max_interval_sec: maximum beacon interval to detect (default 7200s / 2hr)

    Returns:
        list of detected beacon patterns with confidence scores
    """
    # Group queries by (source IP, base domain)
    groups = defaultdict(list)

    for q in dns_queries:
        src_ip = q.get("src_ip", "")
        fqdn = q.get("query", "").lower().rstrip(".")
        ts_str = q.get("timestamp", "")

        ts = parse_timestamp(ts_str)
        if not ts or not src_ip or not fqdn:
            continue

        # Extract base domain (last 2 labels)
        parts = fqdn.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = fqdn

        groups[(src_ip, base_domain)].append(ts)

    beacons = []

    for (src_ip, base_domain), timestamps in groups.items():
        if len(timestamps) < min_queries:
            continue

        # Sort timestamps and compute intervals
        timestamps.sort()
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]

        if not intervals:
            continue

        intervals = np.array(intervals)

        # Filter out zero intervals (duplicate timestamps)
        intervals = intervals[intervals > 0]
        if len(intervals) < min_queries - 1:
            continue

        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        median_interval = np.median(intervals)

        # Skip if interval is outside detection range
        if mean_interval < min_interval_sec or mean_interval > max_interval_sec:
            continue

        # Coefficient of variation (jitter)
        cv = (std_interval / mean_interval * 100) if mean_interval > 0 else 100

        # Time span of activity
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        hours_active = time_span / 3600

        # Beacon scoring
        score = 0.0
        flags = []

        # Low jitter = strong beacon indicator
        if cv < 5:
            score += 40
            flags.append(f"very_low_jitter:CV={cv:.1f}%")
        elif cv < 15:
            score += 30
            flags.append(f"low_jitter:CV={cv:.1f}%")
        elif cv < max_jitter_pct:
            score += 15
            flags.append(f"moderate_jitter:CV={cv:.1f}%")
        else:
            continue  # Too much jitter, not a beacon

        # Long duration increases confidence
        if hours_active > 24:
            score += 20
            flags.append(f"persistent:{hours_active:.1f}h")
        elif hours_active > 4:
            score += 10
            flags.append(f"sustained:{hours_active:.1f}h")

        # High query count increases confidence
        if len(timestamps) > 100:
            score += 15
            flags.append(f"high_volume:{len(timestamps)}")
        elif len(timestamps) > 50:
            score += 10
            flags.append(f"moderate_volume:{len(timestamps)}")

        # Common C2 intervals (60s, 120s, 300s, 600s, 900s, 1800s, 3600s)
        common_intervals = [60, 120, 300, 600, 900, 1800, 3600]
        for ci in common_intervals:
            if abs(mean_interval - ci) < ci * 0.1:  # Within 10% of common interval
                score += 10
                flags.append(f"common_c2_interval:~{ci}s")
                break

        beacons.append({
            "src_ip": src_ip,
            "base_domain": base_domain,
            "query_count": len(timestamps),
            "mean_interval_sec": round(mean_interval, 2),
            "median_interval_sec": round(median_interval, 2),
            "std_interval_sec": round(std_interval, 2),
            "jitter_cv_pct": round(cv, 2),
            "first_seen": timestamps[0].isoformat(),
            "last_seen": timestamps[-1].isoformat(),
            "duration_hours": round(hours_active, 2),
            "score": round(score, 1),
            "flags": flags,
        })

    beacons.sort(key=lambda x: x["score"], reverse=True)
    return beacons


def print_beacon_report(beacons, top_n=20):
    """Print formatted beacon detection report."""
    print("=" * 80)
    print("  DNS BEACONING DETECTION REPORT")
    print("=" * 80)
    print(f"  Beacon patterns detected: {len(beacons)}")
    print()

    if not beacons:
        print("  No beaconing patterns detected.")
        return

    print(f"  TOP {min(top_n, len(beacons))} BEACON CANDIDATES")
    print("  " + "-" * 76)

    for b in beacons[:top_n]:
        print(f"  Score: {b['score']:.1f}  |  {b['src_ip']} -> {b['base_domain']}")
        print(f"    Queries: {b['query_count']}  "
              f"Interval: {b['mean_interval_sec']:.1f}s +/- {b['std_interval_sec']:.1f}s  "
              f"Jitter: {b['jitter_cv_pct']:.1f}%")
        print(f"    Active: {b['duration_hours']:.1f}h  "
              f"({b['first_seen']} to {b['last_seen']})")
        print(f"    Flags: {', '.join(b['flags'])}")
        print()
```
