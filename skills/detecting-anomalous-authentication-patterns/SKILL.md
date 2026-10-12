---
name: detecting-anomalous-authentication-patterns
description: >-
  Detects anomalous authentication using UEBA analytics, statistical baselines, and ML to
  identify impossible travel, credential stuffing, brute force, password spraying, and
  compromised-account behavior across authentication logs. Use when hunting compromised accounts
  in auth logs, implementing impossible-travel or password-spray detection, or baselining user
  login behavior for anomaly alerting. Keywords: UEBA, impossible travel, credential stuffing,
  password spray, brute force, authentication logs, sign-in anomaly. Do not use for broad
  user-behavior analytics beyond authentication events - use performing-user-behavior-analytics.
domain: cybersecurity
subdomain: identity-access-management
tags:
- UEBA
- authentication-anomaly
- impossible-travel
- brute-force
- credential-stuffing
- behavioral-analytics
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MEASURE-2.5
- MAP-5.1
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1110
- T1110.003
- T1110.004
- T1078
- T1021
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - positioning
  techniques:
  - id: T1110.004
    name: 'Brute Force:  Credential Stuffing'
    tactic: initial-access
    source: attack
  - id: T1110.003
    name: 'Brute Force: Password Spraying'
    tactic: initial-access
    source: attack
  - id: F1006
    name: Account Takeover
    tactic: initial-access
    source: f3
  - id: F1006.002
    name: 'Account Takeover: Exposed Login Credential'
    tactic: initial-access
    source: f3
  - id: T1539
    name: Steal Web Session Cookie
    tactic: positioning
    source: attack
---

# Detecting Anomalous Authentication Patterns

## When to Use

- Security operations needs to identify compromised accounts from authentication log analysis
- Implementing impossible travel detection to flag geographically inconsistent logins
- Detecting brute force, password spraying, and credential stuffing attacks in real time
- Building behavioral baselines for users to identify deviations indicating account compromise
- Correlating authentication anomalies with threat intelligence for lateral movement detection
- Investigating alerts from SIEM or IdP for suspicious sign-in activity

**Do not use** for static rule-based alerting on single failed logins; anomaly detection requires statistical baselines across time and entity dimensions to reduce false positives.

## Prerequisites

- Authentication log sources (Azure AD/Entra ID sign-in logs, Okta system logs, Active Directory event logs 4624/4625/4648/4768/4771)
- SIEM platform (Splunk, Microsoft Sentinel, Elastic SIEM) with at least 90 days of baseline data
- GeoIP database for location-based anomaly detection (MaxMind GeoLite2 or IP2Location)
- Python 3.9+ with pandas, scikit-learn, and scipy for custom analytics
- User identity context (department, role, typical work hours, location)

## Workflow

### Step 1: Collect and Normalize Authentication Logs

Aggregate authentication events from all identity sources:

```python
import pandas as pd
import json
from datetime import datetime, timedelta
from collections import defaultdict

# Parse authentication logs from multiple sources
def normalize_auth_logs(log_source, raw_logs):
    """Normalize authentication events to a common schema."""
    normalized = []

    for event in raw_logs:
        if log_source == "azure_ad":
            normalized.append({
                "timestamp": event["createdDateTime"],
                "user": event["userPrincipalName"],
                "source_ip": event["ipAddress"],
                "location": {
                    "city": event.get("location", {}).get("city"),
                    "state": event.get("location", {}).get("state"),
                    "country": event.get("location", {}).get("countryOrRegion"),
                    "lat": event.get("location", {}).get("geoCoordinates", {}).get("latitude"),
                    "lon": event.get("location", {}).get("geoCoordinates", {}).get("longitude")
                },
                "result": "success" if event["status"]["errorCode"] == 0 else "failure",
                "failure_reason": event["status"].get("failureReason", ""),
                "app": event.get("appDisplayName", "Unknown"),
                "device": event.get("deviceDetail", {}).get("operatingSystem", "Unknown"),
                "browser": event.get("deviceDetail", {}).get("browser", "Unknown"),
                "mfa_result": event.get("authenticationDetails", [{}])[0].get("succeeded", None),
                "risk_level": event.get("riskLevelDuringSignIn", "none"),
                "client_app": event.get("clientAppUsed", "Unknown"),
                "source": "azure_ad"
            })
        elif log_source == "okta":
            normalized.append({
                "timestamp": event["published"],
                "user": event["actor"]["alternateId"],
                "source_ip": event["client"]["ipAddress"],
                "location": {
                    "city": event["client"].get("geographicalContext", {}).get("city"),
                    "state": event["client"].get("geographicalContext", {}).get("state"),
                    "country": event["client"].get("geographicalContext", {}).get("country"),
                    "lat": event["client"].get("geographicalContext", {}).get("geolocation", {}).get("lat"),
                    "lon": event["client"].get("geographicalContext", {}).get("geolocation", {}).get("lon")
                },
                "result": "success" if event["outcome"]["result"] == "SUCCESS" else "failure",
                "failure_reason": event["outcome"].get("reason", ""),
                "app": event.get("target", [{}])[0].get("displayName", "Unknown"),
                "device": event["client"].get("device", "Unknown"),
                "browser": event["client"].get("userAgent", {}).get("browser", "Unknown"),
                "source": "okta"
            })
        elif log_source == "windows_ad":
            normalized.append({
                "timestamp": event["TimeCreated"],
                "user": event["TargetUserName"],
                "source_ip": event.get("IpAddress", ""),
                "location": None,  # Requires GeoIP enrichment
                "result": "success" if event["EventId"] in [4624, 4648] else "failure",
                "failure_reason": event.get("FailureReason", ""),
                "logon_type": event.get("LogonType", ""),
                "source": "windows_ad"
            })

    return pd.DataFrame(normalized)

# Enrich with GeoIP data for Windows AD logs missing location
import geoip2.database

def enrich_geoip(df, geoip_db_path="/opt/geoip/GeoLite2-City.mmdb"):
    """Add geolocation data to events missing location information."""
    reader = geoip2.database.Reader(geoip_db_path)

    for idx, row in df.iterrows():
        if row["location"] is None and row["source_ip"]:
            try:
                response = reader.city(row["source_ip"])
                df.at[idx, "location"] = {
                    "city": response.city.name,
                    "country": response.country.iso_code,
                    "lat": response.location.latitude,
                    "lon": response.location.longitude
                }
            except Exception:
                pass

    reader.close()
    return df
```

### Step 2: Detect Impossible Travel Anomalies

Identify logins from geographically impossible locations:

```python
from math import radians, sin, cos, sqrt, atan2
from datetime import datetime

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate great-circle distance between two points in km."""
    R = 6371  # Earth's radius in kilometers

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))

    return R * c

def detect_impossible_travel(df, max_speed_kmh=900):
    """
    Detect impossible travel events where a user authenticates from
    two locations faster than physically possible.

    max_speed_kmh: Maximum realistic travel speed (900 km/h ~= commercial flight)
    """
    alerts = []

    # Sort by user and timestamp
    df_sorted = df.sort_values(["user", "timestamp"])

    for user, user_events in df_sorted.groupby("user"):
        successful_events = user_events[user_events["result"] == "success"]

        for i in range(1, len(successful_events)):
            prev = successful_events.iloc[i-1]
            curr = successful_events.iloc[i]

            # Skip if location data is missing
            if not prev.get("location") or not curr.get("location"):
                continue
            if not prev["location"].get("lat") or not curr["location"].get("lat"):
                continue

            # Calculate distance and time delta
            distance_km = haversine_distance(
                prev["location"]["lat"], prev["location"]["lon"],
                curr["location"]["lat"], curr["location"]["lon"]
            )

            time_diff = (pd.Timestamp(curr["timestamp"]) -
                        pd.Timestamp(prev["timestamp"])).total_seconds() / 3600

            if time_diff <= 0:
                continue

            required_speed = distance_km / time_diff

            # Flag if required speed exceeds maximum realistic travel
            if required_speed > max_speed_kmh and distance_km > 100:
                alerts.append({
                    "alert_type": "IMPOSSIBLE_TRAVEL",
                    "severity": "HIGH",
                    "user": user,
                    "timestamp": curr["timestamp"],
                    "details": {
                        "location_1": f"{prev['location']['city']}, {prev['location']['country']}",
                        "location_2": f"{curr['location']['city']}, {curr['location']['country']}",
                        "time_1": prev["timestamp"],
                        "time_2": curr["timestamp"],
                        "distance_km": round(distance_km, 1),
                        "time_hours": round(time_diff, 2),
                        "required_speed_kmh": round(required_speed, 1),
                        "source_ip_1": prev["source_ip"],
                        "source_ip_2": curr["source_ip"]
                    }
                })

    return alerts

# Run impossible travel detection
travel_alerts = detect_impossible_travel(auth_df)
print(f"Impossible travel alerts: {len(travel_alerts)}")
for alert in travel_alerts:
    print(f"  [{alert['severity']}] {alert['user']}: "
          f"{alert['details']['location_1']} -> {alert['details']['location_2']} "
          f"({alert['details']['distance_km']} km in {alert['details']['time_hours']}h)")
```

### Step 3: Detect Brute Force and Password Spraying

Identify credential attack patterns across authentication logs:

```python
from collections import Counter

def detect_brute_force(df, threshold_failures=10, window_minutes=10):
    """
    Detect brute force attacks: many failed attempts against
    a single account in a short time window.
    """
    alerts = []
    failed = df[df["result"] == "failure"].copy()
    failed["timestamp"] = pd.to_datetime(failed["timestamp"])

    for user, user_fails in failed.groupby("user"):
        user_fails_sorted = user_fails.sort_values("timestamp")

        # Sliding window analysis
        for i, row in user_fails_sorted.iterrows():
            window_start = row["timestamp"]
            window_end = window_start + timedelta(minutes=window_minutes)

            window_events = user_fails_sorted[
                (user_fails_sorted["timestamp"] >= window_start) &
                (user_fails_sorted["timestamp"] <= window_end)
            ]

            if len(window_events) >= threshold_failures:
                source_ips = window_events["source_ip"].unique()
                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "user": user,
                    "timestamp": str(window_start),
                    "details": {
                        "failed_attempts": len(window_events),
                        "window_minutes": window_minutes,
                        "source_ips": list(source_ips),
                        "distributed": len(source_ips) > 1,
                        "failure_reasons": dict(Counter(window_events["failure_reason"]))
                    }
                })
                break  # One alert per user per detection pass

    return alerts

def detect_password_spray(df, threshold_users=10, window_minutes=30):
    """
    Detect password spraying: failed logins against many different
    accounts from the same source in a short window (1-2 attempts per user).
    """
    alerts = []
    failed = df[df["result"] == "failure"].copy()
    failed["timestamp"] = pd.to_datetime(failed["timestamp"])

    for source_ip, ip_events in failed.groupby("source_ip"):
        ip_events_sorted = ip_events.sort_values("timestamp")

        for i, row in ip_events_sorted.iterrows():
            window_start = row["timestamp"]
            window_end = window_start + timedelta(minutes=window_minutes)

            window_events = ip_events_sorted[
                (ip_events_sorted["timestamp"] >= window_start) &
                (ip_events_sorted["timestamp"] <= window_end)
            ]

            unique_users = window_events["user"].nunique()
            attempts_per_user = len(window_events) / unique_users if unique_users > 0 else 0

            # Password spray: many users targeted, few attempts per user
            if unique_users >= threshold_users and attempts_per_user <= 3:
                # Check if any succeeded (compromised account)
                success_after = df[
                    (df["source_ip"] == source_ip) &
                    (df["result"] == "success") &
                    (pd.to_datetime(df["timestamp"]) > window_start) &
                    (pd.to_datetime(df["timestamp"]) < window_end + timedelta(hours=1))
                ]

                alerts.append({
                    "alert_type": "PASSWORD_SPRAY",
                    "severity": "CRITICAL" if len(success_after) > 0 else "HIGH",
                    "timestamp": str(window_start),
                    "details": {
                        "source_ip": source_ip,
                        "targeted_users": unique_users,
                        "total_attempts": len(window_events),
                        "avg_attempts_per_user": round(attempts_per_user, 1),
                        "window_minutes": window_minutes,
                        "successful_logins_after": len(success_after),
                        "compromised_accounts": list(success_after["user"].unique()) if len(success_after) > 0 else []
                    }
                })
                break

    return alerts

# Run detections
brute_force_alerts = detect_brute_force(auth_df)
spray_alerts = detect_password_spray(auth_df)
print(f"Brute force alerts: {len(brute_force_alerts)}")
print(f"Password spray alerts: {len(spray_alerts)}")
```

### Step 4: Build Behavioral Baselines and Detect Deviations

Create user behavioral profiles and flag statistical anomalies:

See [references/behavioral-baselines.md](references/behavioral-baselines.md) for the full baseline-building, deviation-detection, and Isolation Forest code.

### Step 5: Implement SIEM Detection Rules

Deploy detection rules for common authentication attack patterns:

See [references/siem-detection-rules.md](references/siem-detection-rules.md) for the full Splunk SPL detection queries.

### Step 6: Correlate and Score Authentication Anomalies

Combine multiple detection signals into risk scores:

See [references/risk-scoring.md](references/risk-scoring.md) for the full composite risk-scoring implementation.

## Key Concepts, Tools, Scenarios, and Output Format

See [references/reference-and-scenarios.md](references/reference-and-scenarios.md) for the Key Concepts glossary, Tools & Systems, Common Scenarios, and the full Output Format example.