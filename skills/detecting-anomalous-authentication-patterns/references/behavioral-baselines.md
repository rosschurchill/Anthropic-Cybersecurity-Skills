# Behavioral Baseline and Deviation Detection

```python
import numpy as np
from scipy import stats
from sklearn.ensemble import IsolationForest

def build_user_baseline(df, user, lookback_days=90):
    """Build behavioral baseline for a specific user."""
    user_events = df[df["user"] == user].copy()
    user_events["timestamp"] = pd.to_datetime(user_events["timestamp"])
    user_events["hour"] = user_events["timestamp"].dt.hour
    user_events["day_of_week"] = user_events["timestamp"].dt.dayofweek

    baseline = {
        "user": user,
        "typical_hours": {
            "start": int(user_events["hour"].quantile(0.05)),
            "end": int(user_events["hour"].quantile(0.95)),
            "mean": float(user_events["hour"].mean()),
            "std": float(user_events["hour"].std())
        },
        "typical_days": list(user_events["day_of_week"].mode().values),
        "typical_ips": list(user_events["source_ip"].value_counts().head(10).index),
        "typical_locations": list(
            user_events["location"].apply(
                lambda x: x.get("country") if isinstance(x, dict) else None
            ).dropna().value_counts().head(5).index
        ),
        "typical_apps": list(user_events["app"].value_counts().head(10).index),
        "typical_devices": list(user_events["device"].value_counts().head(5).index),
        "avg_daily_logins": float(
            user_events.groupby(user_events["timestamp"].dt.date).size().mean()
        ),
        "std_daily_logins": float(
            user_events.groupby(user_events["timestamp"].dt.date).size().std()
        ),
        "failure_rate": float(
            (user_events["result"] == "failure").mean()
        )
    }

    return baseline

def detect_behavioral_anomalies(event, baseline):
    """Compare a new authentication event against user baseline."""
    anomalies = []
    event_time = pd.Timestamp(event["timestamp"])

    # Off-hours login detection
    hour = event_time.hour
    if baseline["typical_hours"]["std"] > 0:
        z_score = abs(hour - baseline["typical_hours"]["mean"]) / baseline["typical_hours"]["std"]
        if z_score > 2.5:
            anomalies.append({
                "type": "OFF_HOURS_LOGIN",
                "severity": "MEDIUM",
                "detail": f"Login at {hour}:00 (baseline: {baseline['typical_hours']['start']}:00-{baseline['typical_hours']['end']}:00)",
                "z_score": round(z_score, 2)
            })

    # New source IP
    if event["source_ip"] not in baseline["typical_ips"]:
        anomalies.append({
            "type": "NEW_SOURCE_IP",
            "severity": "MEDIUM",
            "detail": f"Login from unknown IP: {event['source_ip']}"
        })

    # New country
    if event.get("location") and isinstance(event["location"], dict):
        country = event["location"].get("country")
        if country and country not in baseline["typical_locations"]:
            anomalies.append({
                "type": "NEW_COUNTRY",
                "severity": "HIGH",
                "detail": f"Login from new country: {country}"
            })

    # New application
    if event.get("app") and event["app"] not in baseline["typical_apps"]:
        anomalies.append({
            "type": "NEW_APPLICATION",
            "severity": "LOW",
            "detail": f"Access to new application: {event['app']}"
        })

    # New device
    if event.get("device") and event["device"] not in baseline["typical_devices"]:
        anomalies.append({
            "type": "NEW_DEVICE",
            "severity": "MEDIUM",
            "detail": f"Login from new device: {event['device']}"
        })

    # Weekend login for weekday-only users
    if event_time.dayofweek >= 5 and 5 not in baseline["typical_days"] and 6 not in baseline["typical_days"]:
        anomalies.append({
            "type": "WEEKEND_LOGIN",
            "severity": "LOW",
            "detail": f"Weekend login detected (typical days: {baseline['typical_days']})"
        })

    return anomalies

def isolation_forest_anomaly_detection(df):
    """Use Isolation Forest for multivariate anomaly detection."""
    # Feature engineering
    features_df = df.copy()
    features_df["timestamp"] = pd.to_datetime(features_df["timestamp"])
    features_df["hour"] = features_df["timestamp"].dt.hour
    features_df["day_of_week"] = features_df["timestamp"].dt.dayofweek
    features_df["is_failure"] = (features_df["result"] == "failure").astype(int)

    # Encode categorical features
    features_df["ip_frequency"] = features_df.groupby("source_ip")["source_ip"].transform("count")
    features_df["user_frequency"] = features_df.groupby("user")["user"].transform("count")

    feature_columns = ["hour", "day_of_week", "is_failure", "ip_frequency", "user_frequency"]
    X = features_df[feature_columns].fillna(0)

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,  # Expect 1% anomaly rate
        random_state=42,
        n_jobs=-1
    )
    features_df["anomaly_score"] = model.fit_predict(X)
    features_df["anomaly_probability"] = model.score_samples(X)

    # Extract anomalies (labeled as -1)
    anomalies = features_df[features_df["anomaly_score"] == -1]

    return anomalies.sort_values("anomaly_probability")
```
