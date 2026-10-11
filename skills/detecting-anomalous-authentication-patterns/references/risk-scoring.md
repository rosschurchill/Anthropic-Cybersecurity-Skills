# Authentication Risk Scoring

```python
def calculate_auth_risk_score(user, alerts, baseline):
    """
    Calculate composite risk score for authentication events.
    Combines multiple anomaly signals with weighted scoring.
    """
    score = 0
    risk_factors = []

    weights = {
        "IMPOSSIBLE_TRAVEL": 40,
        "PASSWORD_SPRAY": 35,
        "BRUTE_FORCE": 30,
        "CREDENTIAL_STUFFING": 35,
        "NEW_COUNTRY": 25,
        "OFF_HOURS_LOGIN": 15,
        "NEW_SOURCE_IP": 10,
        "NEW_DEVICE": 10,
        "NEW_APPLICATION": 5,
        "WEEKEND_LOGIN": 5,
        "MFA_BYPASS": 45,
        "LEGACY_PROTOCOL": 20
    }

    for alert in alerts:
        alert_type = alert.get("type") or alert.get("alert_type")
        weight = weights.get(alert_type, 10)

        # Adjust weight based on severity
        severity_multiplier = {
            "CRITICAL": 2.0,
            "HIGH": 1.5,
            "MEDIUM": 1.0,
            "LOW": 0.5
        }
        severity = alert.get("severity", "MEDIUM")
        adjusted_weight = weight * severity_multiplier.get(severity, 1.0)

        score += adjusted_weight
        risk_factors.append({
            "factor": alert_type,
            "weight": adjusted_weight,
            "detail": alert.get("detail", alert.get("details", ""))
        })

    # Normalize score to 0-100
    normalized_score = min(100, score)

    # Determine risk level
    if normalized_score >= 80:
        risk_level = "CRITICAL"
        recommended_action = "Immediate account suspension and investigation"
    elif normalized_score >= 60:
        risk_level = "HIGH"
        recommended_action = "Force MFA re-enrollment and notify SOC"
    elif normalized_score >= 40:
        risk_level = "MEDIUM"
        recommended_action = "Require step-up authentication"
    elif normalized_score >= 20:
        risk_level = "LOW"
        recommended_action = "Monitor and log for trend analysis"
    else:
        risk_level = "INFORMATIONAL"
        recommended_action = "No action required"

    return {
        "user": user,
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "risk_factors": sorted(risk_factors, key=lambda x: x["weight"], reverse=True),
        "timestamp": datetime.utcnow().isoformat()
    }
```
