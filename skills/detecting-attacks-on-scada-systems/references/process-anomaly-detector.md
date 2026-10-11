# Process Data Anomaly Detector

```python
#!/usr/bin/env python3
"""SCADA Process Data Anomaly Detector.

Monitors historian data to detect physical process anomalies
that may indicate cyber attacks manipulating control logic
while spoofing sensor readings (Stuxnet-style attacks).
"""

import json
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from statistics import mean, stdev
from typing import Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


@dataclass
class ProcessVariable:
    """Represents a monitored process variable."""
    tag_name: str
    description: str
    unit: str
    low_limit: float
    high_limit: float
    rate_of_change_limit: float  # Maximum change per second
    engineering_low: float
    engineering_high: float


@dataclass
class Anomaly:
    """Represents a detected process anomaly."""
    timestamp: str
    tag_name: str
    anomaly_type: str
    severity: str
    current_value: float
    expected_range: str
    description: str
    attack_pattern: str = ""


class ProcessAnomalyDetector:
    """Detects anomalies in SCADA process data from historian."""

    def __init__(self, historian_url, api_key=None):
        self.historian_url = historian_url
        self.api_key = api_key
        self.variables = {}
        self.history = defaultdict(lambda: deque(maxlen=1000))
        self.anomalies = []

    def add_variable(self, var: ProcessVariable):
        """Register a process variable to monitor."""
        self.variables[var.tag_name] = var

    def fetch_current_values(self):
        """Fetch current values from historian API."""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        tag_list = list(self.variables.keys())
        params = {"tags": ",".join(tag_list), "count": 1}

        try:
            resp = requests.get(
                f"{self.historian_url}/api/v1/streams/values/current",
                params=params,
                headers=headers,
                timeout=10,
                verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true",  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            print(f"[ERROR] Historian API error: {e}")
            return {}

    def check_value(self, tag_name, value, timestamp):
        """Check a process variable value against all detection rules."""
        var = self.variables.get(tag_name)
        if not var:
            return

        self.history[tag_name].append((timestamp, value))

        # Rule 1: Value out of engineering limits
        if value < var.engineering_low or value > var.engineering_high:
            self.anomalies.append(Anomaly(
                timestamp=timestamp,
                tag_name=tag_name,
                anomaly_type="OUT_OF_RANGE",
                severity="critical",
                current_value=value,
                expected_range=f"{var.engineering_low}-{var.engineering_high} {var.unit}",
                description=f"{tag_name} ({var.description}) at {value} {var.unit} - outside engineering limits",
                attack_pattern="Process manipulation - value driven outside safe operating range",
            ))

        # Rule 2: Rate of change exceeds physical limits
        history = list(self.history[tag_name])
        if len(history) >= 2:
            prev_ts, prev_val = history[-2]
            try:
                dt = (datetime.fromisoformat(timestamp) - datetime.fromisoformat(prev_ts)).total_seconds()
                if dt > 0:
                    rate = abs(value - prev_val) / dt
                    if rate > var.rate_of_change_limit:
                        self.anomalies.append(Anomaly(
                            timestamp=timestamp,
                            tag_name=tag_name,
                            anomaly_type="RATE_OF_CHANGE_VIOLATION",
                            severity="high",
                            current_value=value,
                            expected_range=f"Max rate: {var.rate_of_change_limit} {var.unit}/s",
                            description=(
                                f"{tag_name} changing at {rate:.2f} {var.unit}/s "
                                f"(limit: {var.rate_of_change_limit} {var.unit}/s)"
                            ),
                            attack_pattern="Possible sensor spoofing or actuator manipulation",
                        ))
            except (ValueError, TypeError):
                pass

        # Rule 3: Flatline detection (sensor reading not changing when process is active)
        if len(history) >= 20:
            recent_values = [v for _, v in list(history)[-20:]]
            if len(set(recent_values)) == 1:
                self.anomalies.append(Anomaly(
                    timestamp=timestamp,
                    tag_name=tag_name,
                    anomaly_type="FLATLINE_DETECTED",
                    severity="high",
                    current_value=value,
                    expected_range="Expected variation during active process",
                    description=f"{tag_name} flatlined at {value} for 20+ consecutive readings",
                    attack_pattern="Stuxnet-style replay attack - frozen sensor value while process is manipulated",
                ))

        # Rule 4: Statistical anomaly (z-score based)
        if len(history) >= 50:
            values = [v for _, v in list(history)[-50:]]
            avg = mean(values)
            std = stdev(values) if len(values) > 1 else 0
            if std > 0:
                z_score = abs(value - avg) / std
                if z_score > 3.5:
                    self.anomalies.append(Anomaly(
                        timestamp=timestamp,
                        tag_name=tag_name,
                        anomaly_type="STATISTICAL_ANOMALY",
                        severity="medium",
                        current_value=value,
                        expected_range=f"Mean: {avg:.2f}, StdDev: {std:.2f} (z={z_score:.1f})",
                        description=f"{tag_name} value {value} is {z_score:.1f} standard deviations from mean",
                        attack_pattern="Possible gradual process manipulation",
                    ))

    def report_anomalies(self):
        """Print detected anomalies."""
        if not self.anomalies:
            print("[*] No anomalies detected")
            return

        print(f"\n{'='*70}")
        print(f"PROCESS ANOMALY DETECTION REPORT - {len(self.anomalies)} anomalies")
        print(f"{'='*70}")

        for a in self.anomalies:
            print(f"\n  [{a.severity.upper()}] {a.anomaly_type}")
            print(f"    Time: {a.timestamp}")
            print(f"    Tag: {a.tag_name}")
            print(f"    Value: {a.current_value}")
            print(f"    Expected: {a.expected_range}")
            print(f"    Detail: {a.description}")
            if a.attack_pattern:
                print(f"    Attack Pattern: {a.attack_pattern}")


if __name__ == "__main__":
    from collections import defaultdict

    detector = ProcessAnomalyDetector(
        historian_url="https://10.30.1.50:5450",
    )

    # Define monitored process variables for a chemical reactor
    detector.add_variable(ProcessVariable(
        tag_name="REACTOR_01.TEMP",
        description="Reactor 1 Temperature",
        unit="C",
        low_limit=150, high_limit=280,
        rate_of_change_limit=5.0,
        engineering_low=100, engineering_high=350,
    ))
    detector.add_variable(ProcessVariable(
        tag_name="REACTOR_01.PRESSURE",
        description="Reactor 1 Pressure",
        unit="bar",
        low_limit=2.0, high_limit=8.0,
        rate_of_change_limit=0.5,
        engineering_low=0, engineering_high=12.0,
    ))
    detector.add_variable(ProcessVariable(
        tag_name="PUMP_03.FLOW",
        description="Feed Pump 3 Flow Rate",
        unit="m3/h",
        low_limit=5.0, high_limit=25.0,
        rate_of_change_limit=2.0,
        engineering_low=0, engineering_high=30.0,
    ))

    print("[*] Starting process anomaly monitoring...")
    print("[*] Press Ctrl+C to stop and generate report")

    try:
        while True:
            data = detector.fetch_current_values()
            for item in data.get("items", []):
                detector.check_value(
                    item.get("tag"),
                    item.get("value"),
                    item.get("timestamp", datetime.now().isoformat()),
                )
            time.sleep(5)
    except KeyboardInterrupt:
        detector.report_anomalies()
```
