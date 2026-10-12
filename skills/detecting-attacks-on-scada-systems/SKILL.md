---
name: detecting-attacks-on-scada-systems
description: >-
  Detects cyber attacks on SCADA systems including MITM on industrial protocols, unauthorized PLC
  command injection, HMI compromise, historian data manipulation, and control-communication DoS,
  using OT-specific IDS, industrial-protocol anomaly detection, and process-data analytics. Use
  when deploying OT detection in a SCADA environment, investigating a suspected ICS attack, or
  building rules for OT attack patterns like Stuxnet, TRITON, or Industroyer. Keywords: SCADA,
  OT, PLC, HMI, historian, Modbus, DNP3, Dragos, Nozomi, Claroty, ICS IDS. Do not use for
  Modbus-specific traffic anomaly monitoring alone - use
  monitoring-scada-modbus-traffic-anomalies.
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot-security
- ics
- scada
- industrial-control
- iec62443
- intrusion-detection
- threat-detection
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
- GV.OC-02
mitre_attack:
- T0846
- T0836
- T0831
- T0814
- T0832
---

# Detecting Attacks on SCADA Systems

## When to Use

- When deploying intrusion detection capabilities in a SCADA environment for the first time
- When investigating suspected cyber attacks against industrial control systems
- When building detection rules for OT-specific attack patterns (Stuxnet, TRITON, Industroyer)
- When integrating OT network monitoring with an enterprise SOC for unified threat visibility
- When responding to alerts from OT security monitoring tools (Dragos, Nozomi, Claroty)

**Do not use** for detecting attacks on IT-only networks without SCADA/ICS components, for building generic network IDS rules (see building-detection-rules-with-sigma), or for incident response procedures after an attack is confirmed (see performing-ot-incident-response).

## Prerequisites

- Passive network monitoring sensors deployed on SPAN/TAP ports at OT network boundaries
- OT intrusion detection system (Dragos Platform, Nozomi Guardian, Claroty xDome, or Suricata with OT rulesets)
- Understanding of industrial protocols in use (Modbus, DNP3, OPC UA, EtherNet/IP, S7comm)
- Baseline of normal SCADA communication patterns (polling intervals, function codes, register ranges)
- Access to process historian data for physical process anomaly correlation

## Workflow

### Step 1: Establish SCADA Communication Baselines

Before detecting anomalies, establish what normal SCADA traffic looks like. Industrial protocols are highly deterministic - the same master polls the same slaves at the same intervals reading the same registers.

```python
#!/usr/bin/env python3
"""SCADA Communication Baseline Builder.

Analyzes OT network traffic to establish deterministic baselines for
Modbus/TCP, DNP3, EtherNet/IP, and S7comm communications.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime
from statistics import mean, stdev

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)

MODBUS_FUNC_NAMES = {
    1: "Read Coils", 2: "Read Discrete Inputs",
    3: "Read Holding Registers", 4: "Read Input Registers",
    5: "Write Single Coil", 6: "Write Single Register",
    8: "Diagnostics", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 17: "Report Slave ID",
    22: "Mask Write Register", 23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface Transport",
}


class SCADABaselineBuilder:
    """Builds deterministic baselines from SCADA traffic captures."""

    def __init__(self):
        self.modbus_sessions = defaultdict(lambda: {
            "func_codes": defaultdict(int),
            "register_ranges": set(),
            "intervals": [],
            "last_seen": None,
            "request_count": 0,
        })
        self.communication_pairs = defaultdict(lambda: {
            "protocols": set(),
            "packet_count": 0,
            "first_seen": None,
            "last_seen": None,
        })

    def process_pcap(self, pcap_file):
        """Process pcap file to build SCADA baselines."""
        packets = rdpcap(pcap_file)
        print(f"[*] Processing {len(packets)} packets for baseline...")

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst
            ts = float(pkt.time)

            # Track communication pairs
            pair_key = f"{src}->{dst}"
            pair = self.communication_pairs[pair_key]
            pair["packet_count"] += 1
            if pair["first_seen"] is None:
                pair["first_seen"] = ts
            pair["last_seen"] = ts

            # Analyze Modbus/TCP
            if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
                self._analyze_modbus(pkt, src, dst, ts)

    def _analyze_modbus(self, pkt, src, dst, timestamp):
        """Extract Modbus function codes and register ranges."""
        payload = bytes(pkt[TCP].payload)
        if len(payload) < 8:
            return

        # MBAP header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1) + func_code(1)
        func_code = payload[7]
        session_key = f"{src}->{dst}"
        session = self.modbus_sessions[session_key]

        session["func_codes"][func_code] += 1
        session["request_count"] += 1
        session["protocols"] = {"Modbus/TCP"}

        # Track polling intervals
        if session["last_seen"] is not None:
            interval = timestamp - session["last_seen"]
            if 0.01 < interval < 60:  # Reasonable polling interval
                session["intervals"].append(interval)
        session["last_seen"] = timestamp

        # Extract register range for read/write operations
        if len(payload) >= 12 and func_code in (1, 2, 3, 4, 5, 6, 15, 16):
            start_register = (payload[8] << 8) | payload[9]
            if func_code in (1, 2, 3, 4, 15, 16) and len(payload) >= 12:
                count = (payload[10] << 8) | payload[11]
                session["register_ranges"].add((func_code, start_register, start_register + count))

    def generate_baseline(self):
        """Generate the baseline profile from collected data."""
        baseline = {
            "generated": datetime.now().isoformat(),
            "modbus_baselines": {},
            "communication_pairs": {},
        }

        for session_key, session in self.modbus_sessions.items():
            avg_interval = mean(session["intervals"]) if session["intervals"] else 0
            interval_std = stdev(session["intervals"]) if len(session["intervals"]) > 1 else 0

            baseline["modbus_baselines"][session_key] = {
                "allowed_function_codes": list(session["func_codes"].keys()),
                "function_code_distribution": {
                    MODBUS_FUNC_NAMES.get(k, f"FC{k}"): v
                    for k, v in session["func_codes"].items()
                },
                "polling_interval_avg_sec": round(avg_interval, 3),
                "polling_interval_stddev": round(interval_std, 3),
                "register_ranges": [
                    {"func_code": r[0], "start": r[1], "end": r[2]}
                    for r in session["register_ranges"]
                ],
                "total_requests": session["request_count"],
            }

        return baseline

    def export_baseline(self, output_file):
        """Export baseline to JSON file."""
        baseline = self.generate_baseline()
        with open(output_file, "w") as f:
            json.dump(baseline, f, indent=2)
        print(f"[*] Baseline saved to: {output_file}")

        # Print summary
        print(f"\n{'='*60}")
        print("SCADA COMMUNICATION BASELINE SUMMARY")
        print(f"{'='*60}")
        for session, data in baseline["modbus_baselines"].items():
            print(f"\n  Session: {session}")
            print(f"    Function Codes: {data['allowed_function_codes']}")
            print(f"    Polling Interval: {data['polling_interval_avg_sec']}s (+/- {data['polling_interval_stddev']}s)")
            print(f"    Register Ranges: {len(data['register_ranges'])}")
            print(f"    Total Requests: {data['total_requests']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scada_baseline.py <pcap_file> [output.json]")
        sys.exit(1)

    builder = SCADABaselineBuilder()
    builder.process_pcap(sys.argv[1])
    output = sys.argv[2] if len(sys.argv) > 2 else "scada_baseline.json"
    builder.export_baseline(output)
```

### Step 2: Deploy OT-Specific Detection Rules

Create detection rules for known SCADA attack patterns including those used by TRITON, Industroyer/CrashOverride, and PIPEDREAM/INCONTROLLER.

```yaml
# Suricata Rules for SCADA Attack Detection
# Deploy on IDS sensor monitoring OT network SPAN port

# --- Modbus Attack Detection ---

# Unauthorized Modbus write to PLC from non-engineering workstation
alert modbus any any -> $OT_PLC_SUBNET 502 (
  msg:"OT-DETECT Modbus write from unauthorized source";
  modbus_func:!read_coils; modbus_func:!read_discrete_inputs;
  modbus_func:!read_holding_registers; modbus_func:!read_input_registers;
  flow:to_server,established;
  threshold:type both, track by_src, count 1, seconds 60;
  classtype:attempted-admin;
  sid:3000001; rev:1;
)

# Modbus diagnostic/restart command (FC 8) - potential PLC DoS
alert modbus any any -> $OT_PLC_SUBNET 502 (
  msg:"OT-DETECT Modbus diagnostics command to PLC";
  modbus_func:diagnostics;
  flow:to_server,established;
  classtype:attempted-dos;
  sid:3000002; rev:1;
)

# Modbus broadcast write (unit ID 0) - affects all slaves
alert modbus any any -> $OT_PLC_SUBNET 502 (
  msg:"OT-CRITICAL Modbus broadcast write command";
  modbus_unit_id:0;
  flow:to_server,established;
  classtype:attempted-admin;
  sid:3000003; rev:1;
  priority:1;
)

# --- S7comm Attack Detection (Siemens) ---

# S7comm CPU STOP command - shuts down PLC execution
alert tcp any any -> $SIEMENS_PLC_SUBNET 102 (
  msg:"OT-CRITICAL S7comm CPU STOP command detected";
  content:"|03 00|"; offset:0; depth:2;
  content:"|29|"; offset:17; depth:1;
  flow:to_server,established;
  classtype:attempted-dos;
  sid:3000010; rev:1;
  priority:1;
)

# S7comm PLC program upload (potential logic modification)
alert tcp any any -> $SIEMENS_PLC_SUBNET 102 (
  msg:"OT-CRITICAL S7comm program download to PLC";
  content:"|03 00|"; offset:0; depth:2;
  content:"|1a|"; offset:17; depth:1;
  flow:to_server,established;
  classtype:attempted-admin;
  sid:3000011; rev:1;
  priority:1;
)

# --- DNP3 Attack Detection ---

# DNP3 cold restart command
alert tcp any any -> $OT_RTU_SUBNET 20000 (
  msg:"OT-CRITICAL DNP3 cold restart command";
  content:"|05 64|"; offset:0; depth:2;
  content:"|0d|"; offset:12; depth:1;
  flow:to_server,established;
  classtype:attempted-dos;
  sid:3000020; rev:1;
  priority:1;
)

# DNP3 firmware update command - potential PIPEDREAM indicator
alert tcp any any -> $OT_RTU_SUBNET 20000 (
  msg:"OT-CRITICAL DNP3 file transfer / firmware update";
  content:"|05 64|"; offset:0; depth:2;
  content:"|19|"; offset:12; depth:1;
  flow:to_server,established;
  classtype:attempted-admin;
  sid:3000021; rev:1;
  priority:1;
)

# --- Network Anomaly Detection ---

# New device communicating with PLCs (not in baseline)
alert ip !$AUTHORIZED_OT_HOSTS any -> $OT_PLC_SUBNET any (
  msg:"OT-DETECT Unauthorized device communicating with PLC subnet";
  flow:to_server;
  threshold:type limit, track by_src, count 1, seconds 3600;
  classtype:network-scan;
  sid:3000030; rev:1;
)

# Port scan targeting OT protocols
alert tcp any any -> $OT_NETWORK any (
  msg:"OT-DETECT Port scan targeting industrial protocols";
  flags:S;
  threshold:type threshold, track by_src, count 10, seconds 60;
  classtype:network-scan;
  sid:3000031; rev:1;
)
```

### Step 3: Implement Process Data Anomaly Detection

Monitor physical process data from the historian to detect attacks that manipulate the process while hiding their effects from operators (the Stuxnet attack pattern).

See [references/process-anomaly-detector.md](references/process-anomaly-detector.md) for the full historian-based process anomaly detector.

### Step 4: Detect Known ICS Malware Indicators

Monitor for indicators of compromise (IOCs) associated with known ICS-targeting malware families.

```yaml
# Known ICS Malware Detection Signatures
# Reference: MITRE ATT&CK for ICS, CISA ICS-CERT advisories

malware_families:
  TRITON_TRISIS:
    description: "Targets Schneider Electric Triconex Safety Instrumented Systems"
    target: "Safety controllers (SIS)"
    network_indicators:
      - protocol: "TriStation"
        port: 1502
        pattern: "Unusual TriStation commands from non-engineering workstation"
      - protocol: "TCP"
        pattern: "Connection to Triconex controller from unauthorized IP"
    host_indicators:
      - "trilog.exe present on engineering workstation"
      - "inject.bin in System32 directory"
      - "imain.bin payload targeting Triconex firmware"
    detection_rule: |
      alert tcp !$SIS_ENGINEERING_WS any -> $SIS_CONTROLLERS 1502 (
        msg:"OT-CRITICAL Unauthorized TriStation connection to SIS";
        flow:to_server; sid:3000100; rev:1; priority:1;)

  INDUSTROYER_CRASHOVERRIDE:
    description: "Targets power grid SCADA via IEC 60870-5-101/104, IEC 61850, OPC DA"
    target: "Power grid substations and SCADA"
    network_indicators:
      - protocol: "IEC 60870-5-104"
        port: 2404
        pattern: "Rapid sequence of control commands outside normal polling"
      - protocol: "OPC DA"
        pattern: "Enumeration of OPC servers followed by write commands"
    host_indicators:
      - "haslo.exe (backdoor launcher)"
      - "61850.dll (IEC 61850 attack module)"
      - "OPC.dll (OPC DA attack module)"
      - "104.dll (IEC 104 attack module)"
    detection_rule: |
      alert tcp any any -> $SUBSTATION_RTU 2404 (
        msg:"OT-CRITICAL Rapid IEC 104 control commands - Industroyer pattern";
        flow:to_server,established;
        threshold:type threshold, track by_src, count 50, seconds 10;
        sid:3000110; rev:1; priority:1;)

  PIPEDREAM_INCONTROLLER:
    description: "Modular ICS attack framework targeting Schneider/OMRON PLCs and OPC UA"
    target: "Multiple PLC vendors (Schneider, OMRON) and OPC UA servers"
    network_indicators:
      - protocol: "CODESYS"
        port: 1217
        pattern: "CODESYS runtime exploitation attempts"
      - protocol: "OPC UA"
        port: 4840
        pattern: "OPC UA server enumeration and unauthorized method calls"
      - protocol: "Modbus"
        port: 502
        pattern: "Rapid Modbus write commands to multiple unit IDs"
    host_indicators:
      - "TAGRUN tool for OPC UA scanning"
      - "CODECALL tool for CODESYS exploitation"
      - "OMSHELL tool for OMRON PLC interaction"
    detection_rule: |
      alert tcp any any -> $OT_NETWORK 1217 (
        msg:"OT-CRITICAL CODESYS runtime connection - PIPEDREAM indicator";
        flow:to_server,established;
        sid:3000120; rev:1; priority:1;)
```

## Key Concepts, Tools, Scenarios, and Output Format

See [references/reference-and-scenarios.md](references/reference-and-scenarios.md) for the Key Concepts glossary, Tools & Systems, Common Scenarios, and the full Output Format example.