---
name: performing-plc-firmware-security-analysis
description: >-
  Analyzes PLC firmware for integrity, backdoors, and vulnerabilities as part of an IEC
  62443-4-2 component security evaluation, performed on lab devices or offline backups rather
  than live controllers. Use when validating PLC firmware after a suspected compromise or
  supply-chain attack, vetting a new PLC platform before deployment, or researching ICS device
  firmware in an authorized lab. Do not use for live Siemens S7 protocol and PLC communication
  analysis — use performing-s7comm-protocol-security-analysis.
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot-security
- ics
- scada
- industrial-control
- iec62443
- firmware-analysis
- plc-security
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
- GV.OC-02
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
---

# Performing PLC Firmware Security Analysis

## When to Use

- When assessing PLC security as part of an IEC 62443 component security evaluation (IEC 62443-4-2)
- When validating firmware integrity after a suspected compromise or supply chain attack
- When evaluating the security of a new PLC platform before deployment in critical infrastructure
- When performing vulnerability research on industrial control system devices in an authorized lab
- When responding to an incident where PLC logic or firmware tampering is suspected

**Do not use** on live production PLCs without explicit authorization and safety controls in place. Firmware extraction and analysis should be performed on lab devices or offline backups. Never upload PLC firmware to public analysis services. See performing-ics-penetration-testing for authorized live testing procedures.

## Prerequisites

- Isolated lab environment with the target PLC hardware or an emulated environment
- PLC programming software for the target platform (Siemens TIA Portal, Rockwell Studio 5000, Schneider EcoStruxure)
- Firmware extraction tools (binwalk, firmware-mod-kit, JTAG/SWD debugger)
- Static analysis tools (Ghidra, IDA Pro, Binary Ninja with ARM/MIPS/PowerPC support)
- Understanding of PLC architecture (real-time OS, ladder logic execution, I/O scanning)
- Reference copy of known-good firmware for integrity comparison

## Workflow

### Step 1: Acquire PLC Firmware for Analysis

Extract or obtain PLC firmware through authorized methods. This can be done by downloading from the vendor, extracting from a lab device, or obtaining from a project backup.

See [references/firmware-acquisition-tool.md](references/firmware-acquisition-tool.md) for the full firmware acquisition and integrity verification tool (PLCFirmwareAcquisition).

### Step 2: Perform Static Analysis of Firmware Image

Use binwalk for firmware unpacking and Ghidra for disassembly to identify security issues in the firmware binary.

```bash
# Step 2a: Unpack firmware image with binwalk
binwalk -e firmware.bin
# Output: _firmware.bin.extracted/

# Identify firmware components
binwalk firmware.bin
# Look for: file system images, compressed sections, bootloader, RTOS kernel

# Extract strings for credential and configuration analysis
strings -n 8 firmware.bin > firmware_strings.txt

# Search for hardcoded credentials
grep -iE "(password|passwd|pwd|secret|key|credential|login|admin|root)" firmware_strings.txt

# Search for network configuration
grep -iE "(http|ftp|telnet|ssh|snmp|modbus|192\.168|10\.|172\.)" firmware_strings.txt

# Search for debug/backdoor indicators
grep -iE "(debug|backdoor|test_mode|factory|service_port|hidden)" firmware_strings.txt

# Search for cryptographic material
grep -iE "(BEGIN RSA|BEGIN CERTIFICATE|AES|DES|private.key)" firmware_strings.txt

# Step 2b: Entropy analysis to detect encrypted/compressed sections
binwalk -E firmware.bin
# High entropy sections may contain encrypted payloads or compressed data

# Step 2c: Analyze with Ghidra (headless mode)
analyzeHeadless /tmp/ghidra_project PLC_FW \
  -import firmware.bin \
  -processor ARM:LE:32:Cortex \
  -postScript FindCryptoConstants.java \
  -postScript FindHardcodedStrings.java \
  -log /tmp/ghidra_analysis.log
```

### Step 3: Analyze PLC Communication Stack Security

Examine how the PLC handles industrial protocol requests, focusing on authentication bypass, buffer overflows in packet parsing, and command injection vulnerabilities.

```python
#!/usr/bin/env python3
"""PLC Protocol Security Analyzer.

Tests PLC protocol implementation for common vulnerabilities
including authentication bypass, malformed packet handling,
and function code access control.

WARNING: Only run against lab/test PLCs, never production systems.
"""

import socket
import struct
import sys
import time
from dataclasses import dataclass


@dataclass
class ProtocolTestResult:
    test_name: str
    target: str
    protocol: str
    result: str  # PASS, FAIL, ERROR
    severity: str
    detail: str


class ModbusSecurityTester:
    """Tests Modbus/TCP implementation security."""

    def __init__(self, target_ip, target_port=502):
        self.target = target_ip
        self.port = target_port
        self.results = []

    def _send_modbus(self, unit_id, func_code, data=b""):
        """Send a Modbus/TCP request and return response."""
        # MBAP Header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
        mbap = struct.pack(">HHHB", 0x0001, 0x0000, len(data) + 2, unit_id)
        pdu = struct.pack("B", func_code) + data

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.send(mbap + pdu)
            response = sock.recv(1024)
            sock.close()
            return response
        except Exception as e:
            return None

    def test_authentication_required(self):
        """Test if PLC requires authentication for read/write operations."""
        # Test unauthenticated read
        read_data = struct.pack(">HH", 0, 10)  # Read 10 registers from address 0
        response = self._send_modbus(1, 3, read_data)

        if response and len(response) > 8 and response[7] != 0x83:
            self.results.append(ProtocolTestResult(
                test_name="Modbus Authentication - Read",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="high",
                detail="PLC accepts unauthenticated Modbus read commands. No authentication required.",
            ))

        # Test unauthenticated write
        write_data = struct.pack(">HH", 100, 0)  # Write 0 to register 100
        response = self._send_modbus(1, 6, write_data)

        if response and len(response) > 8 and response[7] != 0x86:
            self.results.append(ProtocolTestResult(
                test_name="Modbus Authentication - Write",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="critical",
                detail="PLC accepts unauthenticated Modbus WRITE commands. Any host can modify registers.",
            ))

    def test_function_code_access_control(self):
        """Test if PLC restricts dangerous function codes."""
        dangerous_funcs = {
            8: "Diagnostics (can restart communications)",
            17: "Report Slave ID (information disclosure)",
            43: "Encapsulated Interface Transport (device identification)",
        }

        for fc, desc in dangerous_funcs.items():
            response = self._send_modbus(1, fc, b"\x00\x00")
            if response and len(response) > 8:
                error_code = response[7]
                if error_code != (fc | 0x80):  # Not an exception response
                    self.results.append(ProtocolTestResult(
                        test_name=f"Function Code Access - FC{fc}",
                        target=self.target,
                        protocol="Modbus/TCP",
                        result="FAIL",
                        severity="medium",
                        detail=f"PLC responds to FC{fc} ({desc}) without access control",
                    ))

    def test_invalid_unit_id(self):
        """Test PLC response to broadcast and invalid unit IDs."""
        # Broadcast (unit ID 0) - should be carefully handled
        read_data = struct.pack(">HH", 0, 1)
        response = self._send_modbus(0, 3, read_data)

        if response and len(response) > 8 and response[7] != 0x83:
            self.results.append(ProtocolTestResult(
                test_name="Broadcast Unit ID Handling",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="high",
                detail="PLC responds to broadcast unit ID 0. This enables broadcast write attacks.",
            ))

    def test_malformed_packet_handling(self):
        """Test PLC resilience against malformed Modbus packets."""
        # Oversized length field
        malformed = struct.pack(">HHH", 0x0001, 0x0000, 0xFFFF) + b"\x01\x03\x00\x00\x00\x01"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.send(malformed)
            time.sleep(1)

            # Verify PLC is still responsive
            read_data = struct.pack(">HH", 0, 1)
            response = self._send_modbus(1, 3, read_data)
            sock.close()

            if response is None:
                self.results.append(ProtocolTestResult(
                    test_name="Malformed Packet - Oversized Length",
                    target=self.target,
                    protocol="Modbus/TCP",
                    result="FAIL",
                    severity="critical",
                    detail="PLC became unresponsive after receiving oversized length field. Possible DoS vulnerability.",
                ))
            else:
                self.results.append(ProtocolTestResult(
                    test_name="Malformed Packet - Oversized Length",
                    target=self.target,
                    protocol="Modbus/TCP",
                    result="PASS",
                    severity="info",
                    detail="PLC correctly handles oversized length field without crashing",
                ))
        except Exception as e:
            pass

    def run_all_tests(self):
        """Run all Modbus security tests."""
        print(f"\n{'='*60}")
        print(f"PLC MODBUS SECURITY ANALYSIS - {self.target}:{self.port}")
        print(f"{'='*60}")

        self.test_authentication_required()
        self.test_function_code_access_control()
        self.test_invalid_unit_id()
        self.test_malformed_packet_handling()

        for r in self.results:
            icon = "[FAIL]" if r.result == "FAIL" else "[PASS]"
            print(f"\n  {icon} {r.test_name}")
            print(f"    Severity: {r.severity}")
            print(f"    Detail: {r.detail}")

        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python plc_protocol_tester.py <target_plc_ip> [port]")
        print("WARNING: Only use against lab/test PLCs!")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502

    tester = ModbusSecurityTester(target, port)
    tester.run_all_tests()
```

## Key Concepts

| Term | Definition |
|------|------------|
| PLC Firmware | The embedded software running on a Programmable Logic Controller, including the real-time operating system, protocol stacks, and I/O drivers |
| Ladder Logic | Graphical programming language for PLCs that represents relay logic circuits, stored as program blocks in PLC memory |
| Function Block | Reusable PLC programming element that encapsulates logic with defined inputs/outputs, can be analyzed for malicious modifications |
| Firmware Integrity | Verification that PLC firmware has not been modified from the vendor-supplied or approved version using cryptographic hash comparison |
| IEC 62443-4-2 | Component security requirements in the IEC 62443 standard, defining security capabilities required for IACS components including PLCs |
| JTAG/SWD | Hardware debug interfaces (Joint Test Action Group / Serial Wire Debug) used for firmware extraction and low-level analysis |

## Tools & Systems

- **Binwalk**: Firmware analysis tool for scanning, extracting, and analyzing embedded firmware images
- **Ghidra**: NSA-developed reverse engineering framework supporting ARM, MIPS, PowerPC architectures common in PLCs
- **EMUX/FIRMADYNE**: Firmware emulation frameworks for dynamic analysis of embedded device firmware
- **PLCinject**: Research tool for analyzing PLC logic injection vulnerabilities (use only in authorized lab settings)
- **OpenPLC**: Open-source PLC platform useful as a test target for security research

## Output Format

```
PLC Firmware Security Analysis Report
=======================================
Device: [PLC Model and Firmware Version]
Analysis Date: YYYY-MM-DD
Methodology: Static + Dynamic Analysis

FIRMWARE INTEGRITY:
  SHA-256: [hash]
  Baseline Match: [Yes/No]
  Vendor Signature Valid: [Yes/No/Not Signed]

VULNERABILITIES FOUND:
  [PLC-001] [Severity] [Title]
    CWE: [CWE-ID]
    Detail: [Technical description]
    Impact: [Operational impact]
    Remediation: [Fix or mitigation]
```
