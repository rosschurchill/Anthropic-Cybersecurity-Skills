# TXT Record Payload Detection

```python
#!/usr/bin/env python3
"""DNS TXT record payload detection for C2 command delivery."""

import base64
import re
import math
from collections import Counter


def shannon_entropy(data):
    """Calculate Shannon entropy."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def analyze_txt_record(txt_data, domain=""):
    """
    Analyze a DNS TXT record response for C2 payload indicators.

    Indicators:
      - High entropy content (encoded/encrypted payloads)
      - Base64-encoded executable content
      - PowerShell stager patterns
      - Unusually large TXT records (>255 bytes per string, multiple strings)
      - Known C2 framework patterns
    """
    findings = {
        "domain": domain,
        "txt_length": len(txt_data),
        "entropy": shannon_entropy(txt_data),
        "suspicious": False,
        "indicators": [],
        "decoded_preview": None,
    }

    # Length check - legitimate TXT records are typically short (SPF, DKIM, verification)
    if len(txt_data) > 500:
        findings["indicators"].append({
            "type": "oversized_txt",
            "detail": f"TXT record length {len(txt_data)} exceeds normal threshold (500)",
            "severity": "medium",
        })

    # High entropy - suggests encoded/encrypted payload
    if findings["entropy"] > 4.5 and len(txt_data) > 100:
        findings["indicators"].append({
            "type": "high_entropy_payload",
            "detail": f"Entropy {findings['entropy']:.3f} suggests encoded data",
            "severity": "high",
        })

    # Base64 detection
    b64_pattern = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')
    if b64_pattern.match(txt_data.strip()):
        findings["indicators"].append({
            "type": "base64_encoded",
            "detail": "Content matches base64 pattern",
            "severity": "high",
        })
        try:
            decoded = base64.b64decode(txt_data.strip())
            preview = decoded[:200]

            # Check for PE header (MZ)
            if preview[:2] == b'MZ':
                findings["indicators"].append({
                    "type": "pe_executable",
                    "detail": "Decoded base64 contains PE executable (MZ header)",
                    "severity": "critical",
                })

            # Check for ELF header
            if preview[:4] == b'\x7fELF':
                findings["indicators"].append({
                    "type": "elf_executable",
                    "detail": "Decoded base64 contains ELF executable",
                    "severity": "critical",
                })

            # Check for PowerShell patterns
            decoded_str = decoded.decode("utf-8", errors="ignore")
            ps_patterns = [
                r"Invoke-Expression",
                r"IEX\s*\(",
                r"New-Object\s+System\.Net",
                r"DownloadString",
                r"FromBase64String",
                r"Start-Process",
                r"\-enc\s",
                r"powershell\s.*\-e\s",
            ]
            for pattern in ps_patterns:
                if re.search(pattern, decoded_str, re.IGNORECASE):
                    findings["indicators"].append({
                        "type": "powershell_stager",
                        "detail": f"Decoded content contains PowerShell pattern: {pattern}",
                        "severity": "critical",
                    })
                    break

            findings["decoded_preview"] = repr(preview[:100])

        except Exception:
            pass

    # Known C2 TXT patterns
    cobalt_pattern = re.compile(r'^[a-f0-9]{32,}$', re.IGNORECASE)
    if cobalt_pattern.match(txt_data.strip()):
        findings["indicators"].append({
            "type": "hex_encoded_payload",
            "detail": "Pure hex string in TXT record - possible Cobalt Strike beacon config",
            "severity": "high",
        })

    # Multiple concatenated base64 blocks (common in staged delivery)
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', txt_data)
    if len(b64_blocks) > 3:
        findings["indicators"].append({
            "type": "multi_block_payload",
            "detail": f"{len(b64_blocks)} base64 blocks found - possible staged payload",
            "severity": "high",
        })

    # Check for known legitimate TXT patterns to reduce false positives
    legitimate_patterns = [
        r'^v=spf1\s',           # SPF record
        r'^v=DKIM1',            # DKIM record
        r'^v=DMARC1',           # DMARC record
        r'^google-site-verification=',
        r'^MS=',                # Microsoft domain verification
        r'^docusign=',
        r'^apple-domain-verification=',
        r'^facebook-domain-verification=',
        r'^_globalsign-domain-verification=',
    ]
    for pattern in legitimate_patterns:
        if re.match(pattern, txt_data, re.IGNORECASE):
            findings["indicators"] = []
            findings["legitimate"] = True
            return findings

    findings["suspicious"] = len(findings["indicators"]) > 0
    return findings


def analyze_txt_records_bulk(records):
    """Analyze a batch of DNS TXT records."""
    results = []
    for record in records:
        domain = record.get("domain", record.get("query", ""))
        txt_data = record.get("txt", record.get("answer", ""))
        if txt_data:
            finding = analyze_txt_record(txt_data, domain)
            if finding["suspicious"]:
                results.append(finding)

    results.sort(
        key=lambda x: max((i.get("severity_score", 0) for i in x["indicators"]),
                          default=0),
        reverse=True,
    )
    return results
```
