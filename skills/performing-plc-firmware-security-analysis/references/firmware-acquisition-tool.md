# PLC Firmware Acquisition and Integrity Verification

```python
#!/usr/bin/env python3
"""PLC Firmware Acquisition and Integrity Verification.

Supports firmware extraction from project files, network downloads,
and binary image comparison against known-good baselines.
"""

import hashlib
import json
import os
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path


class PLCFirmwareAcquisition:
    """Handles PLC firmware acquisition from various sources."""

    def __init__(self, output_dir="firmware_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.manifest = {
            "acquisition_date": datetime.now().isoformat(),
            "firmware_samples": [],
        }

    def extract_from_siemens_project(self, project_path):
        """Extract firmware/program blocks from Siemens TIA Portal project.

        TIA Portal projects (.ap16/.ap17) are ZIP archives containing
        XML-encoded PLC program blocks and system configuration.
        """
        print(f"[*] Analyzing Siemens project: {project_path}")
        results = {"platform": "Siemens", "blocks": []}

        if zipfile.is_zipfile(project_path):
            with zipfile.ZipFile(project_path, "r") as zf:
                for info in zf.infolist():
                    # Program blocks are stored as XML in specific paths
                    if "ProgramBlocks" in info.filename or "SystemBlocks" in info.filename:
                        block_data = zf.read(info.filename)
                        block_hash = hashlib.sha256(block_data).hexdigest()

                        block_path = self.output_dir / info.filename.replace("/", "_")
                        block_path.write_bytes(block_data)

                        results["blocks"].append({
                            "name": info.filename,
                            "size": info.file_size,
                            "sha256": block_hash,
                            "extracted_to": str(block_path),
                        })
                        print(f"  [+] Extracted: {info.filename} ({info.file_size} bytes)")

        self.manifest["firmware_samples"].append(results)
        return results

    def extract_from_rockwell_project(self, acd_path):
        """Extract program data from Rockwell Studio 5000 ACD file.

        ACD files contain controller program, tags, and configuration.
        """
        print(f"[*] Analyzing Rockwell project: {acd_path}")
        results = {"platform": "Rockwell/Allen-Bradley", "blocks": []}

        with open(acd_path, "rb") as f:
            header = f.read(256)
            # ACD files have a specific signature
            if b"RSLogix" in header or b"Studio 5000" in header:
                f.seek(0)
                full_data = f.read()
                file_hash = hashlib.sha256(full_data).hexdigest()

                results["blocks"].append({
                    "name": os.path.basename(acd_path),
                    "size": len(full_data),
                    "sha256": file_hash,
                    "header_signature": header[:16].hex(),
                })
                print(f"  [+] Project hash: {file_hash}")

        self.manifest["firmware_samples"].append(results)
        return results

    def compute_firmware_hash(self, firmware_path):
        """Compute multiple hashes of a firmware image for integrity tracking."""
        data = Path(firmware_path).read_bytes()
        return {
            "file": str(firmware_path),
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

    def compare_firmware_integrity(self, current_fw, baseline_fw):
        """Compare current firmware against known-good baseline."""
        current_hash = self.compute_firmware_hash(current_fw)
        baseline_hash = self.compute_firmware_hash(baseline_fw)

        match = current_hash["sha256"] == baseline_hash["sha256"]

        result = {
            "comparison_date": datetime.now().isoformat(),
            "current_firmware": current_hash,
            "baseline_firmware": baseline_hash,
            "integrity_match": match,
            "verdict": "PASS - Firmware matches baseline" if match else "FAIL - Firmware modified!",
        }

        if not match:
            # Find the offset where files diverge
            current_data = Path(current_fw).read_bytes()
            baseline_data = Path(baseline_fw).read_bytes()
            min_len = min(len(current_data), len(baseline_data))

            first_diff = None
            diff_count = 0
            for i in range(min_len):
                if current_data[i] != baseline_data[i]:
                    if first_diff is None:
                        first_diff = i
                    diff_count += 1

            result["first_difference_offset"] = f"0x{first_diff:08x}" if first_diff else None
            result["total_different_bytes"] = diff_count
            result["size_difference"] = len(current_data) - len(baseline_data)

        return result

    def save_manifest(self):
        """Save acquisition manifest."""
        manifest_path = self.output_dir / "acquisition_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(self.manifest, f, indent=2)
        print(f"\n[*] Manifest saved: {manifest_path}")


if __name__ == "__main__":
    acq = PLCFirmwareAcquisition()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python process.py extract-siemens <project.ap17>")
        print("  python process.py extract-rockwell <project.acd>")
        print("  python process.py compare <current.bin> <baseline.bin>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "extract-siemens" and len(sys.argv) > 2:
        acq.extract_from_siemens_project(sys.argv[2])
    elif cmd == "extract-rockwell" and len(sys.argv) > 2:
        acq.extract_from_rockwell_project(sys.argv[2])
    elif cmd == "compare" and len(sys.argv) > 3:
        result = acq.compare_firmware_integrity(sys.argv[2], sys.argv[3])
        print(json.dumps(result, indent=2))
    else:
        print("Invalid command")
        sys.exit(1)

    acq.save_manifest()
```
