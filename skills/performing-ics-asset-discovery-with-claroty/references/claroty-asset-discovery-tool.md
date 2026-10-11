# Claroty xDome Asset Discovery Configuration and Reporting Tool

```python
#!/usr/bin/env python3
"""Claroty xDome Asset Discovery Configuration and Reporting Tool.

Automates the configuration of passive monitoring sensors and generates
asset inventory reports from Claroty xDome API.
"""

import json
import sys
import csv
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class ClarotyAssetDiscovery:
    """Interface with Claroty xDome API for ICS asset discovery."""

    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.session.verify = verify_ssl

    def get_sites(self):
        """Retrieve all monitored sites."""
        resp = self.session.get(f"{self.base_url}/api/v1/sites")
        resp.raise_for_status()
        return resp.json().get("sites", [])

    def get_assets(self, site_id: Optional[str] = None, asset_type: Optional[str] = None):
        """Retrieve discovered assets with optional filtering.

        asset_type: PLC, RTU, HMI, DCS, Engineering_Workstation,
                    Historian, Network_Device, IO_Module, Safety_Controller
        """
        params = {}
        if site_id:
            params["site_id"] = site_id
        if asset_type:
            params["type"] = asset_type

        resp = self.session.get(f"{self.base_url}/api/v1/assets", params=params)
        resp.raise_for_status()
        return resp.json().get("assets", [])

    def get_asset_detail(self, asset_id: str):
        """Retrieve detailed asset information including firmware, modules, and CVEs."""
        resp = self.session.get(f"{self.base_url}/api/v1/assets/{asset_id}")
        resp.raise_for_status()
        return resp.json()

    def get_communication_map(self, site_id: str):
        """Retrieve communication relationships between assets."""
        resp = self.session.get(
            f"{self.base_url}/api/v1/sites/{site_id}/communications"
        )
        resp.raise_for_status()
        return resp.json().get("communications", [])

    def get_vulnerabilities(self, site_id: Optional[str] = None, severity: str = "critical"):
        """Retrieve vulnerabilities for discovered assets."""
        params = {"min_severity": severity}
        if site_id:
            params["site_id"] = site_id

        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities", params=params)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])

    def export_asset_inventory(self, output_file: str, site_id: Optional[str] = None):
        """Export full asset inventory to CSV for compliance reporting."""
        assets = self.get_assets(site_id=site_id)
        if not assets:
            print("[!] No assets found")
            return

        fieldnames = [
            "asset_id", "name", "type", "vendor", "model", "firmware_version",
            "ip_address", "mac_address", "serial_number", "purdue_level",
            "zone", "protocol", "first_seen", "last_seen", "risk_score",
            "cve_count", "site_name",
        ]

        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for asset in assets:
                writer.writerow({
                    "asset_id": asset.get("id", ""),
                    "name": asset.get("name", "Unknown"),
                    "type": asset.get("type", ""),
                    "vendor": asset.get("vendor", ""),
                    "model": asset.get("model", ""),
                    "firmware_version": asset.get("firmware_version", ""),
                    "ip_address": asset.get("ip_address", ""),
                    "mac_address": asset.get("mac_address", ""),
                    "serial_number": asset.get("serial_number", ""),
                    "purdue_level": asset.get("purdue_level", ""),
                    "zone": asset.get("zone", ""),
                    "protocol": ", ".join(asset.get("protocols", [])),
                    "first_seen": asset.get("first_seen", ""),
                    "last_seen": asset.get("last_seen", ""),
                    "risk_score": asset.get("risk_score", 0),
                    "cve_count": asset.get("cve_count", 0),
                    "site_name": asset.get("site_name", ""),
                })

        print(f"[+] Exported {len(assets)} assets to {output_file}")

    def generate_purdue_level_report(self, site_id: str):
        """Generate asset distribution report by Purdue Model level."""
        assets = self.get_assets(site_id=site_id)
        levels = {0: [], 1: [], 2: [], 3: [], 3.5: [], 4: [], 5: []}

        for asset in assets:
            level = asset.get("purdue_level", -1)
            if level in levels:
                levels[level].append(asset)

        print(f"\n{'='*65}")
        print("PURDUE MODEL ASSET DISTRIBUTION REPORT")
        print(f"{'='*65}")
        print(f"Site: {site_id}")
        print(f"Total Assets Discovered: {len(assets)}")
        print(f"Report Generated: {datetime.now().isoformat()}")
        print(f"{'-'*65}")

        level_names = {
            0: "Level 0 - Physical Process (Sensors/Actuators)",
            1: "Level 1 - Basic Control (PLCs/RTUs)",
            2: "Level 2 - Supervisory Control (HMI/SCADA)",
            3: "Level 3 - Site Operations (Historian/MES)",
            3.5: "Level 3.5 - IT/OT DMZ",
            4: "Level 4 - Enterprise IT",
            5: "Level 5 - Enterprise Network/Internet",
        }

        for level, name in level_names.items():
            device_list = levels.get(level, [])
            print(f"\n  {name}")
            print(f"    Count: {len(device_list)}")
            if device_list:
                vendors = set(a.get("vendor", "Unknown") for a in device_list)
                types = set(a.get("type", "Unknown") for a in device_list)
                print(f"    Vendors: {', '.join(vendors)}")
                print(f"    Types: {', '.join(types)}")
                high_risk = [a for a in device_list if a.get("risk_score", 0) >= 7]
                if high_risk:
                    print(f"    High-Risk Assets: {len(high_risk)}")
                    for a in high_risk[:5]:
                        print(f"      - {a['name']} (Risk: {a.get('risk_score')})")


if __name__ == "__main__":
    discovery = ClarotyAssetDiscovery(
        base_url="https://your-claroty-instance.claroty.cloud",
        api_token="your-api-token-here",
        verify_ssl=True,
    )

    print("[*] Fetching sites...")
    sites = discovery.get_sites()
    for site in sites:
        print(f"  Site: {site['name']} (ID: {site['id']})")

    if sites:
        site_id = sites[0]["id"]
        print(f"\n[*] Generating Purdue level report for {sites[0]['name']}...")
        discovery.generate_purdue_level_report(site_id)

        print(f"\n[*] Exporting asset inventory...")
        discovery.export_asset_inventory(
            f"asset_inventory_{datetime.now().strftime('%Y%m%d')}.csv",
            site_id=site_id,
        )

        print(f"\n[*] Checking critical vulnerabilities...")
        vulns = discovery.get_vulnerabilities(site_id=site_id, severity="critical")
        print(f"  Critical vulnerabilities: {len(vulns)}")
        for v in vulns[:10]:
            print(f"    - {v.get('cve_id')}: {v.get('description', '')[:80]}")
```
