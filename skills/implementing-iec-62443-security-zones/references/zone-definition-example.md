# IEC 62443-3-2 Zone Definition Example

```yaml
# IEC 62443-3-2 Zone Definition Document
facility: "Petrochemical Refinery - Unit 3"
assessment_date: "2026-02-23"
standard: "IEC 62443-3-2:2020"

zones:
  - zone_id: "Z1-SIS"
    name: "Safety Instrumented Systems"
    purdue_level: 1
    security_level_target: "SL 3"
    criticality: "Safety Critical"
    assets:
      - "Triconex 3008 Safety Controller (SIS-01)"
      - "Triconex 3008 Safety Controller (SIS-02)"
      - "SIS Engineering Workstation"
    security_requirements:
      - "Physically isolated from all other zones (air-gapped)"
      - "Dedicated engineering workstation with removable media controls"
      - "No remote access permitted under any circumstances"
      - "Change management requires dual authorization"
    allowed_conduits: []  # No network conduits - fully air-gapped

  - zone_id: "Z2-BPCS"
    name: "Basic Process Control System"
    purdue_level: "1-2"
    security_level_target: "SL 2"
    criticality: "High"
    assets:
      - "Allen-Bradley ControlLogix PLCs (PLC-01 through PLC-12)"
      - "Rockwell FactoryTalk View HMIs (HMI-01 through HMI-06)"
      - "Engineering Workstation (EWS-01)"
    security_requirements:
      - "Industrial firewall at zone boundary with protocol inspection"
      - "Read-only access from Level 3 for data acquisition"
      - "Write access restricted to engineering workstation subnet"
      - "USB ports disabled on HMIs"
    allowed_conduits: ["C1-BPCS-OPS"]

  - zone_id: "Z3-OPS"
    name: "Site Operations"
    purdue_level: 3
    security_level_target: "SL 2"
    criticality: "Medium"
    assets:
      - "OSIsoft PI Historian (HIST-01)"
      - "OPC UA Server (OPC-01)"
      - "MES Application Server (MES-01)"
      - "Alarm Management Server (ALM-01)"
    security_requirements:
      - "Firewall between operations and control zones"
      - "Firewall between operations and DMZ"
      - "No direct internet access"
      - "Antivirus with OT-approved signatures"
    allowed_conduits: ["C1-BPCS-OPS", "C2-OPS-DMZ"]

  - zone_id: "Z4-DMZ"
    name: "Industrial Demilitarized Zone"
    purdue_level: 3.5
    security_level_target: "SL 2"
    criticality: "Medium"
    assets:
      - "PI-to-PI Interface (DMZ-HIST-01)"
      - "Patch Management Server (DMZ-WSUS-01)"
      - "Remote Access Jump Server (DMZ-JUMP-01)"
      - "Data Diode - Waterfall Security (DMZ-DD-01)"
    security_requirements:
      - "Dual-homed firewalls on both sides"
      - "No direct traffic traversal - all connections terminate in DMZ"
      - "Data diode for unidirectional historian replication"
      - "Jump server with MFA for remote access"
    allowed_conduits: ["C2-OPS-DMZ", "C3-DMZ-ENT"]

  - zone_id: "Z5-ENT"
    name: "Enterprise Network"
    purdue_level: 4
    security_level_target: "SL 1"
    criticality: "Low (from OT perspective)"
    assets:
      - "Corporate systems accessing OT data"
    security_requirements:
      - "Firewall between enterprise and DMZ"
      - "No direct access to any OT zone below DMZ"
    allowed_conduits: ["C3-DMZ-ENT"]

conduits:
  - conduit_id: "C1-BPCS-OPS"
    name: "Control-to-Operations Conduit"
    connects: ["Z2-BPCS", "Z3-OPS"]
    security_level: "SL 2"
    protocols_allowed:
      - protocol: "OPC UA"
        port: 4840
        direction: "Z2 -> Z3 (read only)"
        security_mode: "SignAndEncrypt"
      - protocol: "Modbus/TCP"
        port: 502
        direction: "Z3 -> Z2 (read only, FC 3/4 only)"
        security_mode: "Firewall-enforced function code filtering"
    controls:
      - "Industrial firewall with OT protocol DPI"
      - "Allowlisted source/destination IP pairs"
      - "Function code filtering (block all write operations from L3)"
      - "Connection rate limiting"

  - conduit_id: "C2-OPS-DMZ"
    name: "Operations-to-DMZ Conduit"
    connects: ["Z3-OPS", "Z4-DMZ"]
    security_level: "SL 2"
    protocols_allowed:
      - protocol: "PI-to-PI"
        port: 5450
        direction: "Z3 -> Z4 (unidirectional via data diode)"
      - protocol: "HTTPS"
        port: 443
        direction: "Z4 -> Z3 (patch downloads only)"
    controls:
      - "Data diode for historian replication (Waterfall Security)"
      - "Firewall with application-layer inspection"
      - "Patch server pulls only from approved vendor repositories"

  - conduit_id: "C3-DMZ-ENT"
    name: "DMZ-to-Enterprise Conduit"
    connects: ["Z4-DMZ", "Z5-ENT"]
    security_level: "SL 1"
    protocols_allowed:
      - protocol: "HTTPS"
        port: 443
        direction: "Z5 -> Z4 (historian read, remote access portal)"
      - protocol: "RDP"
        port: 3389
        direction: "Z5 -> Z4 (jump server with MFA)"
    controls:
      - "Next-gen firewall with SSL inspection"
      - "MFA required for all remote access sessions"
      - "Session recording on jump server"
```
