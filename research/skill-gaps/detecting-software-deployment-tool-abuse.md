# Detecting Software Deployment Tool Abuse — research notes

- **Proposed slug:** detecting-software-deployment-tool-abuse
- **ATT&CK:** T1072 Software Deployment Tools (tactics: execution, lateral-movement) — related: T1651 Cloud Administration Command, T1570 Lateral Tool Transfer, T1078 Valid Accounts. Detection strategy: **DET0223** (analytics AN0623 Windows/SCCM-Intune, AN0626 cloud). (Verify ids against v19.2.)
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary who, after compromising an admin of an enterprise software-deployment / configuration-management system, uses it to push code to many endpoints at once — the system's whole purpose is trusted, authenticated, SYSTEM-context mass execution, so one compromised console is lateral movement and impact at scale (the 2017 NotPetya-style vector). Covers Microsoft SCCM/MECM and Intune, and Puppet/Chef/Ansible/SaltStack, JAMF/MDM on macOS, and cloud management services. The skill alerts on new/anomalous deployments, deployments outside change windows or by unusual accounts, and the resulting SYSTEM-context child processes on endpoints.

## Data sources / telemetry
- **Endpoint process creation (AN0623):** Windows Security **4688** / Sysmon **Event ID 1**. Look for deployment agents spawning interpreters: `CcmExec.exe`/`CCMExec.exe` or `cmtrace.exe` → `powershell.exe`/`cmd.exe`/`wscript.exe`; Intune Management Extension (`Microsoft.Management.Services.IntuneWindowsAgent.exe` / `IntuneManagementExtension`) spawning scripts; `puppet`/`chef-client`/`ansible`/`salt-minion` spawning shells. Fields: ParentImage, User context (SYSTEM), CommandLine, timing.
- **SCCM/MECM server + client logs:** client `execmgr.log`, `AppEnforce.log`, `PolicyAgent.log`, `Scripts` feature logs; site-server audit of new packages/applications/deployments and collection membership changes. Watch SCCM admin/security-role group changes (Windows **4720/4728/4732**).
- **Intune:** Entra/Intune audit logs — new device-configuration / PowerShell script / Win32-app assignments, new app deployments, changes to assignment groups.
- **Cloud/config-mgmt (AN0626):** cloud-native management script execution outside expected org IDs, admin groups, or maintenance windows (overlaps T1651); Ansible Tower/AWX job logs, Puppet/Chef server reports.

## Detection logic / approach
Per DET0223, the two complementary angles — **server-side** (who created/assigned a deployment) and **endpoint-side** (what the agent then executed) — correlated:
- **Server-side:** new SCCM package/application/deployment, Scripts-feature run, or Intune script/app assignment created by an account that does not normally author deployments, or outside the change window; sudden broad collection/assignment-group targeting (fan-out).
- **Endpoint-side (AN0623):** alert when the deployment agent spawns a script/binary from SYSTEM context with an unexpected parent or command line. Tunable parameters: allowlist of expected parents (`CCMExec.exe`, `IntuneManagementExtension`), expected SYSTEM-account deployment activity, and maintenance-hour `TimeWindow` (mutable elements: ParentImageList, UserContext, TimeWindow).
- **Correlate:** a new/odd server-side deployment immediately followed by the same payload executing across many hosts confirms abuse vs. a one-off.
- **Privilege-escalation path:** SCCM-specific hunts (admin-role group adds, PXE/NAA credential access) as precursors.

Example Sigma-style (process_creation, Windows):
```yaml
detection:
  selection_parent:
    ParentImage|endswith:
      - '\CcmExec.exe'
      - '\IntuneManagementExtension.exe'
  selection_child:
    Image|endswith: ['\powershell.exe','\cmd.exe','\wscript.exe','\cscript.exe','\mshta.exe']
  filter_expected:
    CommandLine|contains: <approved deployment script names / signed hashes>
  condition: selection_parent and selection_child and not filter_expected
```
Scope tightly and allowlist known deployment content; otherwise this is noisy, since legitimate deployments do exactly this.

## Response / mitigation
- Least privilege and tiered admin on SCCM/MECM, Intune, and config-management masters; MFA + PAW for deployment admins; separate the deployment system into its own admin tier (it is effectively domain-wide SYSTEM).
- Change-control gate + approval for new deployments; alert on out-of-band package/script creation; code-sign and allowlist deployment payloads; restrict the SCCM Scripts feature and audit its use.
- Harden SCCM (NAA, PXE, site-server hardening) per vendor guidance; monitor admin-role membership.
- Response: suspend the deployment/assignment, identify every targeted host, contain and triage them, revoke the authoring account, preserve server + client execmgr/AppEnforce logs, review recently created packages/scripts for implants.

## Real tools
Microsoft Configuration Manager (SCCM/MECM), Microsoft Intune, Entra audit logs; Puppet, Chef, Ansible/AWX/Tower, SaltStack; JAMF Pro and other MDM; Sysmon, Windows Security auditing, Splunk/Sentinel/Elastic; SharpSCCM / Misconfiguration Manager (for understanding attack paths and validating detections).

## Draft frontmatter mappings
- mitre_attack: [T1072, T1570, T1078, T1651]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, PR.AA-05, PR.PS-01, PR.IR-01]
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): detecting-poisoned-pipeline-execution

## Draft description (<=1024 chars)
Detects adversary abuse of enterprise software-deployment and configuration-management systems — SCCM/MECM, Intune, Puppet/Chef/Ansible, JAMF/MDM — to push code to many endpoints at once as trusted, SYSTEM-context mass execution (NotPetya-style lateral movement and impact). Correlates server-side signals (new or out-of-window deployments/scripts/app assignments by unusual accounts, broad collection or group targeting) with endpoint process creation where the deployment agent (CCMExec.exe, IntuneManagementExtension) spawns PowerShell/cmd. Use when hunting lateral movement via deployment tooling or triaging unexpected enterprise software pushes. Keywords: T1072, SCCM, MECM, Intune, Scripts feature, CCMExec, IntuneManagementExtension, Ansible, Puppet, JAMF, 4688, DET0223. Do not use for CI/CD build-pipeline poisoning (use detecting-poisoned-pipeline-execution) or cloud VM management-service execution (use detecting-cloud-administration-command-abuse).

## Key references
- https://attack.mitre.org/techniques/T1072/
- https://attack.mitre.org/detectionstrategies/DET0223 (verify id against v19.2)
- https://d3fend.mitre.org/offensive-technique/attack/T1072
- https://mitre.ptsecurity.com/en-US/T1072

## Open questions / scope boundaries
- Verify DET0223/AN0623/AN0626 ids and the exact Intune agent process name against primary sources; confirm current SCCM client log filenames.
- Author must supply the organization's approved-deployment allowlist (parent processes, signed payload hashes, change windows) — core to false-positive control.
- Must NOT cover CI/CD pipeline execution (T1677 — detecting-poisoned-pipeline-execution) or cloud VM admin-command services (T1651 — detecting-cloud-administration-command-abuse); scope is endpoint/device management-and-deployment platforms.
