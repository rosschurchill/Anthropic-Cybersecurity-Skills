# PetitPotam and Coercion Attack Detection

```spl
# Splunk: Detect PetitPotam / EFSCoerce Attack
# Monitor for machine account NTLM authentications relayed to other services

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
    TargetUserName="*$"
| where match(TargetUserName, "^[A-Z0-9\\-]+\\$$")
| eval is_dc = if(match(TargetUserName, "(DC|DCSERVER|DOMCTRL)"), "Yes", "No")
| where IpAddress != "127.0.0.1" AND IpAddress != "::1"
| stats count values(ComputerName) as target_hosts
    values(IpAddress) as source_ips by TargetUserName
| where count > 2 OR mvcount(source_ips) > 1
| table TargetUserName source_ips target_hosts count
| sort -count
```

```kql
-- Microsoft Sentinel KQL: PetitPotam / Coercion Attack Detection
-- Detects domain controller machine account authenticating from unexpected IPs

let dc_accounts = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TargetUserName endswith "$"
| where Computer startswith "DC"
| distinct TargetUserName;

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName in (dc_accounts)
| where IpAddress != "127.0.0.1" and IpAddress != "::1"
| extend SourceHostExpected = iff(
    Computer == replace_string(TargetUserName, "$", ""), true, false)
| where SourceHostExpected == false
| project TimeGenerated, Computer, TargetUserName, IpAddress,
    WorkstationName, LogonProcessName, AuthenticationPackageName
| sort by TimeGenerated desc
```

```yaml
# Sigma Rule: NTLM Relay - Computer Account Authentication from Unexpected Source
title: Potential NTLM Relay of Computer Account Credentials
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: stable
description: >
  Detects a computer account (ending in $) authenticating via NTLM LogonType 3
  where the source IP does not match the computer's known IP, indicating possible
  NTLM relay of coerced machine authentication (PetitPotam, DFSCoerce, PrinterBug).
references:
    - https://www.crowdstrike.com/en-us/blog/how-to-detect-domain-controller-account-relay-attacks-with-crowdstrike-identity-protection/
    - https://www.fox-it.com/nl-en/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
    - https://www.nccgroup.com/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: NTLM
        TargetUserName|endswith: '$'
    filter_localhost:
        IpAddress:
            - '127.0.0.1'
            - '::1'
            - '-'
    condition: selection and not filter_localhost
level: high
tags:
    - attack.credential_access
    - attack.t1557.001
    - attack.t1187
falsepositives:
    - Legitimate NTLM authentication from machine accounts during failover
    - Cluster service machine account authentication
```
