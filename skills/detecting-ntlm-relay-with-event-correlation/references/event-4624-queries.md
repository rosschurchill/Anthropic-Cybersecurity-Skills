# Event 4624 LogonType 3 Analysis Queries

```spl
# Splunk: Detect IP-to-Hostname Mismatches in Network Logons
# Core NTLM relay detection -- correlates WorkstationName with IpAddress

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM" LmPackageName="NTLM V2"
| where TargetUserName != "ANONYMOUS LOGON"
    AND TargetUserName != "-"
    AND NOT match(TargetUserName, ".*\\$$")
| eval workstation_lower=lower(WorkstationName)
| lookup dns_inventory.csv hostname AS workstation_lower OUTPUT expected_ip
| where isnotnull(expected_ip) AND IpAddress != expected_ip
| table _time ComputerName TargetUserName WorkstationName IpAddress expected_ip
    LogonProcessName AuthenticationPackageName
| sort -_time
| rename ComputerName as TargetHost, IpAddress as ActualSourceIP,
    expected_ip as ExpectedSourceIP
```

```spl
# Splunk: Detect Rapid Multi-Host Authentication (Relay Spraying)
# Attackers relay captured credentials to multiple targets quickly

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| bin _time span=2m
| stats dc(ComputerName) as target_count values(ComputerName) as targets
    values(IpAddress) as source_ips by _time TargetUserName
| where target_count > 3
| table _time TargetUserName source_ips target_count targets
| sort -target_count
```

```spl
# Splunk: Detect NTLM Authentication from Non-Workstation IPs
# Relay tools often run from Linux attack boxes not in DNS/DHCP inventory

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| lookup dhcp_leases.csv ip AS IpAddress OUTPUT mac_address hostname
| where isnull(hostname)
| stats count dc(ComputerName) as targets_hit values(ComputerName) as target_hosts
    by IpAddress TargetUserName WorkstationName
| where count > 1
| table IpAddress TargetUserName WorkstationName targets_hit target_hosts count
| sort -targets_hit
```

```kql
-- Microsoft Sentinel KQL: NTLM Relay Detection via IP-Hostname Mismatch

let known_hosts = datatable(WorkstationName:string, ExpectedIP:string)
[
    // Populate from CMDB or use DeviceNetworkInfo table
];
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| where IpAddress != "-" and IpAddress != "::1" and IpAddress != "127.0.0.1"
| extend WorkstationClean = toupper(trim_end(@"\s+", WorkstationName))
| join kind=inner (known_hosts) on WorkstationName
| where IpAddress != ExpectedIP
| project TimeGenerated, Computer, TargetUserName, WorkstationName,
    IpAddress, ExpectedIP, LogonProcessName, AuthenticationPackageName,
    LmPackageName
| sort by TimeGenerated desc
```

```kql
-- Microsoft Sentinel KQL: Rapid NTLM Authentication to Multiple Targets

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| summarize TargetCount=dcount(Computer),
    Targets=make_set(Computer),
    SourceIPs=make_set(IpAddress),
    AuthCount=count()
    by TargetUserName, bin(TimeGenerated, 2m)
| where TargetCount > 3
| project TimeGenerated, TargetUserName, SourceIPs, TargetCount, Targets, AuthCount
| sort by TargetCount desc
```
