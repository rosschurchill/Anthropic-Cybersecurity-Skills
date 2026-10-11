# SIEM Detection Queries (Splunk and KQL)

```spl
# Splunk: Detect MMC20.Application DCOM Lateral Movement
# Correlates network logon (4624 Type 3) with mmc.exe process creation

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\mmc.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
 OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe")
| eval target_host=ComputerName
| join target_host type=inner
    [search index=wineventlog EventCode=4624 LogonType=3
    | where AuthenticationPackageName="NTLM" OR AuthenticationPackageName="Kerberos"
    | eval target_host=ComputerName
    | rename IpAddress as source_ip, TargetUserName as logon_user
    | fields target_host source_ip logon_user _time]
| where abs(_time - relative_time(now(), "-5m")) < 300
| table _time target_host Image ParentImage CommandLine source_ip logon_user
| sort -_time
```

```spl
# Splunk: Detect ShellWindows/ShellBrowserWindow DCOM Lateral Movement
# Identifies explorer.exe spawning suspicious child processes on servers

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\explorer.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval target_host=ComputerName
| join target_host type=inner
    [search index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
     EventCode=3 DestinationPort=135 Initiated="false"
    | eval target_host=ComputerName
    | rename SourceIp as dcom_source_ip
    | fields target_host dcom_source_ip _time]
| where abs(_time - relative_time(now(), "-2m")) < 120
| stats count values(Image) as child_processes values(CommandLine) as commands
    by target_host dcom_source_ip
| where count > 0
| table target_host dcom_source_ip child_processes commands count
```

```spl
# Splunk: DCOM RPC Endpoint Mapper Connection Anomaly
# Identifies hosts receiving unusual volumes of inbound RPC connections

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 DestinationPort=135 Initiated="false"
| stats dc(SourceIp) as unique_sources count by ComputerName
| where unique_sources > 3 OR count > 10
| sort -unique_sources
| table ComputerName unique_sources count
```

```kql
-- Microsoft Sentinel KQL: DCOM Lateral Movement via MMC20.Application

let dcom_network = SysmonEvent
| where EventID == 3
| where DestinationPort == 135
| where InitiatedConnection == false
| project NetworkTime=TimeGenerated, TargetComputer=Computer,
    SourceIP=SourceIp, DestPort=DestinationPort;

let dcom_process = SysmonEvent
| where EventID == 1
| where ParentImage endswith "\\mmc.exe"
    or ParentImage endswith "\\dllhost.exe"
| where Image endswith "\\cmd.exe"
    or Image endswith "\\powershell.exe"
    or Image endswith "\\pwsh.exe"
    or Image endswith "\\wscript.exe"
    or Image endswith "\\mshta.exe"
| project ProcessTime=TimeGenerated, TargetComputer=Computer,
    ParentImage, Image, CommandLine, User;

dcom_network
| join kind=inner (dcom_process) on TargetComputer
| where abs(datetime_diff('second', NetworkTime, ProcessTime)) < 60
| project NetworkTime, ProcessTime, TargetComputer, SourceIP,
    ParentImage, Image, CommandLine, User
| sort by NetworkTime desc
```

```kql
-- Microsoft Sentinel KQL: ShellWindows DCOM Lateral Movement

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName in ("NTLM", "Kerberos")
| project LogonTime=TimeGenerated, TargetComputer=Computer,
    SourceIP=IpAddress, LogonUser=TargetUserName
| join kind=inner (
    SysmonEvent
    | where EventID == 1
    | where ParentImage endswith "\\explorer.exe"
    | where Image endswith "\\cmd.exe"
        or Image endswith "\\powershell.exe"
        or Image endswith "\\pwsh.exe"
    | project ProcessTime=TimeGenerated, TargetComputer=Computer,
        Image, CommandLine, User
) on TargetComputer
| where ProcessTime between (LogonTime .. (LogonTime + 2m))
| project LogonTime, ProcessTime, TargetComputer, SourceIP,
    LogonUser, Image, CommandLine
| sort by LogonTime desc
```
