# NTLM Downgrade Detection

```spl
# Splunk: Detect NTLMv1 Authentication (Downgrade from NTLMv2)
# NTLMv1 is weaker and easier to relay/crack -- should not be in use

index=wineventlog EventCode=4624 LogonType=3
    LmPackageName="NTLM V1"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| stats count values(ComputerName) as targets
    values(IpAddress) as source_ips
    by TargetUserName LmPackageName
| table TargetUserName LmPackageName source_ips targets count
| sort -count
```

```spl
# Splunk: Detect NTLM Downgrade Attack Pattern
# NTLMv1 appearing after a period of only NTLMv2 suggests active downgrade

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
| bin _time span=1h
| stats count(eval(LmPackageName="NTLM V1")) as ntlmv1_count
    count(eval(LmPackageName="NTLM V2")) as ntlmv2_count
    by _time
| where ntlmv1_count > 0
| eval ntlmv1_ratio = round(ntlmv1_count / (ntlmv1_count + ntlmv2_count) * 100, 2)
| table _time ntlmv1_count ntlmv2_count ntlmv1_ratio
| sort -_time
```

```kql
-- Microsoft Sentinel KQL: NTLMv1 Downgrade Detection

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where LmPackageName == "NTLM V1"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| project TimeGenerated, Computer, TargetUserName, WorkstationName,
    IpAddress, LmPackageName, LogonProcessName
| sort by TimeGenerated desc
```

```powershell
# PowerShell: Detect NTLMv1 Authentication Events on Local System

$ntlmv1Events = Get-WinEvent -LogName Security -FilterXPath @"
*[System[(EventID=4624)]]
 and
*[EventData[Data[@Name='LmPackageName']='NTLM V1']]
"@ -MaxEvents 500 -ErrorAction SilentlyContinue

if ($ntlmv1Events.Count -gt 0) {
    Write-Host "[!] WARNING: $($ntlmv1Events.Count) NTLMv1 authentication events detected!" -ForegroundColor Red
    $ntlmv1Events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time         = $_.TimeCreated
            TargetUser   = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            Workstation  = ($eventData | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
            SourceIP     = ($eventData | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            LmPackage    = ($eventData | Where-Object { $_.Name -eq "LmPackageName" }).'#text'
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "[+] No NTLMv1 authentication events found (Good)" -ForegroundColor Green
}

# Audit GPO settings for NTLM restriction
Write-Host "`n=== NTLM RESTRICTION POLICY ==="
$ntlmPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

$level = switch ($ntlmPolicy.LmCompatibilityLevel) {
    0 { "Send LM & NTLM responses (Most Vulnerable)" }
    1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
    2 { "Send NTLM response only" }
    3 { "Send NTLMv2 response only (Recommended minimum)" }
    4 { "Send NTLMv2 response only, refuse LM" }
    5 { "Send NTLMv2 response only, refuse LM & NTLM (Most Secure)" }
    default { "Not configured (defaults to 3 on modern Windows)" }
}
Write-Host "[*] LmCompatibilityLevel: $($ntlmPolicy.LmCompatibilityLevel) - $level"
```
