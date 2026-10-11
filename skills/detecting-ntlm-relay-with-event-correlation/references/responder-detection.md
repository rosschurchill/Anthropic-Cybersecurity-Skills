# Responder Detection Queries and Rules

```spl
# Splunk: Detect Responder LLMNR/NBT-NS Poisoning via Network Logs
# Responder answers LLMNR (UDP 5355) and NBT-NS (UDP 137) queries

index=network sourcetype=zeek_dns
| where query_type IN ("LLMNR", "NBNS")
    OR id.resp_p IN (5355, 137)
| stats dc(id.orig_h) as victims count by id.resp_h answers
| where count > 10
| rename id.resp_h as responder_ip
| table responder_ip victims answers count
| sort -count
```

```spl
# Splunk: Detect LLMNR/NBT-NS Response from Non-DNS Servers
# Legitimate DNS servers respond to these; Responder impersonates them

index=network sourcetype="bro:dns:json" OR sourcetype="zeek:conn:json"
| where id_resp_p=5355 OR id_resp_p=137
| where NOT cidrmatch("10.10.0.0/24", id_resp_h)
| stats count dc(id_orig_h) as unique_victims by id_resp_h
| where unique_victims > 3
| table id_resp_h unique_victims count
| rename id_resp_h as suspicious_responder
```

```powershell
# PowerShell: Detect LLMNR and NBT-NS activity on local network
# Run on a monitoring host to identify Responder-like behavior

# Check if LLMNR is disabled (should be disabled to prevent poisoning)
$llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -ErrorAction SilentlyContinue
Write-Host "[*] LLMNR Status: $(if ($llmnr.EnableMulticast -eq 0) { 'DISABLED (Good)' } else { 'ENABLED (Vulnerable to Responder)' })"

# Check if NBT-NS is disabled
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $nbtns = $adapter.TcpipNetbios
    $status = switch ($nbtns) {
        0 { "Default (Enabled)" }
        1 { "Enabled" }
        2 { "Disabled (Good)" }
    }
    Write-Host "[*] Adapter '$($adapter.Description)' NBT-NS: $status"
}

# Query Windows Firewall logs for LLMNR/NBT-NS traffic
Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" `
    -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match "5355|137" -and $_.Message -match "UDP"
    } |
    Select-Object TimeCreated, @{N='Detail';E={$_.Message.Substring(0,200)}} |
    Format-Table -AutoSize
```

```yaml
# Sigma Rule: Responder LLMNR/NBT-NS Poisoning Detection
title: Potential Responder LLMNR/NBT-NS Poisoning Activity
id: 7a8b9c0d-e1f2-3a4b-5c6d-7e8f9a0b1c2d
status: stable
description: >
  Detects a single host responding to LLMNR (UDP 5355) or NBT-NS (UDP 137)
  queries from multiple unique sources, indicating possible Responder poisoning.
references:
    - https://www.hackthebox.com/blog/ntlm-relay-attack-detection
    - https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/
logsource:
    category: firewall
detection:
    selection:
        dst_port:
            - 5355
            - 137
        action: allow
    condition: selection | count(src_ip) by dst_ip > 5
    timeframe: 5m
level: high
tags:
    - attack.credential_access
    - attack.t1557.001
falsepositives:
    - Legitimate WINS servers or DNS servers responding to broadcast queries
    - Network discovery tools performing name resolution
```
