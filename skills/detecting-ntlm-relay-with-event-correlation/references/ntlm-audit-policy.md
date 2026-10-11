# NTLM Audit and Restriction Policy Configuration

```powershell
# PowerShell: Enable NTLM Auditing via Group Policy Registry Settings
# Must be applied via GPO for domain-wide coverage

# Audit all NTLM authentication in this domain
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings >
#      Local Policies > Security Options >
#      Network Security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all

# Registry equivalent (apply via GPO preferences or startup script)
# Domain Controller setting:
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
#     -Name "AuditNTLMInDomain" -Value 7 -Type DWord

# Audit incoming NTLM traffic on all servers:
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
#     -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord

# After enabling auditing, NTLM events appear in:
# Applications and Services Logs > Microsoft > Windows > NTLM > Operational

# Query NTLM operational log for audit events
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(8001, 8002, 8003, 8004) } |
    Select-Object TimeCreated, Id,
        @{N='EventType'; E={
            switch ($_.Id) {
                8001 { "NTLM client blocked audit" }
                8002 { "NTLM server blocked audit" }
                8003 { "NTLM server blocked in domain" }
                8004 { "NTLM authentication to DC audit" }
            }
        }},
        @{N='Detail'; E={$_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))}} |
    Format-Table -AutoSize
```

```spl
# Splunk: Monitor NTLM Audit Events (Event ID 8004)
# Shows all NTLM authentications passing through domain controllers

index=wineventlog source="WinEventLog:Microsoft-Windows-NTLM/Operational"
    EventCode=8004
| rex field=Message "Calling client name:\s+(?<client_name>[^\r\n]+)"
| rex field=Message "Calling client IP:\s+(?<client_ip>[^\r\n]+)"
| rex field=Message "Server name:\s+(?<server_name>[^\r\n]+)"
| stats count dc(server_name) as unique_servers by client_name client_ip
| sort -count
| table client_name client_ip unique_servers count
```
