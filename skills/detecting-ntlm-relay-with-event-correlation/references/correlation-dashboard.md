# Comprehensive Correlation Dashboard

```spl
# Splunk: NTLM Relay Detection Dashboard -- Combined Correlation Query

# Panel 1: IP-Hostname Mismatches (Core Relay Indicator)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON" AND NOT match(TargetUserName, ".*\\$$")
| eval mismatch=if(lower(WorkstationName) != lower(mvindex(split(IpAddress, "."), 0)),
    "POSSIBLE_MISMATCH", "OK")
| where mismatch="POSSIBLE_MISMATCH"
| stats count by TargetUserName WorkstationName IpAddress ComputerName

# Panel 2: NTLMv1 Downgrade Events
index=wineventlog EventCode=4624 LmPackageName="NTLM V1"
| timechart span=1h count by ComputerName

# Panel 3: Machine Account Relay (PetitPotam Indicator)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
    TargetUserName="*$"
| stats count values(IpAddress) as relay_sources by TargetUserName ComputerName

# Panel 4: NTLM Authentication Volume Anomaly
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| timechart span=15m count
| streamstats window=20 avg(count) as avg_count stdev(count) as stdev_count
| eval upper_bound=avg_count + (3 * stdev_count)
| where count > upper_bound

# Panel 5: SMB Signing Status (from audit results)
| inputlookup smb_signing_audit.csv
| stats count by Status
| table Status count
```
