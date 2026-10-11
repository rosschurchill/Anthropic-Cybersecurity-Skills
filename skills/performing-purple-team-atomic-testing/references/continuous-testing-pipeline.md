# Continuous Atomic Testing Pipeline

```powershell
# Continuous Atomic Testing - scheduled execution with validation
# Run as a scheduled task or via CI/CD pipeline

$PriorityTechniques = @(
    # Top MITRE ATT&CK techniques by prevalence (Red Canary Threat Detection Report)
    @{ Id = "T1059.001"; Name = "PowerShell" },
    @{ Id = "T1059.003"; Name = "Windows Command Shell" },
    @{ Id = "T1547.001"; Name = "Registry Run Keys" },
    @{ Id = "T1053.005"; Name = "Scheduled Task" },
    @{ Id = "T1003.001"; Name = "LSASS Memory" },
    @{ Id = "T1003.003"; Name = "NTDS" },
    @{ Id = "T1070.004"; Name = "File Deletion" },
    @{ Id = "T1218.011"; Name = "Rundll32" },
    @{ Id = "T1082";     Name = "System Information Discovery" },
    @{ Id = "T1105";     Name = "Ingress Tool Transfer" }
)

$ResultsLog = @()
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

foreach ($technique in $PriorityTechniques) {
    Write-Host "`n[*] Testing $($technique.Id) - $($technique.Name)" -ForegroundColor Cyan

    # Check prerequisites
    try {
        $prereqs = Invoke-AtomicTest $technique.Id -TestNumbers 1 -CheckPrereqs 2>&1
        $prereqsMet = $prereqs -notmatch "not met"
    } catch {
        $prereqsMet = $false
    }

    if (-not $prereqsMet) {
        Write-Host "    [!] Prerequisites not met, attempting install..." -ForegroundColor Yellow
        try {
            Invoke-AtomicTest $technique.Id -TestNumbers 1 -GetPrereqs 2>&1 | Out-Null
        } catch {
            Write-Host "    [!] Prereq install failed, skipping" -ForegroundColor Red
            $ResultsLog += [PSCustomObject]@{
                TechniqueId = $technique.Id
                Name        = $technique.Name
                Status      = "PREREQS_FAILED"
                Timestamp   = (Get-Date).ToString("o")
            }
            continue
        }
    }

    # Execute the test
    try {
        $startTime = Get-Date
        Invoke-AtomicTest $technique.Id -TestNumbers 1 -Confirm:$false
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Host "    [+] Executed successfully (${duration}s)" -ForegroundColor Green

        $ResultsLog += [PSCustomObject]@{
            TechniqueId = $technique.Id
            Name        = $technique.Name
            Status      = "EXECUTED"
            Duration    = $duration
            Timestamp   = $startTime.ToString("o")
        }
    } catch {
        Write-Host "    [-] Execution failed: $($_.Exception.Message)" -ForegroundColor Red
        $ResultsLog += [PSCustomObject]@{
            TechniqueId = $technique.Id
            Name        = $technique.Name
            Status      = "FAILED"
            Error       = $_.Exception.Message
            Timestamp   = (Get-Date).ToString("o")
        }
    }

    # Cleanup
    try {
        Invoke-AtomicTest $technique.Id -TestNumbers 1 -Cleanup 2>&1 | Out-Null
        Write-Host "    [+] Cleanup completed" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [!] Cleanup failed" -ForegroundColor Yellow
    }

    # Brief pause between tests for log ingestion
    Start-Sleep -Seconds 10
}

# Export results
$ResultsLog | Export-Csv "C:\AtomicRedTeam\logs\continuous_test_$RunTimestamp.csv" -NoTypeInformation
$ResultsLog | Format-Table -AutoSize

# Summary
$executed = ($ResultsLog | Where-Object Status -eq "EXECUTED").Count
$failed = ($ResultsLog | Where-Object Status -ne "EXECUTED").Count
Write-Host "`n=== CONTINUOUS TEST SUMMARY ===" -ForegroundColor Cyan
Write-Host "  Executed: $executed / $($PriorityTechniques.Count)" -ForegroundColor Green
Write-Host "  Failed:   $failed / $($PriorityTechniques.Count)" -ForegroundColor Red
```
