# FIDO2 Security Key Registration Workflow

```powershell
# Bulk FIDO2 security key registration via Temporary Access Pass
# Step 1: Issue Temporary Access Pass for key registration

function Issue-TemporaryAccessPass {
    param(
        [string]$UserId,
        [int]$LifetimeMinutes = 60,
        [bool]$IsUsableOnce = $true
    )

    $tap = @{
        "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
        lifetimeInMinutes = $LifetimeMinutes
        isUsableOnce = $IsUsableOnce
    }

    $result = New-MgUserAuthenticationTemporaryAccessPassMethod `
        -UserId $UserId `
        -BodyParameter $tap

    return @{
        UserId = $UserId
        TemporaryAccessPass = $result.TemporaryAccessPass
        ExpiresAt = $result.CreatedDateTime.AddMinutes($LifetimeMinutes)
    }
}

# Bulk issue TAPs for security key registration event
$registrationUsers = Import-Csv "security_key_registration_list.csv"

$tapResults = foreach ($user in $registrationUsers) {
    $tap = Issue-TemporaryAccessPass -UserId $user.UserPrincipalName
    [PSCustomObject]@{
        User = $user.UserPrincipalName
        TAP = $tap.TemporaryAccessPass
        Expires = $tap.ExpiresAt
        KeySerial = $user.AssignedKeySerial
    }
}

# Export TAPs for secure distribution to registration team
$tapResults | Export-Csv "tap_assignments.csv" -NoTypeInformation

# Monitor FIDO2 registration progress
function Get-Fido2RegistrationStatus {
    $allUsers = Get-MgUser -All -Property "id,userPrincipalName,department"

    $registrationStatus = foreach ($user in $allUsers) {
        $methods = Get-MgUserAuthenticationFido2Method -UserId $user.Id

        [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            Department = $user.Department
            Fido2KeyCount = $methods.Count
            KeyModels = ($methods.Model -join ", ")
            RegistrationDates = ($methods.CreatedDateTime -join ", ")
            HasBackupKey = $methods.Count -ge 2
        }
    }

    return $registrationStatus
}

$status = Get-Fido2RegistrationStatus
$total = $status.Count
$registered = ($status | Where-Object { $_.Fido2KeyCount -gt 0 }).Count
$withBackup = ($status | Where-Object { $_.HasBackupKey }).Count

Write-Host "FIDO2 Registration Progress"
Write-Host "  Total Users: $total"
Write-Host "  Registered:  $registered ($([math]::Round($registered/$total*100,1))%)"
Write-Host "  With Backup: $withBackup ($([math]::Round($withBackup/$total*100,1))%)"
```
