# Passwordless Adoption Metrics

```powershell
# Generate passwordless adoption dashboard data
function Get-PasswordlessAdoptionMetrics {
    # Authentication method registration statistics
    $registrationReport = Get-MgReportAuthenticationMethodUserRegistrationDetail -All

    $metrics = @{
        TotalUsers = $registrationReport.Count
        PasswordlessCapable = ($registrationReport | Where-Object { $_.IsPasswordlessCapable }).Count
        MfaRegistered = ($registrationReport | Where-Object { $_.IsMfaRegistered }).Count
        Fido2Registered = ($registrationReport | Where-Object { "fido2" -in $_.MethodsRegistered }).Count
        WhfbRegistered = ($registrationReport | Where-Object { "windowsHelloForBusiness" -in $_.MethodsRegistered }).Count
        AuthenticatorRegistered = ($registrationReport | Where-Object { "microsoftAuthenticator" -in $_.MethodsRegistered }).Count
        SmsOnly = ($registrationReport | Where-Object {
            "sms" -in $_.MethodsRegistered -and
            "fido2" -notin $_.MethodsRegistered -and
            "windowsHelloForBusiness" -notin $_.MethodsRegistered
        }).Count
    }

    # Authentication method usage from sign-in logs
    $signInLogs = Get-MgAuditLogSignIn -Top 10000 -Filter "createdDateTime ge $((Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ'))"

    $authMethodUsage = $signInLogs |
        Group-Object { $_.AuthenticationMethodsUsed -join "," } |
        Select-Object Count, Name | Sort-Object Count -Descending

    return @{
        Registration = $metrics
        Usage = $authMethodUsage
    }
}

$adoption = Get-PasswordlessAdoptionMetrics
$reg = $adoption.Registration

Write-Host "PASSWORDLESS ADOPTION REPORT"
Write-Host "============================"
Write-Host "Total Users:              $($reg.TotalUsers)"
Write-Host "Passwordless Capable:     $($reg.PasswordlessCapable) ($([math]::Round($reg.PasswordlessCapable/$reg.TotalUsers*100,1))%)"
Write-Host "  FIDO2 Keys:             $($reg.Fido2Registered)"
Write-Host "  Windows Hello:          $($reg.WhfbRegistered)"
Write-Host "  Authenticator:          $($reg.AuthenticatorRegistered)"
Write-Host "MFA Registered:           $($reg.MfaRegistered) ($([math]::Round($reg.MfaRegistered/$reg.TotalUsers*100,1))%)"
Write-Host "SMS Only (needs upgrade): $($reg.SmsOnly)"
```
