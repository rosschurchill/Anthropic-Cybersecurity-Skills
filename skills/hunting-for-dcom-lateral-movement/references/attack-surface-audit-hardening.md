# DCOM Attack Surface Audit and Hardening

```powershell
# Audit DCOM configuration across the domain
# Enumerate remotely accessible DCOM objects

# List DCOM applications registered on local system
Get-CimInstance -ClassName Win32_DCOMApplication |
    Select-Object AppID, Name |
    Sort-Object Name |
    Format-Table -AutoSize

# Check DCOM launch permissions for high-risk objects
$clsids = @{
    "MMC20.Application"    = "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}"
    "ShellWindows"         = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
    "ShellBrowserWindow"   = "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"
    "Excel.Application"    = "{00024500-0000-0000-C000-000000000046}"
    "Outlook.Application"  = "{0006F03A-0000-0000-C000-000000000046}"
}

foreach ($name in $clsids.Keys) {
    $clsid = $clsids[$name]
    $regPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
    if (Test-Path $regPath) {
        $launchPermission = (Get-ItemProperty -Path "$regPath" -Name "LaunchPermission" -ErrorAction SilentlyContinue)
        Write-Host "[*] $name ($clsid): $(if ($launchPermission) { 'Custom permissions set' } else { 'DEFAULT permissions (potentially exploitable)' })"
    } else {
        Write-Host "[-] $name ($clsid): Not found on this system"
    }
}

# Check if DCOM is enabled (should be restricted on servers that don't need it)
$dcomEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM").EnableDCOM
Write-Host "`n[*] DCOM Enabled: $dcomEnabled"

# Check remote launch and activation permissions
$remoteLaunch = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "DefaultLaunchPermission" -ErrorAction SilentlyContinue)
Write-Host "[*] Default Launch Permission: $(if ($remoteLaunch) { 'Custom' } else { 'System Default' })"
```

```powershell
# Hardening: Restrict DCOM remote access via Group Policy
# These settings should be applied via GPO in production

# Disable DCOM on systems that do not require it
# Computer Configuration > Administrative Templates > System > Distributed COM >
#   Application Compatibility > Enable Distributed COM on this computer = Disabled

# Restrict DCOM launch permissions via registry
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "N"

# Block RPC/DCOM at the host firewall for non-admin traffic
# New-NetFirewallRule -DisplayName "Block Inbound DCOM/RPC" `
#     -Direction Inbound -LocalPort 135 -Protocol TCP `
#     -Action Block -RemoteAddress "Any" `
#     -Group "DCOM Hardening"
#
# New-NetFirewallRule -DisplayName "Allow DCOM from Admin Subnets" `
#     -Direction Inbound -LocalPort 135 -Protocol TCP `
#     -Action Allow -RemoteAddress "10.10.0.0/24" `
#     -Group "DCOM Hardening"

# Windows Firewall: Restrict dynamic RPC port range
# netsh int ipv4 set dynamicport tcp start=49152 num=1024
```
