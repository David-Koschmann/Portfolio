<#
.SYNOPSIS
    This PowerShell script disables Wi-Fi Sense auto-connect to open/shared hotspots, preventing the system from automatically joining unsecured or untrusted wireless networks.

.NOTES
    Author          : David Koschmann
    LinkedIn        : www.linkedin.com/in/davidkoschmann
    GitHub          : https://github.com/David-Koschmann
    Date Created    : 19-AUG-2026
    Last Modified   : 19-AUG-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000065
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000065/

.TESTED ON
    Date(s) Tested  : 19-AUG-2026
    Tested By       : David Koschmann
    Systems Tested  : Windows 11 Pro (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run as Administrator.
    PS C:\> .\WN11-CC-000065.ps1
#>

$RegPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"

if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

New-ItemProperty -Path $RegPath -Name "AutoConnectAllowedOEM" -Value 0 -PropertyType DWord -Force | Out-Null
