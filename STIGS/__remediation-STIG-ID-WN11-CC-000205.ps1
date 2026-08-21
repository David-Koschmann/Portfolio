<#
.SYNOPSIS
    This PowerShell script configures Windows Telemetry to the 'Basic' level, restricting diagnostic data collection and preventing excessive telemetry from being sent outside the enterprise.

.NOTES
    Author          : Davvid Koschmann
    LinkedIn        : www.linkedin.com/in/davidkoschmann
    GitHub          : https://github.com/David-Koschmann
    Date Created    : 19-AUG-2026
    Last Modified   : 19-AUG-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000205
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000205/

.TESTED ON
    Date(s) Tested  : 19-AUG-2026
    Tested By       : David Koschmann
    Systems Tested  : Windows 11 Pro (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run as Administrator.
    PS C:\> .\__remediation-STIG-ID-WN11-CC-000205.ps1
#>

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"

if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Value 1 = Basic (safe on all editions). Use 0 (Security) instead if running Windows 11 Enterprise.
New-ItemProperty -Path $RegPath -Name "AllowTelemetry" -Value 1 -PropertyType DWord -Force | Out-Null
