<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Davvid Koschmann
    LinkedIn        : www.linkedin.com/in/davidkoschmann
    GitHub          : https://github.com/David-Koschmann
    Date Created    : 19-AUG-2026
    Last Modified   : 19-AUG-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\STIG-ID-WN11-AU-000500.ps1 
#>

# YOUR CODE GOES HERE

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Create the key path if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set MaxSize (dword:00008000 = 32768 decimal, in bytes)
New-ItemProperty -Path $regPath -Name "MaxSize" -Value 0x8000 -PropertyType DWord -Force | Out-Null
