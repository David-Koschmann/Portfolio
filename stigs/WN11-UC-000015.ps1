<#
.SYNOPSIS
    This PowerShell script disables toast notifications on the lock screen, preventing potentially sensitive notification content from being visible to unauthorized personnel at a locked workstation.

.NOTES
    Author          : David Koschmann
    LinkedIn        : www.linkedin.com/in/davidkoschmann
    GitHub          : https://github.com/David-Koschmann
    Date Created    : 19-AUG-2026
    Last Modified   : 19-AUG-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UC-000015
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-UC-000015/

.TESTED ON
    Date(s) Tested  : 19-AUG-2026
    Tested By       : David Koschmann
    Systems Tested  : Windows 11 Pro (Azure VM)
    PowerShell Ver. : 5.1

.USAGE
    Run as Administrator.
    PS C:\> .\WN11-UC-000015.ps1
#>

# NOTE: This setting is per-user (HKEY_CURRENT_USER), not machine-wide. Run in the context
# of the user account being scanned/remediated.
$RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"

if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

New-ItemProperty -Path $RegPath -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -PropertyType DWord -Force | Out-Null
