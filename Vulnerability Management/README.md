# Programmatic Vulnerability Remediations

## Remediations Table

| Tenable PluginID | CVE | Description | Language | Link |
|---|---|---|---|---|
| N/A | N/A | Windows OS Updates - Re-enable Automatic Updates | Shell | [View Remediation](#1-windows-os-updates---re-enable-automatic-updates) |
| N/A | N/A | Guest Account Group Membership - Remove from Administrators & Disable | Shell | [View Remediation](#2-guest-account-group-membership---remove-from-administrators--disable) |
| 56710 | N/A | Wireshark / Ethereal Unsupported Version Detection - Force Remove | PowerShell | [View Remediation](https://github.com/kenbananola/ken-remediation-scripts/blob/main/wireshark-winpcap-force-remove.ps1) |
| 57608 | N/A | SMB Signing Not Required - Re-enable SMB Signing | PowerShell | [View Remediation](#4-smb-signing---re-enable) |
| 58453 | N/A | Terminal Services Doesn't Use Network Level Authentication (NLA) Only | PowerShell | [View Remediation](#5-rdp-network-level-authentication---re-enable-nla) |
| 63478 | N/A | Microsoft Windows LM / NTLMv1 Authentication Enabled | Shell | [View Remediation](#6-weak-lan-manager-authentication-level---restore-to-secure-default) |

---

## Remediation Commands

### 1. Windows OS Updates - Re-enable Automatic Updates

Run in **Command Prompt (Admin)**:
```shell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f
```

Verify with:
```shell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
```

---

### 2. Guest Account Group Membership - Remove from Administrators & Disable

Run in **Command Prompt (Admin)** one at a time:
```shell
net localgroup Administrators Guest /delete
```
```shell
net user Guest /active:no
```

---

### 3. Wireshark / WinPcap - Force Remove

PowerShell script: [wireshark-winpcap-force-remove.ps1](https://github.com/kenbananola/ken-remediation-scripts/blob/main/wireshark-winpcap-force-remove.ps1)

Run directly as **Administrator**:
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/kenbananola/ken-remediation-scripts/main/wireshark-winpcap-force-remove.ps1" -OutFile "$env:TEMP\wireshark-remove.ps1"; PowerShell -ExecutionPolicy Bypass -File "$env:TEMP\wireshark-remove.ps1"
```

---

### 4. SMB Signing - Re-enable

Run in **PowerShell (Admin)**:
```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
```

Verify with:
```powershell
Get-SmbServerConfiguration | Select RequireSecuritySignature, EnableSecuritySignature
```

Both values should return **True**.

---

### 5. RDP Network Level Authentication - Re-enable NLA

Run in **PowerShell (Admin)**:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Force
```

Verify with:
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
```

`UserAuthentication` should return **1**.

---

### 6. Weak LAN Manager Authentication Level - Restore to Secure Default

Run in **Command Prompt (Admin)**:
```shell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
```

Verify with:
```shell
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
```

It should return **0x5**.
