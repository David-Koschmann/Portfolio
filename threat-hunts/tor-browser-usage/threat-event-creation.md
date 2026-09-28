# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" Took to Create Logs and IoCs
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-15.0.20.exe /S```
3. Open the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites
5. Create a file on the desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in it

---

## Tables Used to Detect IoCs
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being silently installed (matches any installer version)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows" and ProcessCommandLine contains "/S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By
- **Author Name**: David Koschmann
- **Author Contact**: www.linkedin.com/in/davidkoschmann
- **Date**: August 20, 2026

---

## Revision History
| **Version** | **Changes** | **Date** | **Modified By** |
|-------------|-------------|----------|-----------------|
| 1.0 | Scenario based on the Log(N) Pacific cyber range threat hunt template | | |
| 1.1 | Adapted for this hunt: updated installer version, fixed documentation links and queries | August 20, 2026 | David Koschmann |
