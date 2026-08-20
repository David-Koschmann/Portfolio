
# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 10/11 Virtual Machine (Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file with the string "tor" in it and discovered that a user downloaded a TOR installer, which resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at `2026-08-20T00:29:21.4324219Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "maclean-oce-au1"
| where Timestamp >= datetime(2026-08-20T00:29:21.4324219Z)
| order by Timestamp desc
```

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at 10:29:32 AM on August 20, 2026, user `smaclean` on the `maclean-oce-au1` device ran the file `tor-browser-windows-x86_64-portable-15.0.20.exe`.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "maclean-oce-au1"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, AccountName, FileName, ProcessCommandLine
```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user `smaclean` actually opened the TOR browser. There was evidence they did open it at 10:35:54 AM.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "maclean-oce-au1"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
| sort by Timestamp asc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR Browser was used to establish a connection over any of the known TOR ports. This search returned results confirming TOR network activity on host `maclean-oce-au1` under account `smaclean`.

At 10:36:23 AM, `firefox.exe` connected to `127.0.0.1:9150` — the local SOCKS port Tor Browser uses to route traffic through the Tor network — confirming the browser was actively using Tor for its connections, not just running with Tor idle.

Between 10:40:37 AM and 10:40:46 AM, `tor.exe` established outbound connections on port `9001` (the standard Tor relay/OR port) to two external IPs — `217.23.8.2` and `136.243.146.151` — consistent with Tor relay/entry-node traffic. A second `firefox.exe` connection to `127.0.0.1:9150` at 10:40:46 AM confirms continued Tor circuit usage at that time.

**Conclusion:** The `DeviceNetworkEvents` data corroborates that Tor Browser was not merely launched but actively used to route traffic through the Tor network, evidenced by local SOCKS proxy connections (port 9150) and outbound Tor relay connections (port 9001) to known Tor infrastructure IPs.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "maclean-oce-au1"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## Chronological Event Timeline

**Device:** `maclean-oce-au1` | **Account:** `smaclean` | **Session Context:** Remote session via Guacamole RDP (source IP `10.0.8.5`)

### 1. TOR Installer Download Completed
- **Timestamp:** `10:29:21 AM`
- **Event:** `msedge.exe` renamed `Unconfirmed 608620.crdownload` to `tor-browser-windows-x86_64-portable-15.0.20.exe` in `C:\Users\smaclean\Downloads\`, indicating the Tor Browser installer finished downloading via Microsoft Edge.
- **Source:** `tor-download.csv` — DeviceFileEvents

### 2. Zone Identifier Removed / Installer First Run
- **Timestamp:** `10:29:32 AM`
- **Event:** The Zone.Identifier (Mark-of-the-Web) alternate data stream on the downloaded file was deleted, and `tor-browser-windows-x86_64-portable-15.0.20.exe` was executed for the first time by `smaclean`.
- **Source:** `tor-download.csv`, `tor-install.csv` — DeviceFileEvents / DeviceProcessEvents

### 3. Silent Self-Extraction Triggered
- **Timestamp:** `10:30:38 AM`
- **Event:** The installer was re-invoked with the `/S` (silent) switch: `"tor-browser-windows-x86_64-portable-15.0.20.exe" /S`, launched under a `powershell.exe` parent process — extracting the portable application without further user prompts.
- **Source:** `tor-install.csv` — DeviceProcessEvents

### 4. Application Files Extracted
- **Timestamp:** `10:30:46 AM`
- **Event:** Multiple Tor Browser files were written to `C:\Users\smaclean\Desktop\Tor Browser\Browser\TorBrowser\`, including `tor.exe` and associated license files (`tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`), confirming full extraction of the portable Tor Browser package to the Desktop.
- **Source:** `tor-download.csv` — DeviceFileEvents

### 5. Installation Finalized
- **Timestamp:** `10:30:50 AM`
- **Event:** A shortcut, `Tor Browser.lnk`, was created on the Desktop, marking completion of the portable installation.
- **Source:** `tor-download.csv` — DeviceFileEvents

### 6. Tor Browser Launched
- **Timestamp:** `10:35:54 AM`
- **Event:** `firefox.exe` (Tor Browser's rebranded Firefox executable) was launched from `C:\Users\smaclean\Desktop\Tor Browser\Browser\browser`, followed immediately by the normal cascade of child processes (GPU, tab, RDD, and utility processes) through `10:36:08 AM`.
- **Source:** `tor-process-creation.csv` — DeviceProcessEvents

### 7. Tor Client Process Started
- **Timestamp:** `10:36:05 AM`
- **Event:** `tor.exe` launched with its configuration pointing to `torrc`, `geoip`, and onion-auth data under the Tor Browser data directory, establishing a local SOCKS proxy on `127.0.0.1:9150` and control port on `127.0.0.1:9151` — confirming the Tor networking component initialized alongside the browser.
- **Source:** `tor-process-creation.csv` — DeviceProcessEvents

### 8. Browser Confirmed Routing Through Tor
- **Timestamp:** `10:36:23 AM`
- **Event:** `firefox.exe` connected to the local SOCKS proxy at `127.0.0.1:9150`, confirming the browser was actively routing traffic through Tor rather than merely running with the Tor service idle.
- **Source:** `tor-usage.csv` — DeviceNetworkEvents

### 9. Continued Browser Activity
- **Timestamp:** `10:36:24 AM`
- **Event:** An additional Firefox tab process was spawned, consistent with continued interactive use of the browser.
- **Source:** `tor-process-creation.csv` — DeviceProcessEvents

### 10. Outbound Tor Network Connections Established
- **Timestamp:** `10:40:37 AM – 10:40:46 AM`
- **Event:** `tor.exe` established outbound connections on port `9001` (standard Tor relay/OR port) to two external IPs:
  - `217.23.8.2` (`10:40:37–10:40:38 AM`), associated with the URL `https://www.qsx3cvp34rudopsjpbyjffhf[.]com`
  - `136.243.146.151` (`10:40:40 AM`), associated with the URL `https://www.hnnjztqqrhvd5x[.]com`

  A second `firefox.exe` connection to `127.0.0.1:9150` at `10:40:46 AM` confirmed the browser was actively maintaining a Tor circuit at this time. The malformed/randomized domain names are consistent with Tor relay or `.onion`-related addressing rather than conventional websites.
- **Source:** `tor-usage.csv` — DeviceNetworkEvents

### 11. Sustained Active Browsing Session
- **Timestamp:** `10:55:28 AM – 10:58:52 AM`
- **Event:** A continued series of Firefox tab processes were spawned roughly every 30–90 seconds across this window (tabs 12 through 20), indicating `smaclean` remained actively engaged with the Tor Browser — opening multiple tabs/pages — for approximately 23 minutes after initial launch.
- **Source:** `tor-process-creation.csv` — DeviceProcessEvents

### 12. Suspicious Text File Created on Desktop
- **Timestamp:** `10:59:36 AM`
- **Event:** A blank `New Text Document.txt` was renamed to `tor-shopping-list.txt.txt` on the Desktop via Windows Explorer, and a corresponding "Recent Files" shortcut (`tor-shopping-list.txt.lnk`) was created — indicating the user actively created and opened this file immediately after the Tor browsing session.
- **Source:** `tor-download.csv` — DeviceFileEvents

### 13. File Opened in Notepad
- **Timestamp:** `10:59:42 AM`
- **Event:** `notepad.exe` opened `tor-shopping-list.txt.txt` under `smaclean`'s session.
- **Source:** `tor-download.csv` — DeviceFileEvents (InitiatingProcessCreationTime)

### 14. File Modified/Saved
- **Timestamp:** `11:00:09 AM`
- **Event:** `tor-shopping-list.txt.txt` was modified (content saved) via Notepad, indicating the user typed and saved content into the file shortly after concluding their Tor Browser activity.
- **Source:** `tor-download.csv` — DeviceFileEvents

---

## Summary

On August 20, 2026, user `smaclean` downloaded the Tor Browser portable installer via Microsoft Edge at 10:29 AM on device `maclean-oce-au1`. The installer was executed and silently self-extracted to the Desktop by 10:30 AM, completing with a desktop shortcut at 10:30:50 AM.

At 10:35:54 AM, `smaclean` launched Tor Browser. Within seconds, the embedded Tor client (`tor.exe`) initialized and the browser confirmed active use of the local Tor SOCKS proxy (port 9150) at 10:36:23 AM. Between 10:40:37–10:40:46 AM, outbound connections to known Tor relay infrastructure on port 9001 confirmed the browser successfully connected to the Tor network and routed traffic through it — this was not simply an installation or idle launch, but genuine, active Tor usage. Continued tab-creation activity through 10:58:52 AM shows the browsing session lasted approximately 23 minutes.

Immediately following the session, at 10:59–11:00 AM, `smaclean` created and saved a text file named `tor-shopping-list.txt` on the Desktop — a filename that, combined with the preceding Tor activity, raises concern that Tor was used to access illicit marketplaces or restricted content, and that the file may contain related notes.

**Conclusion:** The evidence conclusively shows `smaclean` downloaded, installed, and actively used Tor Browser to browse the Tor network on a corporate workstation, in apparent violation of acceptable use / network security policy. The creation of a file named `tor-shopping-list.txt` immediately after the session is a significant additional indicator warranting escalation. This activity should be reported to management for further action, and the affected device/user account should be reviewed for policy violation and potential compromise or misuse.

---

## Response Taken

TOR usage was confirmed on endpoint `maclean-oce-au1` (user: `smaclean`). The device was isolated to prevent further unauthorized network activity, and the user's direct manager was notified for further action, including review of the `tor-shopping-list.txt` file contents and initiation of the appropriate disciplinary/HR process per acceptable use policy.
