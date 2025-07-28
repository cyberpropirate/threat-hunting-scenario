# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cyberpropirate/threat-hunting-scenario/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-07-27T03:28:38.1620915Z`. These events began at `2025-07-27T02:15:16.1799514Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-ope"
| where InitiatingProcessAccountName == "ybemployee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-27T02:15:16.1799514Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="3072" height="1509" alt="Screenshot (774)" src="https://github.com/user-attachments/assets/f760119f-4dfa-4751-92c3-3801f9e4e3b2" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLIne that contained the string “tor-browser-windows-x86_64-portable-14.5.5.exe”
Based on the logs returned: On the night of 2025-07-27T02:17:07.5858265Z, a user named ybemployee on a computer named threat-hunt-ope launched the Tor Browser directly from their Downloads folder, using a portable version of the file called tor-browser-windows-x86_64-portable-14.5.5.exe. This action created a new process on the system, indicating the browser was executed.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-ope"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="3072" height="1432" alt="Screenshot (775)" src="https://github.com/user-attachments/assets/26c8faf9-1d31-4204-ba29-687777446f01" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “ybemployee” actually opened the tor browser. There was evidence that they did open it at 2025-07-27T02:19:32.9499319Z. There were several other instances of firefox.exe(tor) as well as tor.exe spawned afterwards 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-ope"
| where FileName has_any ("firefox.exe", "tor.exe","start-tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="3072" height="1589" alt="Screenshot (776)" src="https://github.com/user-attachments/assets/567c405e-60d8-4d8a-846c-7dfd4b1d5ed9" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-07-27T02:20:30.4982041Z, an employee account named ybemployee on the device threat-hunt-ope successfully made a network connection using the program tor.exe, located in the Tor Browser folder on their desktop. The connection was to the remote IP address 94.130.52.190 over port 9030, which is commonly used by the Tor network for directory information. The connection also referenced the URL https://www.nawwgkpzjwrnfjg7pd6qnn.com, suggesting active Tor usage. There were a few other connections 


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-ope"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```
<img width="3072" height="1360" alt="Screenshot (777)" src="https://github.com/user-attachments/assets/7b9efe33-14c5-4080-a8fe-e269cfcfb224" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-27T02:15:16.1799514Z`
- **Event:** The user "ybemployee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ybemployee\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-27T02:17:07.5858265Z`
- **Event:** The user "ybemployee" executed the file `tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe /S`
- **File Path:** `C:\Users\ybemployee\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-27T02:19:32.9499319Z`
- **Event:** User "ybemployee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ybemployee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-07-27T02:20:30.4982041Z`
- **Event:** Network connection established via Tor to a known directory service IP.
- **Action:** Connection success using Tor over port 9030.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ybemployee\desktop\tor browser\browser\torbrowser\tor\tor.exe`
- **Remote IP:** 94.130.52.190
- **RemoteURL:** https://www.nawwgkpzjwrnfjg7pd6qnn.com.



### 5. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-27T03:28:38.1620915Z`
- **Event:** The user "ybemployee" created a file named `tor-shopping-list.lnk` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ybemployee\Desktop\tor-shopping-list.lnk`

---

## Summary

The user ybemployee on the endpoint threat-hunt-ope downloaded, installed, and actively used the Tor Browser. This included:

Launching the Tor portable executable

Successfully executing and spawning Tor-related processes

Connecting to the Tor network through a known directory server (port 9030)

Creating a Tor-related shortcut file on the desktop (tor-shopping-list.lnk)

The sequence of activity confirms deliberate Tor usage with the intent to browse anonymously or evade detection.

---

## Response Taken

Tor usage by user ybemployee was confirmed on device threat-hunt-ope.

The endpoint was isolated from the network.

The incident was escalated to security management, and the user’s direct supervisor was notified.
---
