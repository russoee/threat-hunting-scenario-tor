<img width="400" src="https://drive.google.com/file/d/1It0Ek4Tozynsunvhsom9C8luxhNTi5uJ/view?usp=sharing" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/russoee/Threat_Hunt_Event_-TOR-Usage-.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that certain employees might be using the TOR browser to circumvent network security controls. Recent network logs have revealed unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, anonymous reports suggest that employees have been discussing methods to access restricted sites during work hours. The objective is to identify any TOR activity, investigate related security incidents, and mitigate potential risks. If TOR usage is detected, management should be informed immediately.

### High-Level TOR-Related IoC Discovery Plan
- Review **DeviceFileEvents** for any instances of `tor(.exe)` or `firefox(.exe)` file activity.  
- Analyze **DeviceProcessEvents** for indications of TOR installation or execution.  
- Examine **DeviceNetworkEvents** for outgoing connections over known TOR ports.  


---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched the device file events table for any files containing the string "tor" and discovered that the user "employee" had downloaded a Tor installer. This action resulted in multiple Tor-related files being copied to the desktop and the creation of a file named "tor-shopping-list.txt" on the desktop at 2025-02-12T01:51:03.2719567Z. These events began at: 2025-02-12T01:38:47.0762637Z

Query used: 

```kusto
DeviceFileEvents
| where DeviceName == "eric-threat-hun"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "employee"
| where Timestamp >= datetime(2025-02-12T01:38:47.0762637Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, Account = InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/2d9bcdb7-2c37-44c8-be9b-fd94272b2dc2">

---

### 2. Searched the `DeviceProcessEvents` Table

Next, I searched the DeviceProcessEvents table for any process command lines containing the string "tor-browser". The logs revealed that at 8:42 PM on February 11, 2025, the user "employee" executed a Tor Browser installer (tor-browser-windows-x86_64-portable-14.0.6.exe) from the Downloads folder on the device "eric-threat-hun". The installer was launched with the /S (silent installation) flag, indicating an unattended installation without user prompts. The file's SHA256 hash confirms its integrity, suggesting it was not modified before execution.

Query used: 

```kusto
DeviceProcessEvents
| where DeviceName == "eric-threat-hun"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine, Account = InitiatingProcessAccountName, FileName, FolderPath, SHA256
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/3c1e4c4a-958e-405c-acd5-d942b7b40029">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the DeviceProcessEvents table for any indication that the user "employee" had actually opened Tor Browser. The logs confirm that Tor Browser was launched at 2025-02-12T01:43:26.4145645Z. Additionally, several instances of firefox.exe and tor.exe were spawned after this time, suggesting continued usage of the browser.

Query used to locate event:

```kusto
DeviceProcessEvents
| where DeviceName == "eric-threat-hun"
| where FileName has_any ("tor.exe", "tor-browser.exe", "firefox.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, ProcessCommandLine, Account = InitiatingProcessAccountName, FileName, FolderPath, SHA256
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ce1e0e70-68f7-4566-9111-f80327f2efbc">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The investigation began by focusing on Tor-specific network activity, using a query that filtered for known Tor-related ports. This confirmed that at 8:43 PM on February 11, 2025, the user "employee" launched Tor Browser and successfully connected to a Tor relay node (132.248.59.73:9001), indicating active use of the Tor network. Additional instances of firefox.exe and tor.exe running suggested sustained usage beyond the initial setup.

To expand the scope of the investigation, a second query removed the port-based filter and instead searched for network connections initiated by tor.exe, tor-browser.exe, and firefox.exe. This adjustment revealed additional results, including clearnet activity, indicating that the user may have accessed non-Tor websites alongside their anonymized browsing.

The following queries were used:

```kusto
DeviceNetworkEvents
| where DeviceName == "eric-threat-hun"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

DeviceNetworkEvents
| where DeviceName == "eric-threat-hun"
// | where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| where InitiatingProcessFileName in ("tor.exe", "tor-browser.exe", "firefox.exe")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```


<img width="1212" alt="image" src="https://github.com/user-attachments/assets/0140f9b1-00de-465f-8f0a-c58a7b896761">

---

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/8ef59676-07d3-4da8-8b16-3cbf68bc78f0">

---

# Chronological Events

## Detailed Timeline

### 2025-02-12T01:38:47.0762637Z — File Discovery
- The user **"employee"** appears to have downloaded a Tor installer and copied several Tor-related files to the desktop.
- Investigation of file events also showed multiple files named with “tor” in their paths.

### 2025-02-12T01:41:0485423Z — Tor Browser Installer Executed
- In *DeviceProcessEvents*, the user **"employee"** ran the Tor Browser installer (`tor-browser-windows-x86_64-portable-14.0.6.exe`) from the Downloads folder using the `/S` (silent) flag, indicating an unattended installation without user prompts.
- The file’s SHA256 hash confirmed it had not been modified.

### 2025-02-12T01:43:38174156Z — Tor Browser Launched
- Process logs confirm that Tor Browser (and by extension `firefox.exe` and `tor.exe`) started running, suggesting continued usage of the Tor environment.

### 2025-02-12T01:44:26.4145645Z — Tor Network Connection Established
- Network events show that Tor Browser successfully connected to a Tor relay node at `132.248.59.73:9001`, confirming active Tor usage immediately after installation.

### 2025-02-12T01:51:03.2719567Z — Tor-Related File Created
- A file named **"tor-shopping-list.txt"** was created on the desktop, indicating the user was possibly organizing or noting content while using Tor.

### Additional Network Queries
- When the search was expanded beyond Tor-specific ports, investigators found other network connections initiated by `tor.exe`, `tor-browser.exe`, and `firefox.exe`, suggesting clearnet activity interspersed with anonymized browsing.


---

## Summary
# Summary of Events

The user **`employee`** downloaded and silently installed the Tor Browser on **`eric-threat-hun`** sometime around `2025-02-12T01:38Z` (with logs marking the local time as February 11, 2025, 8:42 PM). Within minutes, the browser connected to a Tor relay node, confirming active Tor usage. Multiple process entries (for `tor.exe`, `tor-browser.exe`, and `firefox.exe`) indicate continued usage of Tor for anonymized traffic. A “tor-shopping-list.txt” file was also created on the desktop, suggesting the user may have been documenting or planning activities while using Tor. Expanded network queries revealed that the user not only used Tor-specific ports but also accessed clearnet sites, pointing to a mixture of anonymized and non-anonymized browsing. These findings directly align with management’s suspicion that an employee might be bypassing network security controls via Tor.


---

## Response Taken

Following the confirmation of TOR usage on the endpoint `eric-threat-hun` by the user `employee`, immediate containment measures were implemented. The device was isolated by placing it in a restricted network segment, effectively revoking its access to prevent any further unauthorized connections or potential data exfiltration.

Management was promptly informed of the findings. The user’s direct manager received a preliminary report detailing the installation and active use of the TOR browser, as well as suspicious network activity. 

To address the incident, the employee will undergo an interview to determine intent and assess any potential policy violations. Concurrently, security teams will review and reinforce policies concerning anonymized browsing and access control. To prevent further unauthorized TOR usage, enhanced endpoint monitoring will be implemented, focusing on detecting similar network behaviors.

If the investigation confirms any deliberate security policy breaches, the case will be escalated to HR and security leadership for further disciplinary action. Additionally, security teams will take proactive measures, including blocking known TOR entry nodes and enforcing stricter firewall rules to mitigate the risk of similar incidents occurring in the future.

This response ensures that security controls are strengthened while aligning with organizational policies and compliance requirements.

---
