# SOC Investigation Spine: Registry Run / Startup Folder Persistence – T1547.001 & T1547.001

**Explanation:** This playbook analyzes the use of the **Registry Run Keys** (e.g., `Run`, `RunOnce`) or the **Startup Folder** to maintain unauthorized access to a system. The attacker achieves persistence by setting a registry value or placing a shortcut/executable file in a location that Windows is configured to execute automatically upon system boot or user logon. The most reliable **Anchor Point** is the **suspicious modification or addition** of a key/value in one of these designated persistence locations, often pointing to an unknown or hidden file.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1078 (Valid Accounts) | **Endpoint/Identity:** Attacker gains initial code execution or credentials on the target host. | **File Creation Event:** Dropper file (`loader.exe`) lands on the user's system. |
| **Execution / Foothold** | T1059 (Command-Line) | **Process:** The initial payload executes a command to achieve persistence. | **Process Event:** `CMD.EXE` or `POWERSHELL.EXE` executes a command to modify the registry. |
| **Persistence (ANCHOR)**| **T1547.001 (Registry Run Keys)** | **Registry/File:** **Modification** of a critical persistence registry key or **creation** of a file in the Startup Folder. | **Registry Event:** **Key Write** or **Value Set** in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or `HKLM\...Run`. |
| **Execution After Boot** | T1059 (Scripting) | **Process:** The persistent item executes the attacker's payload during the next logon/boot cycle. | **Process Anomaly:** Execution of a suspicious file from a persistence location (e.g., `C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`). |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2 Channel) | **Network:** The persistent payload establishes a C2 channel and performs malicious activity (e.g., keylogging, data staging). | **Network Log:** Outbound connection from the payload process to an external C2 IP or domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Registry & File IOCs

1.  **Registry Key Modification:** The most critical IOC is the **Registry Key Write Event** detected by an EDR or system monitor. Focus on these high-value keys:
    * **User-Level Persistence:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    * **System-Wide Persistence:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
    * The **Value Data** (the executable path) will often point to a **suspiciously named file** in a non-standard location (`C:\ProgramData\`, `C:\Users\Public\`, or a heavily hidden directory).
2.  **Startup Folder Artifacts:** Look for the **creation of new files** (especially `.exe`, `.vbs`, `.js`, or `.lnk` shortcuts) in the physical Startup Folder locations:
    * **User:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
    * **All Users:** `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
3.  **File Metadata:** Analyze the file being called by the persistence mechanism. Check its **hash, digital signature (often missing),** and whether it has been **marked as hidden** on the file system.

### Process, Network, and Identity IOCs

1.  **Process Chain Anomaly (Execution):** During the next system boot/logon, the execution chain will be suspicious. The **Parent Process** of the malicious executable will be a legitimate system process responsible for the boot sequence (e.g., `EXPLORER.EXE`, `USERINIT.EXE`, or `SVCHOST.EXE` for a service). The **Child Process** will be the payload (e.g., `payload.exe`).
2.  **Network Connection at Logon:** Check network logs for an **immediate outbound connection** established by the payload process within seconds of the user logging on, indicating a C2 callback.
3.  **Identity Context:** Determine if the attacker targeted a **`HKCU` (Current User)** key, indicating they only have standard user privileges, or a **`HKLM` (Local Machine)** key, indicating they achieved **Administrator/SYSTEM** privileges to set the persistence system-wide.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Disable the persistence mechanism and remove the malicious file. | **Delete the malicious Registry Value** or **remove the file** from the Startup Folder location. **Quarantine the payload executable** and block its hash. |
| **System Integrity** | **Restrict Registry Modification:** Limit who can write to critical system registry keys. | Use **Group Policy** or **EDR controls** to prevent non-administrative or non-system accounts from modifying the `Run` and `RunOnce` keys. |
| **File Policy** | **Monitor Startup Folders:** Implement monitoring on key directories to detect unauthorized file placement. | Configure EDR and File Integrity Monitoring (FIM) to generate high-severity alerts upon **new file creation** in both the User and All Users Startup Folders. |
| **Initial Access Prevention** | **Block Payload:** Prevent the initial dropper from creating the persistent key/file. | Analyze the initial attack vector (e.g., phishing email) and implement email gateway rules to block the delivery of similar payloads. |
