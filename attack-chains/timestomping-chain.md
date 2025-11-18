# SOC Investigation Spine: File Timestomping Behaviour – T1070.006

**Explanation:** This playbook analyzes the defense evasion technique known as **Timestomping**, where an attacker modifies the timestamps (CreationTime, LastWriteTime, LastAccessTime) of a malicious file or artifact to match those of a benign, existing system file. The goal is to avoid detection by security tools and analysts looking for files with recent creation dates. This is achieved using native utilities like PowerShell's `Set-ItemProperty` or specialized tools. The most reliable **Anchor Point** is the **execution of the timestomping command** and the immediate detection of an **abnormal timestamp change** that lacks a corresponding file content modification.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1059 (Execution) | **Endpoint:** Dropper or loader executes and stages the core malicious payload file. | **File Creation Event:** Malicious payload file is initially written to the disk with the true current timestamp. |
| **Execution / Foothold** | T1059 (Command-Line Scripting) | **Process:** The malicious code executes the utility needed to modify the file timestamps. | **Process Event:** Execution of `powershell.exe`, `cmd.exe`, or a custom tool with file modification arguments. |
| **Timestomping (ANCHOR)**| **T1070.006 (Timestomp)** | **File System/Process:** Execution of commands or API calls to alter the MAC timestamps of the payload file. | **File Metadata Change:** EDR/FIM alert on a file's timestamp being updated without a corresponding change in the file content hash or size. |
| **Lateral Movement / Persistence** | T1547 (Persistence) | **Registry/Task:** The stealthy file is then referenced by a persistence mechanism (e.g., Scheduled Task, Run Key). | **Process Anomaly:** The timestomped file is referenced by a suspicious `schtasks.exe /create` or `reg add` command. |
| **Impact / Data Staging** | T1083 (File Reconnaissance) | **File:** The payload executes and performs its malicious function (e.g., encryption, data harvesting). | **Process Event:** Execution of the timestomped file, which leads to further malicious activity. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & File IOCs

1.  **Command Line Execution:** The most direct IOC is the command-line execution of utilities used for time modification. Look for:
    * **PowerShell IOC:** `powershell.exe` executing commands like **`Set-ItemProperty`** or **`$file.CreationTime=$newTime`** against a target file path.
    * **Third-party Tool IOC:** Execution of tools like **`timestomp.exe`** or custom binaries used specifically for this task.
2.  **File Metadata Integrity Anomaly (The Timestomp Tell):** This is the highest-fidelity indicator. Security tools (EDR, FIM) should alert on a timestamp change (CreationTime, LastWriteTime, LastAccessTime) that occurs **without a corresponding modification of the file hash (content)** or file size.
    * **Artifact Comparison:** Compare the **CreationTime** of the malicious file against its true **Write Time** to the disk (captured by initial file creation logs). If the CreationTime is older than the write time, timestomping has occurred.
3.  **Source File Context:** The timestomping command requires a *source* file whose timestamps are to be copied (e.g., `C:\Windows\System32\notepad.exe`). Look for the malicious command-line referencing the metadata of a known, benign system file.

### Network and Identity IOCs

1.  **Network Artifacts:** Timestomping is a post-execution evasion technique and typically has no direct network artifact. However, the process that executed the timestomping command (the dropper/loader) should be checked for prior network activity, such as the **download of the malicious payload** from a C2 server.
2.  **Identity Context:** Determine the **user context** under which the timestomping command was executed. Timestomping system files often requires **Administrator/SYSTEM** privileges, indicating a privilege escalation event must have occurred prior to this phase.
3.  **Pre-Timestomp Event:** Trace the process execution back to the **Initial Access** stage to find the first file creation event for the payload. This event records the **true creation timestamp** which is essential for forensic debunking of the false timestamps.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Remove the threat and the payload that was disguised. | **Quarantine the timestomped file** immediately. **Block the hash** of the malicious payload across the environment. |
| **System Integrity** | **Monitor Timestamp API Calls:** Implement monitoring for specific API calls used to modify file timestamps. | Configure EDR to alert on calls to **`SetFileTime`** or similar APIs when initiated by non-system processes or processes lacking a valid signature. |
| **Forensic Preservation** | **Enhanced Logging:** Ensure detailed process command-line logging is mandatory to capture the timestomping command itself. | Mandate **PowerShell Module Logging and Script Block Logging** to capture any scripts attempting to use `Set-ItemProperty` to modify MAC times. |
| **Process Control** | **Restrict Utility Execution:** Limit the execution of utilities known to be abused for defense evasion. | Use **AppLocker** or **WDAC** to prevent the execution of custom or suspicious binaries with arguments related to file timestamp modification. |
