# SOC Investigation Spine: Scheduled Task Persistence – T1053.005

**Explanation:** This playbook analyzes the technique of achieving persistence by creating or modifying a **Scheduled Task**. Attackers use the legitimate Windows Task Scheduler service (`taskschd.msc`) via command-line utilities (`schtasks.exe` or PowerShell cmdlets) to set their payload to execute automatically. The task is often configured to run under a high-privilege account (SYSTEM or Administrator) or to mimic the naming convention of benign system tasks. The most reliable **Anchor Point** is the **creation of a new, suspicious task** on the system, often pointing to an unknown executable or script.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1078 (Valid Accounts) | **Endpoint/Identity:** Attacker gains initial access and establishes a foothold. | **File Creation Event:** Dropper file (`loader.exe`) lands on the user's system. |
| **Execution / Foothold** | T1059 (Command-Line Scripting) | **Process:** The initial payload executes a command to achieve persistence. | **Process Event:** `CMD.EXE` or `POWERSHELL.EXE` executes a command to create a task. |
| **Persistence (ANCHOR)**| **T1053.005 (Scheduled Task)** | **Task Scheduler/Process:** **Execution** of `schtasks.exe` or `Register-ScheduledTask` to create a malicious job. | **Task Scheduler Event ID 4698** (A scheduled task has been created) or **Event ID 106** (Task Registered). |
| **Execution After Trigger** | T1059 (Scripting) | **Process:** The malicious task executes the attacker's payload based on its defined trigger (time, logon, event). | **Process Anomaly:** The **Task Host process (`taskeng.exe` or `svchost.exe`)** spawns a suspicious child process (the payload). |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2 Channel) | **Network:** The payload executes, establishes a C2 channel, and performs malicious activity. | **Network Log:** Outbound connection from the payload process to an external C2 IP or domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Task IOCs

1.  **Task Creation Event:** The most critical IOC is the **Task Scheduler Operational Event ID 4698** (on the target host), which details the creation of a new scheduled task. Focus on:
    * **Task Name:** Suspicious or generic names (e.g., "GoogleUpdateX," "MaintenanceJob," "ServiceHealth").
    * **Action/Command:** The command executed, often pointing to an unusual executable path (e.g., `C:\ProgramData\temp\update.exe`) or containing suspicious command-line flags.
    * **User/Context:** The account the task is configured to run as (e.g., SYSTEM or a compromised administrative account).
2.  **`schtasks.exe` Command Line:** Look for the command-line execution of **`schtasks.exe`** with the `/create` flag, or the use of PowerShell cmdlets (`New-ScheduledTask`, `Set-ScheduledTask`). The arguments will directly reveal the persistence mechanism.
3.  **Execution Chain Anomaly:** When the malicious task executes, the process tree will show a legitimate **Task Scheduler service process** (`taskeng.exe` or `svchost.exe`) as the **Parent Process** spawning the **malicious payload** as the Child Process. This is the runtime indicator of the attack.

### File, Network, and Identity IOCs

1.  **Task XML File:** Scheduled tasks are stored as XML files. Look for **new XML file creation** in the task folder (`C:\Windows\System32\Tasks\`) corresponding to the suspicious task name. Analyze the XML for unusual triggers (e.g., running every 5 minutes, or running at logon for all users).
2.  **Network Connection at Task Run:** Check network logs for an **outbound connection** initiated by the payload executable (the file the task calls) immediately after the task's defined trigger fires, confirming C2 callback activity.
3.  **File System Artifacts:** Analyze the file being called by the task for suspicious metadata (missing digital signature, high entropy). Quarantining and analyzing this payload file is essential for understanding the full attack capabilities.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Disable the malicious persistence mechanism and remove the threat. | **Disable/Delete the malicious task** using `schtasks.exe /delete` or the Task Scheduler GUI. **Quarantine the payload file** the task was configured to execute. |
| **Task Creation Control** | **Restrict Task Creation:** Limit the ability of standard users or unknown processes to create system-level tasks. | Use **Security Descriptor Definition Language (SDDL)** to restrict who can create tasks in the root folder (`\`). Configure EDR to alert on **`schtasks.exe /create`** by non-system accounts. |
| **Monitoring** | **Mandate Detailed Logging:** Ensure that task creation and execution events are fully captured. | Verify that **Task Scheduler Operational Logs** (Event IDs 106, 4698) are enabled and ingested into the SIEM. |
| **Privilege Restriction** | **Least Privilege:** Ensure tasks are not configured to run with privileges higher than absolutely necessary. | Audit existing scheduled tasks to identify and reduce the number of tasks running with **SYSTEM** or **Administrator** privileges. |
