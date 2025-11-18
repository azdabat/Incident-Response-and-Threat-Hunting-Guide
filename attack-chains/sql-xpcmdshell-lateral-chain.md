# SOC Investigation Spine: SQL Server xp_cmdshell / Agent Lateral Movement – T1574.004 & T1059.003

**Explanation:** This playbook analyzes the abuse of **Microsoft SQL Server** features—specifically the powerful **`xp_cmdshell`** extended stored procedure or the **SQL Server Agent job system**—to achieve operating system command execution on the host server. The attacker must first gain access to the database (Initial Access) and have sufficient permissions (typically `sysadmin` or control over a service account) to enable and execute these features. This results in the database process (`sqlservr.exe`) spawning a command shell, providing a high-privilege foothold for lateral movement. The most reliable **Anchor Point** is the **`sqlservr.exe` process spawning an unexpected child process** like `cmd.exe` or `powershell.exe`.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1190 (Exploit Public-Facing) / T1078 (Valid Accounts) | **Network/Identity:** Attacker gains authenticated access to the SQL Server (e.g., weak SA password, SQL injection, RCE exploit). | **Database Log:** Successful high-privilege login from an external/unusual IP address. |
| **Execution / Configuration** | T1574.004 (Service Executable and Command) | **Database/Process:** Attacker enables `xp_cmdshell` or creates a malicious SQL Agent job. | **SQL Audit Log:** Command executed: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`. |
| **Lateral Movement (ANCHOR)**| **T1059.003 (Command and Scripting Interpreter)** | **Process:** The `sqlservr.exe` process spawns an OS command shell to execute malicious code. | **Process Anomaly:** **`sqlservr.exe` Parent** → **`cmd.exe` or `powershell.exe` Child**. |
| **Persistence / Staging** | T1543.003 (Service Creation) / T1036.003 (Masquerading) | **Process/File:** The command shell drops a payload, creates a persistent service, or performs reconnaissance. | **File Event:** Creation of a suspicious executable in `C:\Windows\Temp` by the `cmd.exe` process spawned by SQL Server. |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2) / T1486 (Data Encrypt) | **Network/Database:** Payload executes C2 communications, performs data dumps, or initiates ransomware encryption. | **Network Log:** Outbound connection from the payload process to an external C2 IP; **Database Log:** Large data export/dump commands. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Database IOCs

1.  **Process Anomaly (The xp\_cmdshell Tell):** The highest-fidelity IOC is the process tree anomaly on the SQL Server host. Look for:
    * **Parent Process:** **`sqlservr.exe`** (the main database engine process).
    * **Child Process:** **`cmd.exe`** or **`powershell.exe`**.
    * **Context:** This is highly unusual behavior unless explicitly mandated by system administrators. The **user context** of this spawned process is critical (often the service account, which frequently runs as **LocalSystem/NT AUTHORITY\SYSTEM**).
2.  **SQL Server Audit Logs:** Review SQL Server audit events for the following executed commands preceding the process anomaly:
    * **`sp_configure`:** Enabling `xp_cmdshell`.
    * **`EXEC xp_cmdshell`:** The direct command used to execute the OS shell (the arguments will often be obfuscated, encoded, or reference a dropped script).
    * **`sp_add_job` / `sp_add_jobstep`:** Creation of a new SQL Agent job where the job step is of type **`CmdExec`** and contains malicious command arguments.
3.  **Process Command Line:** The command-line arguments of the spawned `cmd.exe` or `powershell.exe` will contain the attacker's payload (e.g., base64-encoded strings, IEX calls, or references to C2 URLs).

### Network, File, and Identity IOCs

1.  **Outbound Network Activity:** Check network logs for any outbound connections originating from the **`cmd.exe` or payload process** that was spawned by `sqlservr.exe`. This is a strong indicator of C2 establishment or initial reconnaissance.
2.  **File System Artifacts:** Look for the **creation of new files** in temporary or user-writable directories (e.g., `C:\ProgramData`, `C:\Windows\Temp`) by the `cmd.exe` process. This represents the dropping of the secondary payload (e.g., a reverse shell executable or a persistent service binary).
3.  **Identity/Privilege Audit:** Audit the database account used to run the malicious commands. Confirm if the account was a **high-privilege user** (`sysadmin`) or a **low-privilege account** that was exploited to escalate privileges within the SQL database.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Disable the execution feature and terminate the malicious processes. | **Immediately disable `xp_cmdshell`** (`EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;`). **Kill the malicious child process** (`cmd.exe` or the payload executable) spawned by `sqlservr.exe`. |
| **Configuration Control** | **Principle of Least Privilege (Service Account):** The SQL Server service account should never run as LocalSystem. | Change the **SQL Server Service Account** to a dedicated, low-privilege Managed Service Account (MSA) that does **not** have local administrator rights on the host. |
| **Configuration Control (Feature):** Disable dangerous execution features by default. | **Ensure `xp_cmdshell` is disabled** on all non-essential SQL Server instances. Delete or restrict any unnecessary SQL Agent jobs containing **`CmdExec`** steps. |
| **Process Control** | **Application Control/EDR:** Block the SQL Server process from spawning unapproved child processes. | Configure **WDAC/AppLocker** or EDR controls to alert/block **`sqlservr.exe`** from creating children processes like `cmd.exe`, `powershell.exe`, `certutil.exe`, or `mshta.exe`. |
