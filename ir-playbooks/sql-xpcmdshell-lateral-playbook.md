# Incident Response Playbook – SQL Server xp_cmdshell / Agent Lateral Movement

This playbook addresses a high-impact **Lateral Movement** and **Execution** technique where an attacker exploits a compromised SQL login to execute operating system commands on the underlying host, typically using the stored procedure **`xp_cmdshell`** (T1059.003) or malicious SQL Agent Jobs (T1543.003). This attack allows the attacker to pivot from the database layer to the host's operating system, often gaining **SYSTEM** or high-level service account privileges.

**MITRE ATT&CK Tactic:** Execution (TA0002), Lateral Movement (TA0008), Privilege Escalation (TA0004)
**Technique:** Command and Scripting Interpreter: SQL Stored Procedures (T1059.003), Create or Modify System Process: Windows Service (T1543.003)
**Critical Threat:** The attacker has leveraged the powerful context of the SQL Service Account to gain a foothold on the server, potentially leading to immediate data exfiltration or installation of persistent malware.

---

## 1. L2 Analyst Actions (Initial Triage & Execution Trace)

The L2 analyst must confirm that the host-level command execution originated directly from a SQL Server process.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the executed command is tied to any documented database maintenance script, SQL Agent job, or administrative routine. **Reject any execution of uncommon binaries (e.g., `certutil`, `bitsadmin`) or commands making external connections.**
2.  **Parent Process Check (MDE Focus):** Crucially, verify the Parent Process of the command execution:
    * **`sqlservr.exe`:** Indicates direct execution via `xp_cmdshell`.
    * **`sqlagent.exe`:** Indicates execution via a malicious SQL Server Agent Job.
    * **If neither,** the execution did not originate from the database, and this playbook is likely not the primary concern.
3.  **Command Analysis:** Analyze the full command line executed by the child process (`cmd.exe`, `powershell.exe`). Look for:
    * **File Downloads:** Use of native download utilities (`Invoke-WebRequest`, `certutil -urlcache`, `bitsadmin /transfer`).
    * **Discovery:** Execution of commands like `whoami`, `ipconfig`, `net user`, indicating reconnaissance.
4.  **SQL Credentials:** Identify the **SQL Login Name** used to initiate the session on the database (this is often found in SQL audit logs or specific MDE process logs). This account is the immediate source of the compromise.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId` (The SQL Server host).
* `AccountName` / **`UPN`** (The host service account running SQL, and the originating remote user/account).
* **Time Range:** The $\pm1$ hour surrounding the command execution.
* **Execution Artifacts:** The **Parent SQL Process** (`sqlservr.exe`/`sqlagent.exe`), the **Child Command Line**, and the **Remote Client IP** that connected to the SQL server.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed successful execution of a non-standard command. **Severity is Critical.**
* The command execution is followed by a **new network connection** to an external/unknown C2 IP.
* The compromise occurred using a highly privileged SQL account (e.g., **`sa`** or a `sysadmin` role).
* The SQL Server service account is running as a **Domain Administrator** or a high-privilege Managed Service Account (MSA).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Pivot Analysis)

The L3 analyst must assume the SQL Service Account's privileges have been leveraged to establish a high-privilege host foothold.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Corroboration (External to SQL):** Trace the remote client IP identified in the L2 triage back to the source. How did the attacker gain access to the compromised SQL login? (e.g., SQL Injection on a web app, PtH from a workstation, external brute force attack).
2.  **SQL Activity Analysis:** Audit the **SQL Server Logs** for the exact commands run prior to `xp_cmdshell` execution, specifically looking for:
    * **`sp_configure 'xp_cmdshell', 1`** (Enabling the function).
    * **Malicious Agent Job creation** (`msdb` database modification).
    * **Data Extraction Queries** (e.g., sensitive table selects before exfiltration).
3.  **Post-Execution Analysis:** Analyze the payload executed by the command shell. Look for evidence of:
    * **Persistence:** Creation of a malicious Service or Scheduled Task on the host (T1543.003, T1053.005).
    * **Staging/Exfiltration:** Files staged in temporary directories, followed by network traffic indicative of large data transfer.
4.  **Privilege Check:** Confirm the operating system privileges of the running `sqlservr.exe` process.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1059.003 Confirmed):** Execution and Lateral Movement confirmed via database exploitation.
2.  **Scope the Incident:** The scope includes the **SQL Server host**, the **compromised SQL Login**, the **remote client host/IP**, and **all external C2 infrastructure** used by the payload.

---

## 3. Containment – Recommended Actions (Disabling the Vector and Credential Kill)

Containment must focus on immediately breaking the attacker's ability to execute commands and invalidating the compromised credentials.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected SQL Server host from the network using EDR (if possible) or network controls. **Note:** Ensure a temporary administrative channel remains for critical cleanup.
2.  **Disable `xp_cmdshell`:** **IMMEDIATELY** disable the execution vector:
    ```sql
    EXEC sp_configure 'show advanced options', 1;
    RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell', 0;
    RECONFIGURE;
    ```
3.  **Service/Agent Removal:** If persistence was created via the SQL Agent, disable/delete the malicious job. If the payload created a Windows Service, stop and delete it immediately.
4.  **Credential Revocation:** **IMMEDIATE** password reset/revocation for the compromised SQL Login used to initiate the attack. If the SQL Service Account itself is running with high privilege, plan to change its password and/or degrade its privileges immediately after initial containment.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the database configuration and adhere to the principle of least privilege.

1.  **Control Failure Analysis:** Identify which control failed: **Configuration Management** (`xp_cmdshell` was enabled), **Authentication** (weak SQL login password or exposed credentials), or **Least Privilege** (SQL Service Account was overly privileged).
2.  **Propose and Track Improvements:**
    * **Service Account Least Privilege:** Change the **SQL Server Service Account** from a domain administrator or LocalSystem account to a dedicated, low-privilege **Managed Service Account (MSA)** or virtual account. This is the most crucial step.
    * **Baseline Configuration:** Ensure a GPO or configuration baseline enforces **`xp_cmdshell` as disabled** on all production SQL servers.
    * **Network Segmentation:** Implement network rules to prevent the SQL Server host from initiating outbound connections to the internet, except for necessary services (e.g., patch servers). The SQL Server should only talk to client applications and approved internal resources.
    * **Auditing:** Implement enhanced SQL Server auditing to log all **`sp_configure`** calls, SQL Agent job creations, and failed logins.
3.  **Documentation and Knowledge Transfer:** Update internal playbooks, emphasizing that **SQL Server compromise is a critical path to domain compromise** if service accounts are over-privileged.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query focuses on the signature of `xp_cmdshell` execution: the SQL Server process (`sqlservr.exe` or `sqlagent.exe`) spawning a command shell (`cmd.exe` or `powershell.exe`).

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for SQL Server xp_cmdshell or Agent Execution (T1059.003)
DeviceProcessEvents
| where Timestamp > ago(7d)
// 1. Identify the Parent Process as the SQL Service or Agent
| where InitiatingProcessFileName in ("sqlservr.exe", "sqlagent.exe")
// 2. Identify the Child Process as a shell or staging utility
| where FileName in ("cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe")
| extend ParentAccount = InitiatingProcessAccountName
| extend ExecutedCommand = ProcessCommandLine
| project Timestamp, DeviceName, ParentAccount, InitiatingProcessFileName, FileName, ExecutedCommand, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```
Concluding Remarks: Database to Host Pivot

A SQL Server running a command via xp_cmdshell is a clear indication that an attacker has successfully pivoted from the database to the host operating system. The severity hinges entirely on the privileges of the SQL Service Account:

Low Privilege Service Account: The attacker's impact is contained to the local system and file system.

High Privilege Service Account (e.g., Domain Admin): This is a catastrophic event that provides the attacker a domain-wide foothold, allowing immediate lateral movement to other servers.

Your primary focus must be on disabling the xp_cmdshell vector and ensuring the SQL Service Account does not possess unnecessary host or domain privileges
