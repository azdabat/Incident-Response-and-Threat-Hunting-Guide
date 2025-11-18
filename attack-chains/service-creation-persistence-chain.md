# SOC Investigation Spine: Malicious Service Creation Persistence – T1543.003

**Explanation:** This playbook analyzes the technique of achieving persistence by installing a **new Windows Service** (`CreateService`) or modifying an existing service's parameters (`ChangeServiceConfig`). Attackers use utilities like the Service Control Manager (`sc.exe`), PowerShell cmdlets, or direct API calls to configure the service to execute their malicious binary, typically under the high-privilege **LocalSystem** account. The most reliable **Anchor Point** is the **creation of the new service**, evidenced by a high-fidelity System Event Log ID.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078 (Valid Accounts) / T1068 (Exploitation for Privilege) | **Endpoint/Identity:** Attacker gains code execution and achieves **Administrator or SYSTEM** privileges (required for service creation). | **Event ID 4672** (Special privileges assigned to new logon). |
| **Execution / Foothold** | T1059 (Command-Line Scripting) | **Process:** The attacker stages the payload and executes the command to create the new service. | **File Creation Event:** Malicious executable (`Updater.exe`) dropped in a non-standard location (e.g., `C:\ProgramData`). |
| **Service Creation (ANCHOR)**| **T1543.003 (Windows Service)** | **System Event Log/Process:** **Execution** of `sc.exe` or PowerShell's `New-Service` cmdlet, or detection of the corresponding API call (`CreateService`). | **System Event ID 7045** (A service was installed in the system) or EDR API Hook on **`CreateServiceA/W`**. |
| **Execution After Boot** | T1059 (Scripting) | **Process:** The malicious service starts, and its payload executes under the SYSTEM account. | **Process Anomaly:** The **Service Control Manager (`services.exe`)** process spawns the malicious service executable as a child process. |
| **Impact / Data Staging** | T1074.001 (Local Data Staging) | **File/Identity:** The payload, now running as SYSTEM, collects data or executes high-privilege tasks. | **File Event:** Creation of a compressed archive or log file in a hidden directory. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Service IOCs

1.  **Service Creation Event:** The most critical IOC is the **Windows System Event ID 7045** (Service Control Manager event source) on the target host. Focus on the following attributes within this log entry:
    * **Service Name:** Suspicious or generic names (e.g., "WinServiceHelper," "DeviceDriverUpdate").
    * **File Name/Path:** The `ImagePath` attribute points to an **unusual file path** (e.g., `C:\Users\Public`, `C:\ProgramData`) rather than `C:\Windows\System32`.
    * **Service Account:** The `Service Start Name` is often **LocalSystem** (`NT AUTHORITY\SYSTEM`).
2.  **Command-Line Execution:** Look for the command-line execution of **`sc.exe`** with the `create` subcommand, or PowerShell's `New-Service`, including arguments that define the service binary path, DisplayName, and StartType (often `auto` or `demand`).
3.  **Execution Chain Anomaly:** The malicious service's execution will appear as a **legitimate process (`services.exe`)** acting as the **Parent Process** spawning the **malicious binary** (the `ImagePath` executable). This process will typically run with a **high integrity level** (SYSTEM).

### File, Network, and Identity IOCs

1.  **Malicious Binary Artifacts:** Analyze the file identified in the Service `ImagePath`. Check its file hash, digital signature (will likely be missing), entropy (may be high if packed), and the presence of suspicious imported functions (e.g., networking APIs, encryption).
2.  **File System Dropping:** The creation of the malicious service executable file (the payload) must be traced. Look for the file being created in a directory typically used by non-system applications, indicating an attacker-controlled drop location.
3.  **Network Activity:** Once the service starts, check network logs for an **outbound connection** initiated by the service executable's process name (e.g., `Updater.exe`) to an external C2 IP or domain. This connection will often persist across reboots, providing a long-term communications channel.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Disable the malicious service, remove the persistence, and remove the payload. | **Stop the service** (`sc stop <ServiceName>`) and **delete the service** (`sc delete <ServiceName>`). **Quarantine the payload executable** located at the `ImagePath`. |
| **Privilege Control** | **Principle of Least Privilege:** Strictly limit which accounts can perform service creation/modification. | Use **Service Control Manager (SCM) security descriptors** to limit service creation rights to necessary administrative groups only. |
| **Monitoring** | **Mandate Detailed Logging:** Ensure that both service creation and service control events are captured. | Verify that **System Event ID 7045** (Service Installation) and **System Event ID 7040** (Service Start Type Change) are fully ingested into the SIEM for immediate alerting. |
| **Application Control** | **Prevent Execution:** Block the execution of the payload via its hash or path. | Use **Windows Defender Application Control (WDAC)** or **AppLocker** to block the execution of unsigned executables from user-writable directories (`C:\ProgramData`, `C:\Users\`). |
