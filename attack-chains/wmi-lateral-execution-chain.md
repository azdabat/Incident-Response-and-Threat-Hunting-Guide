# SOC Investigation Spine: WMI-based Lateral Execution – T1021.006

**Explanation:** This playbook analyzes the abuse of **WMI/DCOM** for remote code execution and lateral movement. The attacker utilizes compromised credentials to connect to the target peer system via WMI (typically TCP/135 for initial binding, followed by ephemeral ports) and executes commands using WMI methods (e.g., `Win32_Process.Create()`). This execution chain is often fileless on the target system, leveraging the legitimate **WMI Provider Host (`WmiPrvSE.exe`)** to spawn the malicious command, granting the payload the high-privilege context of the WMI service. The most reliable **Anchor Point** is the **execution of a command shell** on the target peer system with **`WmiPrvSE.exe`** as the parent process.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078 (Valid Accounts) | **Endpoint/Identity:** Attacker gains code execution and obtains administrative credentials on the source host. | **File Event:** Presence of credential dumping tools (e.g., `mimikatz.exe`) on the source host. |
| **Execution / Credential Theft** | T1003 (OS Credential Dumping) | **Process/Identity:** Stolen, often administrative, credentials are obtained for use in the remote WMI session. | **Process Anomaly:** `lsass.exe` accessed by a non-system process with read permissions. |
| **Lateral Execution (ANCHOR)**| **T1021.006 (WMI)** | **Network/Process/Command:** Remote command execution via WMI method call (`Win32_Process.Create`). | **Source: Command Line IOC:** `wmic.exe /node:<IP> process call create ...` |
| **Execution on Target** | T1059 (Command-Line) | **Process/WMI Logs:** Target system spawns a process based on the remote command. | **Target: Process Anomaly:** **`WmiPrvSE.exe` Parent** → **`cmd.exe` or `powershell.exe` Child**. |
| **Impact / Persistence** | T1546.003 (WMI Event Subscription) / T1041 (Exfil) | **WMI/Registry/Network:** Payload establishes persistence or initiates C2 communication. | **WMI-Activity Log ID 5858/5859:** Creation of a permanent WMI event subscription for persistence. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & WMI IOCs

1.  **Process Chain Anomaly (The WMI Tell):** The definitive indicator on the **target peer system** is the unique process tree:
    * **Parent Process:** **`WmiPrvSE.exe`** (WMI Provider Host, runs with high privileges, often SYSTEM).
    * **Child Process:** **`cmd.exe`**, **`powershell.exe`**, or the final payload executable.
    * **Context:** This process relationship indicates command execution initiated by a remote WMI call. The process execution logs (Event ID 4688) must be reviewed to capture the full command line of the child process.
2.  **Source Command Line:** On the **initial compromised host**, look for the execution of WMI client tools with the remote node specified:
    * **`wmic.exe` IOC:** Execution of `wmic.exe /node:<TargetIP>` followed by `process call create ...`.
    * **PowerShell IOC:** Execution of `powershell.exe` with cmdlets like `Invoke-WmiMethod` or `Invoke-CimMethod` targeting `Win32_Process`.
3.  **WMI-Activity Logs (Target):** Review the **Microsoft-Windows-WMI-Activity/Operational Log** on the **target peer system**. Events in this log (e.g., Event ID 5858) will detail the **method calls** and the **user identity** that initiated the remote WMI action.

### Network and Identity IOCs

1.  **Network Protocol & Ports:** Analyze network flow logs for connections:
    * **Initial Binding:** TCP connection to the **target host on port 135 (RPC/DCOM)**, followed by negotiation to an **ephemeral port** for the WMI traffic.
    * **Source/Destination:** Connection originating from the **source host IP** using the client tool (e.g., `wmic.exe` or `powershell.exe`) and destined for the target.
2.  **Authentication Context:** Check **Security Event ID 4624** (Successful Logon) on the **target peer system**. The logon is typically **Logon Type 3 (Network)** and uses the **stolen administrative account**. This confirms the credentials used for the remote execution.
3.  **Post-Execution Network Traffic:** The payload (the command executed by the WMI chain) will attempt C2 communication. Monitor network logs for outbound connections from the **payload process** to external, suspicious IP addresses or domains.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Invalidate credentials and remove the means of remote execution. | **Force password reset** for the compromised account used for lateral movement. **Terminate the malicious processes** spawned by `WmiPrvSE.exe`. **Isolate the source and target hosts**. |
| **Process Control** | **Restrict WMI Execution:** Prevent the WMI service from spawning unnecessary child processes. | Configure **EDR rules** to alert/block **`WmiPrvSE.exe` from spawning any process** that is a command interpreter (`cmd.exe`, `powershell.exe`) or a networking utility (`certutil.exe`). |
| **Network Access Control** | **Restrict WMI/DCOM:** Limit inbound RPC/DCOM and WMI ports to authorized administrative hosts. | **Implement Host Firewalls** on critical servers to restrict inbound TCP/135 and the high ephemeral ports range to only trusted jump boxes or administrative subnets. |
| **Logging and Auditing** | **Mandate Detailed WMI/Process Logging:** Ensure full visibility into remote command execution. | **Enable and Ingest** the **Microsoft-Windows-WMI-Activity/Operational Log** and enforce **PowerShell Script Block Logging (4104)** to capture the full payload executed remotely. |
