# SOC Investigation Spine: WinRM-based Lateral Execution – T1021.006

**Explanation:** This playbook analyzes the abuse of **Windows Remote Management (WinRM)** for lateral movement. Attackers use compromised, valid credentials (often administrative) to connect to a target peer system via WinRM (TCP/5985 or 5986). This allows them to execute arbitrary commands, scripts, or deploy secondary payloads remotely. The execution often uses PowerShell Remoting, resulting in a **`wsmprovhost.exe`** process spawning a PowerShell shell on the target system. The most reliable **Anchor Point** is the **successful remote logon event via WinRM** followed immediately by the **execution of a suspicious command shell** on the target.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078 (Valid Accounts) | **Endpoint/Identity:** Attacker compromises an initial host and obtains administrative credentials (via PtH, PtT, or dumping). | **File Event:** Presence of credential dumping tools (e.g., `mimikatz.exe`) on the source host. |
| **Execution / Credential Theft** | T1003 (OS Credential Dumping) | **Process/Identity:** Stolen, often administrative, credentials are obtained and stored for use in the WinRM session. | **Process Anomaly:** `lsass.exe` accessed by a non-system process with read permissions. |
| **Lateral Execution (ANCHOR)**| **T1021.006 (WinRM)** | **Network/Identity/Process:** Successful WinRM logon to a peer, followed by remote command execution. | **Target: Event ID 4624** (Successful Logon) with **Logon Type 3** (Network), followed by **Event ID 4688** (Process Creation) with parent **`wsmprovhost.exe`**. |
| **Lateral Movement / Command** | T1059.001 (PowerShell) | **Process/PowerShell Logs:** The remote PowerShell session executes reconnaissance or payload delivery commands. | **Target: Event ID 4104** (PowerShell Script Block Logging) containing encoded or suspicious code executed by the `wsmprovhost.exe` chain. |
| **Impact / Data Staging** | T1074.001 (Local Data Staging) | **File:** Attacker stages files or executes core impact payloads on the peer system. | **Target: File System Event:** Creation of suspicious files (e.g., `.exe` payload) in `C:\Windows\Temp` by the remotely executed process. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Identity & Process IOCs

1.  **WinRM Logon Event:** The most critical IOC is the **Windows Security Event ID 4624** (Successful Logon) on the **target** peer machine. Focus on:
    * **Logon Type:** Must be **3 (Network)**, as WinRM uses network authentication.
    * **Source IP:** Check if the **Source Network Address** (the RDP client) is unusual. An administrative account logging into a critical server from a standard client workstation is suspicious.
    * **Authentication:** WinRM often uses Kerberos, so check the preceding **Kerberos TGT/ST requests (Event ID 4768/4769)** to trace the ticket usage.
2.  **Process Chain Anomaly (The WinRM Tell):** On the target peer, the remote execution will manifest as a unique process chain:
    * **Parent Process:** **`wsmprovhost.exe`** (the WinRM host process).
    * **Child Process:** **`powershell.exe`**, **`cmd.exe`**, or the final payload executable.
    * **Context:** The execution of a command shell as a direct child of `wsmprovhost.exe` is the definitive sign of a remote execution via WinRM/PSRemoting.
3.  **PowerShell Script Block Logging (Target):** Review **PowerShell Event ID 4104** for scripts executed on the target by `wsmprovhost.exe`. This often captures the **decoded, malicious payload** or the reconnaissance commands (e.g., `Invoke-Mimikatz`, `Get-LocalGroupMember`) that the attacker ran remotely.

### Network and File IOCs

1.  **Network Flow Protocol:** Analyze network flow logs (NetFlow, Firewall) for **WinRM traffic** (typically TCP/5985 or 5986) originating from the source host and destined for the target. Look for a spike in this traffic volume immediately preceding the logon event.
2.  **Source Process on Client:** On the **source** (initial) host, check EDR/Process logs for the execution of the client tools used to initiate the connection: **`powershell.exe`** with **`-C Enter-PSSession`** or **`-C Invoke-Command`** flags, or the external utility **`winrm.exe`**.
3.  **File Staging:** Look for file creation events on the **target** machine where the file is created by the `powershell.exe` process spawned by `wsmprovhost.exe`, often indicating the downloading or dropping of a persistent payload.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Invalidate credentials and remove the means of remote execution. | **Force password reset** for the compromised account. **Terminate the WinRM session** on the target. **Isolate both the source and target hosts** to contain the threat. |
| **Network Access Control** | **Restrict WinRM Access:** Limit which hosts can initiate WinRM connections. | **Implement Host Firewalls** to block inbound WinRM ports (TCP/5985, 5986) from client workstations to sensitive servers, allowing it only from authorized jump boxes/administrative hosts. |
| **Logging and Auditing** | **Mandate Detailed Logging:** Ensure full visibility into remote command execution. | **Enforce PowerShell Script Block Logging (4104)** and **Module Logging (4103)** system-wide. Configure high-severity alerts for `wsmprovhost.exe` spawning suspicious child processes. |
| **Authentication** | **Tiered Access Model:** Prevent administrative accounts from logging into low-tier client workstations. | Enforce a strict **Tiered Administrative Access Model** to prevent credential theft that can be used for WinRM lateral movement into higher tiers. |
