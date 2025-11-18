# SOC Investigation Spine: SMB / PsExec-style ADMIN$ Lateral Movement – T1570 & T1569.002

**Explanation:** This playbook analyzes the technique of achieving remote code execution and lateral movement using the **Server Message Block (SMB)** protocol (TCP/445) and accessible **administrative shares** (`ADMIN\$`, `C\$`). Attackers utilize tools like PsExec, which drops a service executable on the target's `ADMIN\$` share, creates a temporary service to run the executable with high privileges, and then cleans up. This technique relies on stolen, valid credentials for authentication. The most reliable **Anchor Point** is the rapid sequence of **Network File Transfer (SMB traffic)** immediately followed by **Temporary Service Creation** and **Process Execution** on the target machine.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078 (Valid Accounts) | **Endpoint/Identity:** Attacker gains credentials (via PtH, PtT, or dumping) on the initial host. | **File Event:** Presence of credential dumping tools on the source host. |
| **Execution / Credential Theft** | T1003 (OS Credential Dumping) | **Process/Identity:** Stolen, often administrative, credentials are obtained and stored for use. | **Process Anomaly:** `lsass.exe` accessed by a non-system process with read permissions. |
| **Lateral Movement (ANCHOR)**| **T1570 (File Transfer) & T1569.002 (Service Execution)** | **Network/Process/Service:** A rapid, sequential burst of SMB file write, service creation, and execution on the target peer system. | **Target: Event ID 5140** (Network Share Access) followed by **Event ID 7045** (Service Creation) and **Event ID 4688** (Process Execution). |
| **Lateral Movement / Command** | T1059 (Command-Line) | **Process:** The executed payload (often the PsExec service executable) spawns a command shell to run commands. | **Process Anomaly:** The temporary service executable spawns `cmd.exe` or `powershell.exe` with suspicious arguments. |
| **Impact / Data Staging** | T1074.001 (Local Data Staging) | **File:** Attacker stages files or executes core impact payloads (e.g., encryption) on the peer system. | **File System Event:** Creation of suspicious files or bulk encryption activity on the target host. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Network & Process IOCs

1.  **Sequential Event Chain (The PsExec Tell):** The highest-fidelity IOC is correlating the following three events within seconds on the **target peer machine**, originating from the same **Source IP** (the initial compromised host):
    * **Network Write (SMB):** A file transfer over SMB (TCP/445) to the `ADMIN\$` or `C\$` share, creating a file with a unique, randomized, and short name (e.g., `C:\Windows\PsExecSvc.exe` or `C:\Windows\psexec-nnnn.exe`).
    * **Service Creation (Event ID 7045):** A new Windows Service is created with a temporary name (e.g., "PsExecSvc") and the **`ImagePath`** pointing to the file dropped in step 1.
    * **Process Execution (Event ID 4688):** The newly created service starts, executing the dropped payload, often as **SYSTEM** or a high-privilege account.
2.  **Service Deletion/Cleanup:** Look for a corresponding **Service Deletion (Event ID 7036/7034)** and **File Deletion** immediately after the command completes, indicating the attacker successfully cleaned up their temporary persistence mechanism.
3.  **Authentication Context:** The **Logon Type 3 (Network)** authentication event on the target machine will show the **Source IP** and the **stolen account** used to authenticate over SMB/RPC to access the administrative shares.

### Identity and File IOCs

1.  **Stolen Credentials:** The account used for the SMB logon must be traced back to the initial access host to confirm it was **compromised via credential dumping** (LSASS access) or **ticket theft** (Kerberos PtT).
2.  **File Hash Analysis:** The file hash of the dropped executable (e.g., `psexec-nnnn.exe`) should be obtained and checked against known legitimate PsExec hashes. If the hash is custom (a modified or custom binary), it confirms the attacker is using a custom execution tool.
3.  **Network Protocol:** Analyze network telemetry for a burst of **SMB traffic** (File Write, Service Creation) followed by **RPC traffic** (Service Control Manager calls) originating from the source host targeting the peer.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Invalidate credentials and remove the means of lateral movement. | **Force password reset** for the administrative account used for the attack. **Isolate both the source and target hosts** to contain the threat. |
| **Network Control** | **Restrict SMB Traffic:** Limit or block SMB traffic between non-administrative tiers or unauthorized client-to-client communication. | **Implement Host Firewalls** to block inbound SMB (TCP/445) access from standard client subnets to peer hosts, allowing it only to/from approved administrative hosts. |
| **Privilege Control** | **Block PsExec-Style Tools:** Use EDR or Application Control to block the execution of PsExec and similar tools, or require strict command-line argument whitelisting. | Configure EDR to alert on **`sc.exe` or `New-Service` execution** when preceded by a file write to the `ADMIN\$` share. |
| **Authentication** | **Local Admin Password Solution (LAPS):** Ensure local administrator account credentials are unique across every host to prevent PtH lateral movement across different machines. | **Implement LAPS** across all endpoints and servers to randomize local admin passwords. |
