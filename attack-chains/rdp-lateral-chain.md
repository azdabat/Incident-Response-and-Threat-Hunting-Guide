# SOC Investigation Spine: RDP Lateral Movement – T1021.001

**Explanation:** This playbook analyzes the abuse of the **Remote Desktop Protocol (RDP)** for lateral movement. Once an attacker compromises an initial host and obtains credentials (via PtH, PtT, or dumping), they use the RDP client (`mstsc.exe`) to authenticate to peer systems. This is often an effective stealth technique because RDP traffic is common and expected in many corporate environments. The most reliable **Anchor Point** is the **successful RDP login** to a new host from a source IP address that should not be initiating the session or using an account that lacks administrative context for that peer system.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078.003 (Valid Accounts) | **Identity/Endpoint:** Attacker establishes a foothold and compromises a user account. | **File Event:** Presence of credential dumping tools (e.g., `mimikatz.exe`) on the source host. |
| **Execution / Credential Theft** | T1003 (OS Credential Dumping) | **Process/Identity:** Stolen credentials (plaintext or hash) are obtained from memory (LSASS) or configuration files. | **Process Anomaly:** `lsass.exe` accessed by a non-system process with read permissions. |
| **RDP Lateral Movement (ANCHOR)**| **T1021.001 (RDP)** | **Network/Identity:** Successful RDP login to a peer system from an unusual source IP or using an account outside of its typical usage context. | **Event ID 4624** (Successful Logon) on the target host, with **Logon Type 10** (RemoteInteractive) from an abnormal Source IP. |
| **Lateral Movement / Command** | T1059 (Command-Line) | **Process:** The RDP session is used to execute reconnaissance or payload delivery commands on the new target host. | **Process Event:** Execution of `cmd.exe` or `powershell.exe` on the target host immediately following the RDP logon. |
| **Impact / Data Staging** | T1074.001 (Local Data Staging) | **File:** Attacker stages files (e.g., malware, compressed archives) on the newly accessed host. | **File System Event:** Creation of suspicious files (e.g., `.zip`, `.rar`, `.exe` payload) in `C:\Users\Public` or temp directories. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Identity & Network IOCs

1.  **Logon Type 10 Anomaly (The RDP Tell):** The most critical IOC is the **Windows Security Event ID 4624** (Successful Logon) on the **target** machine. Focus on:
    * **Logon Type:** Must be **10 (RemoteInteractive)**.
    * **Source IP:** Check if the **Source Network Address** (the RDP client) is unusual. An admin account logging into a Domain Controller from a non-admin workstation is highly suspicious.
    * **Account Context:** The account used (e.g., a standard user) successfully logging into a high-value server (e.g., a database or file server) is anomalous.
2.  **RDP Session Spike:** Review network monitoring tools for a sudden **spike in RDP connections** originating from the initial compromised host to multiple peer systems, indicative of a pivot operation.
3.  **Authentication Failure Correlation:** A surge in **failed RDP login attempts (Event ID 4625)** immediately preceding the successful RDP login may indicate the attacker brute-forced or guessed the password/hash.

### Process and File IOCs

1.  **`mstsc.exe` Execution:** On the **source** (initial) host, check EDR/Process logs for the execution of the **`mstsc.exe`** (RDP client) process, potentially with command-line arguments specifying the target IP address. This confirms the attacker initiated the connection.
2.  **Process Activity on Target:** Once logged in via RDP, the attacker's actions are recorded as local process activity. Look for the remote user executing high-risk commands like `whoami`, `net group`, `ipconfig`, followed by file transfer attempts or execution of post-exploitation modules.
3.  **RDP History/Clipboard:** On the **source** host, check file system artifacts for files related to RDP connection history (`.rdp` files) or data that may have been copied via the clipboard (`rdpclip.exe` activity).

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Invalidate the stolen credentials and remove the threat from the host. | **Terminate all active RDP sessions** for the compromised account. **Force password reset** for the compromised account. **Isolate the initial source host.** |
| **RDP Policy** | **Restrict RDP Access:** Limit RDP access only to necessary administrative accounts and source hosts. | **Implement Firewall Rules** to block RDP (TCP/3389) between client workstations and sensitive servers. |
| **Authentication** | **Network Level Authentication (NLA):** Enforce NLA to require pre-authentication, adding a layer of security before the full RDP session is established. | Configure RDP hosts to **require Network Level Authentication** via Group Policy. |
| **Account Monitoring** | **Baseline Context:** Define a baseline for privileged account usage (time, location, source IP). | Configure SIEM alerts for **Logon Type 10** where the **Source IP is not within the defined administrative segment** for the target machine. |
