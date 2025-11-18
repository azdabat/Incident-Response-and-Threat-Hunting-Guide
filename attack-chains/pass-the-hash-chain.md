#  Pass-the-Hash (PtH) Pattern – T1550.002: Lateral Movement

**Explanation:** This playbook analyzes the **Pass-the-Hash (PtH)** technique, a critical lateral movement method where an attacker authenticates to a remote service (like RDP, SMB, or WinRM) using a captured NTLM hash of a user's password instead of the password itself. This is only possible because the NTLM protocol hashes the password *before* sending it over the wire. The most reliable **Anchor Point** is the **successful authentication event** on a target peer system that lacks a corresponding NTLM negotiation (Type 1 or Type 2 messages) or is immediately preceded by the compromised account's hash being dumped.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078.003 (Valid Accounts) | **Identity/Network:** Attacker compromises an initial endpoint, typically via a phishing payload. | *(User successful login)* `Event ID 4624` on initial access host. |
| **Execution/Foothold** | T1003.001 (LSASS Memory) | **Process/File:** Credentials (hashes) are stolen from memory (LSASS) or the SAM database. | **File: `lsass.dmp`** creation; **Process: `Mimikatz.exe`** or **`procdump.exe`** execution. |
| **Pass-the-Hash (ANCHOR)**| **T1550.002 (PtH)** | **Identity/Network:** Successful remote authentication using the stolen hash on a **peer system** (no password/key sent). | **Event ID 4624** (Successful Logon) on a target host, with **Logon Type 3** (Network) or **Logon Type 10** (RemoteInteractive) via NTLM. |
| **Lateral Movement** | T1021.001 (RDP) / T1021.006 (WinRM) | **Network:** The attacker uses RDP/WinRM to fully interact with the peer system using the stolen hash. | **Network Traffic:** High-volume RDP/SMB traffic originating from the compromised machine to a high-value peer server. |
| **Impact / Exfiltration** | T1074.001 (Local Data Staging) | **File:** Data is copied/staged on the lateral server before final compression and exfiltration. | **File: `staged_data[.]zip`** or bulk file reads/writes on the target system. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Identity & Authentication IOCs

1.  **Authentication Anomaly (The PtH Tell):** The highest-fidelity IOC is checking **Windows Security Event ID 4624** (Successful Logon) on the *target* peer machine. Look for the logon method: a PtH event typically results in a **Logon Type 3 (Network)** or **Logon Type 10 (RemoteInteractive)**, often lacking the preceding NTLM Type 1/2 negotiation messages in the network capture, or simply showing a **successful NTLM authentication without an initial password attempt**.
2.  **Source IP Discrepancy:** The PtH authentication event will originate from a **Source IP** that is the **initially compromised endpoint**, not the user's primary workstation. The compromised account is now accessing systems it should not be touching.
3.  **Authentication Failure Spike:** Immediately following credential dumping, look for a temporary spike in **NTLM authentication failures** across the network as the attacker potentially tries various accounts/hashes, followed by the successful PtH event.

### Process, File, and Network IOCs

1.  **Preceding Credential Dump:** On the **source** (initial) host, the PtH event must be preceded by artifacts indicating credential theft (e.g., execution of tools like **`sekurlsa::logonpasswords`** in Mimikatz, or the creation of an **`lsass.dmp`** file).
2.  **Command-Line Artifacts:** Look for the execution of utilities on the source host specifically designed for PtH, such as **`psexec.exe
