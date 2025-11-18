# 🔑 LSASS Credential Dumping Behaviour – T1003.001

**Explanation:** This playbook analyzes one of the highest-value post-exploitation actions: the theft of credentials from the **Local Security Authority Subsystem Service (LSASS)** process memory. This attack utilizes living-off-the-land techniques (like **`procdump.exe`** or **`taskmgr.exe`**) or tools like Mimikatz to create a dump file. The most reliable **Anchor Point** is the combination of **suspicious process access** to LSASS and the subsequent **creation of a large memory dump file**.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.002 (Spearphishing Link) | **Identity/Network:** User clicks link and downloads malicious payload. | (User opens payload; C2 agent executes) |
| **Execution/Privilege** | T1059.003 (PowerShell) | **Process:** Execution of scripts to elevate privileges (e.g., UAC bypass) to **SYSTEM**. | `powershell.exe -c "Get-System"` |
| **LSASS Dumping (ANCHOR)**| **T1003.001 (LSASS Memory)** | **Process:** Execution of a utility attempting to read or dump the memory of **`lsass.exe`**. | `C:\Tools\procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp` |
| **Staging/Transfer** | T1560.001 (Archive via Utility) | **File:** Creation of a compressed file containing the sensitive memory dump. | `C:\Windows\System32\cmd.exe /c "rar a C:\temp\creds.rar C:\temp\lsass.dmp"` |
| **Lateral Movement / Impact** | T1550.002 (Pass the Hash) | **Identity:** Stolen credentials used for lateral authentication (RDP, WinRM). | `pth -u Administrator -d DOMAIN -h HASH-VALUE mstsc.exe /v:PEER-SERVER` |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & File IOCs

1.  **LSASS Access:** The highest-fidelity IOC is security tooling detecting a non-standard process (e.g., **`procdump.exe`**, **`cscript.exe`**, or a suspicious renamed executable) opening **`lsass.exe`** with **`PROCESS_VM_READ`** or **`PROCESS_DUP_HANDLE`** access rights.
2.  **Parent-Child Anomaly:** Look for tools like `taskmgr.exe` or `werfault.exe` being spawned by an unexpected parent process (like `cmd.exe` or a malicious DLL) with arguments suggesting a dump action.
3.  **Memory Dump Artifact:** The sudden creation of a **large file (100MB to 500MB)**, often named **`lsass.dmp`** or similar, in a temporary or user profile directory is a critical file IOC.

### Identity and Network IOCs

1.  **Authentication Failure Spike:** Immediately following the dumping action, look for a spike in **authentication failures** on peer systems, followed by sudden, successful authentication using the **stolen credentials** (Pass-the-Hash/Ticket).
2.  **File Staging/Exfil:** Network telemetry should be checked for outbound connections from the compromised host, attempting to exfiltrate the newly created, large dump file. This often involves a compressed archive file being uploaded (see the Data Exfiltration playbook).
3.  **Registry Key:** If Mimikatz was used for persistence, check registry keys associated with authentication, such as the `WDigest` key, which may have been modified.
