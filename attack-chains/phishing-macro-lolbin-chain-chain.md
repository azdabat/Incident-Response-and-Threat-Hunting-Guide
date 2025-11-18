# SOC Investigation Spine: Phishing → Office Macro → LOLBIN Chain – T1059.005 & T1218

**Explanation:** This playbook analyzes a multi-stage execution chain starting with a phishing email that delivers a Microsoft Office document containing a malicious VBA Macro. The Macro's primary purpose is to invoke a system LOLBIN (e.g., `mshta.exe`, `certutil.exe`, `bitsadmin.exe`) to execute, download, or decode a secondary payload. The most reliable **Anchor Point** is the **suspicious process anomaly** where a Microsoft Office application spawns a terminal process or an unrelated Windows utility.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 (Spearphishing Attachment) | **Email/File:** User opens a malicious attachment (e.g., `Invoice.docm`, `Quote.xls`). | **Email Log:** Delivery of attachment with suspicious VBA/macro content. |
| **Macro Execution** | T1137 (Office Application Startup) | **Process/File:** Office application (Word/Excel) executes the malicious VBA macro. | **Process Event:** `WINWORD.EXE` or `EXCEL.EXE` accessing the network or spawning a non-standard child process. |
| **LOLBIN Execution (ANCHOR)**| **T1218 (Signed Binary Proxy)** | **Process:** A legitimate Office process spawns a suspicious child LOLBIN (`mshta.exe`, `rundll32.exe`, `cmd.exe`). | **Process Anomaly:** `WINWORD.EXE` Parent → `CMD.EXE` Child → `MSHTA.EXE` Grandchild. |
| **Download/C2** | T1105 (Ingress Tool Transfer) | **Network:** The LOLBIN makes an outbound connection to download the final payload from a Command and Control (C2) server. | **Network Log:** Outbound connection from a LOLBIN process (`powershell.exe`, `bitsadmin.exe`) to an external C2 IP or domain. |
| **Impact / Persistence** | T1547.001 (Registry Run Keys) | **Registry/File:** The final payload executes and establishes persistence (e.g., dropping a DLL or setting a Run key). | **Registry Event:** Modification of a **Run key** (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`). |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & File IOCs

1.  **Process Anomaly (The LOLBIN Tell):** The most critical IOC is the **process creation chain** recorded by the EDR/Endpoint logs. Look for **Microsoft Office applications** (`WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`) acting as the **Parent Process** of an unexpected child, such as:
    * **Terminal/Scripting:** `CMD.EXE`, `POWERSHELL.EXE`, `CSCRIPT.EXE`
    * **LOLBINs:** `MSHTA.EXE` (executing HTML/JScript), `CERTUTIL.EXE` (downloading/decoding), `BITSADMIN.EXE` (downloading).
2.  **File IOCs (Macro Artifacts):** The file that initiated the chain (the Office document) must be analyzed for the presence of **VBA code** and specific functions used for spawning processes (`Shell`, `CreateObject`).
3.  **LOLBIN Command Line:** Analyze the **command
