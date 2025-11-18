# 📦 Archive-based Data Staging (T1560.001) Attack Chain

**Explanation:** This playbook analyzes the use of legitimate archiving utilities (like **7z.exe**, **WinRar.exe**, or **Rar.exe**) to stage sensitive data. The attacker compresses a large volume of files into a single, often password-protected, archive. This step is a high-confidence precursor to exfiltration, as it minimizes the volume of network transactions and enables **Defense Evasion (T1036)** by concealing the contents. The **Staging** event is the most reliable **Anchor Point** for detection.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 (Phishing) | **Network:** Malicious URL/IP accessed via browser/email. | (User opens malicious attachment) |
| **Execution/Foothold** | T1059.003 (PowerShell) | **Process:** `powershell.exe` with base64 encoded command. | `powershell.exe -NoP -NonI -Exec Bypass -e SQBFAFgAKAAoAEkAbgB2AG8AawBlAC0ATQB...` |
| **Discovery** | T1083 (File Discovery) | **Process:** High-volume file enumeration (`Get-ChildItem`, `dir /s`). | `cmd.exe /c dir /s "C:\Users\Target\Documents" > C:\temp\files_to_steal.txt` |
| **Archive Staging (ANCHOR)** | **T1560.001 (Archive via Utility)** | **Process/Command:** `7z.exe` or `WinRar.exe` with password flag (`-p`). **File:** Creation of large archive (e.g., > 100MB). | `"C:\Program Files\7-Zip\7z.exe" a -mx=9 -pSecureKey123 C:\temp\Q3_Data_Final.7z @C:\temp\files_to_steal.txt` |
| **Lateral Movement (Optional)** | T1021 (Remote Services) | **Network:** Outbound SMB (Port 445) from victim to staging host. | `cmd.exe /c copy C:\temp\Q3_Data_Final.7z \\FileServer\Drops` |
| **Impact/Exfiltration** | T1041 (Exfiltration Over C2) | **Network:** High volume of outbound traffic (443, 80) from C2 process. | (C2 agent initiates large upload of `Q3_Data_Final.7z` to external IP) |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Command IOCs

1.  **Archive Command Line:** Detection of **`7z.exe`**, **`WinRar.exe`**, or **`Rar.exe`** containing the **`-p` (password)** or **`-r` (recursive)** flags.
2.  **Parent-Child Relationship:** The malicious C2 process (e.g., `powershell.exe`) is the **Immediate Parent** of the archiving utility.
3.  **Cleanup Attempt:** Execution of `cmd.exe /c del C:\temp\*.7z` or `cipher /w:C:\temp` immediately after exfiltration.

### File and System IOCs

1.  **File Creation Anomaly:** Detection of a compressed file (`*.7z`, `*.rar`) being written to a temporary or public user directory (`C:\temp`, `C:\Users\Public`).
2.  **Size Anomaly:** A compressed file over **50MB** created rapidly, coinciding with high Disk Write operations.
3.  **Compromised Identity:** The user account executing the entire chain must be flagged for session revocation and credential reset.
