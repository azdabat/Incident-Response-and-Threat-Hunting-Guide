# SOC Investigation Spine: Suspicious PowerShell Script Abuse – T1059.001

**Explanation:** This playbook analyzes the abuse of the **PowerShell** scripting engine for malicious purposes, often bypassing traditional file-based security controls by executing commands or scripts **directly in memory** (fileless execution). The attack typically involves highly obfuscated or encoded command-line arguments. The most reliable **Anchor Point** is the **execution of PowerShell** with suspicious command-line parameters, particularly those utilizing encoding or hidden windows.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1190 (Exploit) | **Endpoint/Network:** User interaction or vulnerability exploitation leads to initial payload execution. | **Email Log:** Delivery of malicious attachment (e.g., LNK, ISO) that initiates the chain. |
| **Execution / Foothold** | T1059.001 (PowerShell) | **Process:** A suspicious parent process (e.g., Office app, `wscript.exe`) spawns `powershell.exe`. | **Process Anomaly:** `WINWORD.EXE` Parent → `POWERSHELL.EXE` Child. |
| **PowerShell Abuse (ANCHOR)**| **T1027 (Obfuscated Files/Info)** | **Process/PowerShell Logs:** Execution of `powershell.exe` with highly suspicious command-line flags. | **Command Line IOC:** Use of flags like `-EncodedCommand`, `-W Hidden`, or `-NoP -NonI -Exec Bypass`. |
| **Lateral Movement / Staging** | T1021 (Remote Services) / T1574.002 (DLL Search Order) | **Network/Identity:** PowerShell is used for internal reconnaissance (`Invoke-Scan`), credential harvesting, or WMI/WinRM lateral movement. | **Network Flow:** Outbound connection from `powershell.exe` process to a peer server (SMB, RDP, WinRM ports). |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2 Channel) | **Network:** PowerShell script exfiltrates gathered data to an external C2 server. | **Network Log:** Outbound HTTPS/HTTP traffic from `powershell.exe` or its downloaded payload to an untrusted external IP. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Script IOCs

1.  **Command-Line Encoding:** The most critical IOC is the presence of PowerShell flags used for evasion:
    * **`-EncodedCommand` (`-e` or `-enc`):** Indicates the attacker is attempting to hide the actual code being executed. The encoded string must be decoded for analysis.
    * **`-WindowStyle Hidden` (`-W Hidden`):** Indicates the attacker is trying to hide the execution window from the user.
    * **`-NoProfile`, `-NonInteractive`, `-ExecutionPolicy Bypass`:** Flags used to ensure the script executes quickly without security hindrance.
2.  **Parent Process
