#  Log Clearing and Shadow Copy Deletion – T1070.004 / T1490

**Explanation:** This playbook analyzes the critical post-compromise stages where an adversary attempts to destroy evidence and inhibit recovery. The key **Defense Evasion (T1070.004)** action is **Log Clearing** (erasing Windows Event Logs). The key **Impact (T1490)** action is **Shadow Copy Deletion**, which prevents system restore points from being used against ransomware. The execution of the specific Windows utilities for these tasks serves as the most reliable **Anchor Point** for detection.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 (Phishing) | **Identity:** Compromised user account/initial execution context. | (User executes initial loader or C2 agent) |
| **Execution/Privilege** | T1059.003 (PowerShell) | **Process:** C2 agent establishes elevated privileges (T1548.002). | `whoami /priv` (Attacker confirming privileges) |
| **Log Clearing (ANCHOR)** | **T1070.004 (Clear Event Logs)** | **Process:** Execution of **`wevtutil.exe`**, `cmd.exe`, or `powershell.exe` with clearing flags. | `cmd.exe /c wevtutil cl System && wevtutil cl Security && wevtutil cl Application` |
| **Recovery Inhibition (ANCHOR)**| **T1490 (Delete Shadow Copies)** | **Process:** Execution of **`vssadmin.exe`** with deletion flags. **Command:** `delete shadows`. | `vssadmin delete shadows /all /quiet` |
| **Final Impact** | T1486 (Data Encrypted) | **File:** Spikes in file modification and creation of high-entropy files. | (Ransomware module executes immediately after deletion) |
| **Post-Cleanup** | T1565.001 (Data Destruction) | **File:** Deletion of all C2 tools and dropped artifacts. | `cmd.exe /c del C:\temp\*.exe` |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Command IOCs

1.  **Shadow Copy Deletion Command:** The single highest-fidelity IOC is the command line execution of **`vssadmin.exe delete shadows /all`** or any script containing similar WMI/PowerShell commands (`Get-WmiObject -Class Win32_Shadowcopy | Remove-WmiObject`).
2.  **Event Log Clearing Command:** Command line execution of **`wevtutil.exe cl`** (clear log) against core logs (`System`, `Security`, `Application`).
3.  **Process Tree:** The execution of `vssadmin.exe` or `wevtutil.exe` must be traced back to the non-standard, malicious parent process (i.e., not a standard Windows update or management process).

### System and Identity IOCs

1.  **Event ID 1102:** While the adversary attempts to clear logs, the log clearing action itself often generates **Event ID 1102** (The audit log was cleared). This artifact may exist in memory or upstream SIEM if detected before full destruction.
2.  **Required Privileges:** Both `vssadmin delete shadows` and `wevtutil cl Security` require **Administrator-level privileges**. The user identity executing these commands must be immediately flagged for compromise.
3.  **Immediate Follow-up Activity:** Look for a dramatic increase in file I/O operations (Ransomware execution) occurring within seconds or a minute of the `vssadmin` command completing. This confirms the **Shadow Copy Deletion** was a precursor to the final payload.
