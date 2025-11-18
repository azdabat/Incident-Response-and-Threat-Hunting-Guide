# SOC Investigation Spine: Process Hollowing / PE-swap – T1055.012

**Explanation:** This playbook analyzes **Process Hollowing**, a sophisticated code injection technique that executes malicious code within the address space of a benign host process (e.g., `svchost.exe`, `explorer.exe`). The attacker initiates a legitimate process in a suspended state, uses API calls (`NtUnmapViewOfSection`, `WriteProcessMemory`) to replace the legitimate executable code with malicious code, and then resumes the thread. The most reliable **Anchor Point** is the **suspicious memory operation** performed by a non-standard parent process on a newly created, suspended child process.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1204 (User Execution) | **File/Endpoint:** User executes a dropper or loader payload (e.g., LNK file, malicious attachment). | **File System Event:** Creation of a new, unknown executable file in a temporary directory. |
| **Execution / Foothold** | T1055.012 (Process Hollowing) | **Process:** The dropper/loader process attempts to create a new process in a suspended state. | **Process Event:** **`CreateRemoteThread`** or **`CreateProcessInternal`** API calls with the **`CREATE_SUSPENDED`** flag. |
| **Hollowing / PE-swap (ANCHOR)**| **T1055.012 (Process Injection)** | **Memory/Process:** A parent process performs suspicious memory manipulation on a suspended child process. | **API Calls:** High volume of **`WriteProcessMemory`**, **`VirtualAllocEx`**, or **`NtUnmapViewOfSection`** calls targeting the suspended child process. |
| **Lateral Movement / Staging** | T1550 (Authentication Abuse) / T1083 (File Recon) | **Network/Identity:** The hollowed process is used to execute reconnaissance commands or perform credential harvesting. | **Process Anomaly:** The hollowed process (`explorer.exe` or `svchost.exe`) makes **outbound network connections** or executes terminal commands. |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2 Channel) | **Network:** The injected code establishes a C2 channel and exfiltrates data. | **Network Log:** Suspicious outbound connection from the legitimate host process (`explorer.exe`) to an external C2 IP/domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Memory IOCs

1.  **Process Creation & Suspension:** The most critical initial IOC is the **creation of a process in a suspended state**. Look for process creation events where the **`CREATE_SUSPENDED`** flag is explicitly set or the process thread is immediately suspended. The parent process that initiated this should be the focus of the investigation (the malicious loader/dropper).
2.  **Memory Manipulation API Calls:** The definitive sign of hollowing is the sequence of API calls used for memory modification. Look for the parent process calling:
    * **`NtUnmapViewOfSection`:** Used to erase the legitimate code from the child process's memory.
    * **`WriteProcessMemory`:** Used to write the malicious payload's code into the now-empty memory space.
    * **`SetThreadContext` / `ResumeThread`:** Used to redirect the execution flow to the malicious code and start the process.
3.  **Code Signature/Hash Mismatch:** After the injection, advanced EDR/Memory analysis tools can detect that the code running within the process's primary thread **does not match the digital signature or file hash** of the original executable on disk (the PE-swap).

### File, Network, and Identity IOCs

1.  **File Artifacts (Initial Dropper):** Analyze the file that started the attack chain. It is often an unknown, newly created executable or DLL that should be immediately quarantined and analyzed for its malicious intent.
2.  **Network Anomaly:** After the process resumes, the legitimate host process (e.g., `explorer.exe`) will make an **unusual outbound network connection**. The source process name will appear legitimate, but the target IP or domain will be the attacker's C2 server.
3.  **Identity Context:** Determine the **user context** under which the injection occurred. If the compromised user has local administrator rights, the attacker can target system processes for injection, making lateral movement easier.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Limit attacker execution and prevent persistence. | **Isolate the Host** immediately. **Kill the compromised process** (the hollowed child process) and the parent process (the dropper). |
| **Memory Protection** | **Enable EDR/AV Memory Protections:** Utilize security solutions that specifically monitor for and block suspicious memory operations. | Configure EDR to alert on **`WriteProcessMemory`** or **`NtUnmapViewOfSection`** calls against high-value system processes when initiated by non-system processes. |
| **Process Control** | **Code Integrity Policies:** Prevent the loading of unsigned code or the modification of process memory. | Use **Windows Defender Application Control (WDAC)** to enforce strong code integrity, limiting the ability of unsigned executables to run in the first place. |
| **Initial Access Prevention** | **Block High-Risk Files:** Prevent the execution of the initial dropper/loader. | Configure email and endpoint security to block file types commonly used for initial access (e.g., LNK, ISO, IMG, heavily obfuscated scripts). |
