# SOC Investigation Spine: WSL-based Execution and Scripting – T1202 & T1059.004

**Explanation:** This playbook analyzes the use of the **Windows Subsystem for Linux (WSL)** as a **proxy execution environment** (T1202). The attacker executes the `wsl.exe` binary on the Windows host to launch a Linux shell (`bash`) or a script, allowing them to perform actions like C2 communication, payload decoding, and reconnaissance using native Linux utilities. This technique is often fileless on the Windows side and highly evasive, as the primary malicious activity resides within the separate Linux process tree. The most reliable **Anchor Point** is the **execution of `wsl.exe` with suspicious command-line arguments** that pass in encoded or high-entropy Linux commands.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1059 (Execution) | **Windows Host:** Dropper executes to stage the Linux script or initiate the WSL command. | **Process Event:** Execution of a process (e.g., `cmd.exe`, `powershell.exe`) that launches `wsl.exe`. |
| **Execution / Foothold** | T1059.004 (Unix Shell) | **Windows/Process:** `wsl.exe` executes a shell, passing in encoded/obfuscated Linux commands. | **Command Line IOC:** Execution of **`wsl.exe -e bash -c "<encoded_command>"`** or a similar execution chain. |
| **WSL Execution (ANCHOR)**| **T1202 (Indirect Command Execution)** | **Process/Network:** The WSL environment executes the payload using native tools (`curl`, `base64`, `sh`) to establish C2. | **Process Anomaly:** **`wsl.exe` Parent** → **`bash/sh` Child** → **`curl/wget` Grandchild** initiating outbound network connection. |
| **Lateral Movement / Staging** | T1083 (File Reconnaissance) / T1548.003 (Bypass UAC) | **WSL/Windows:** The payload gathers data in the WSL environment before staging it on the Windows filesystem. | **File Event:** Creation of a compressed archive (e.g., `.tar.gz`) in a WSL temp directory (`/tmp/`). |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2) | **Network:** The WSL process or its payload sends staged data to the external C2 server. | **Network Log:** Outbound HTTPS/HTTP connection from a WSL-related process to an external C2 IP/domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Command Line IOCs

1.  **WSL Command Line Anomaly (The Execution Tell):** The most critical IOC is the **Command Line Execution** captured on the Windows Host (Event ID 4688 or EDR logs). Focus on:
    * **`wsl.exe` flags:** Look for the use of the **`-e` or `--exec` flag** and the **`-c` flag** followed by a long string of **high-entropy, base64-encoded, or heavily obfuscated characters**. This indicates an encoded malicious payload passed directly to the Linux shell.
    * **Direct Linux Commands:** `wsl.exe` command lines containing direct calls to network utilities like `curl`, `wget`, or process execution commands like `nohup`, `&`, or backgrounding symbols.
2.  **Process Chain Anomaly:** On the Windows side, the initial process chain will be: **`wsl.exe` Parent** $\rightarrow$ **`bash.exe` or `sh.exe` Child**. The next link in the chain is crucial: **`bash.exe` Parent** $\rightarrow$ **Network Utility (`curl/wget`) or Final Payload**.
3.  **Process Bridge Monitoring:** Look for the **Linux process (`bash/sh`)** interacting with the Windows host by executing Windows executables via the mount point (`/mnt/c/Windows/System32/`). This confirms the payload has transitioned back to the native Windows environment.

### Network, File, and Identity IOCs

1.  **Network Activity from Linux Utility:** Analyze network logs (Firewall/Proxy) for **outbound traffic** where the source process is a **Linux-native network utility** (e.g., `curl`, `wget`, `python`) running under the `wsl.exe` or `vmmem` (WSL2) context. Check for connections to **suspicious external IP addresses or C2 domains**.
2.  **File System Artifacts (WSL/Windows):**
    * **Linux Dropping:** Look for the creation of new files in high-risk Linux directories (`/tmp/`, `/var/tmp/`) using Linux utilities.
    * **Windows Staging:** Check the Windows filesystem for files written by the WSL environment to user-writable paths (`C:\Users\<user>\AppData\Local\Temp`).
3.  **WSL Logging:** If available, review the **Microsoft-Windows-Subsystem-Linux/Operational log** for events detailing the execution of the command line passed to the Linux environment, which can often contain the decoded payload script.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Sever the C2 channel and remove the means of Linux execution. | **Terminate all active `wsl.exe` processes** and the associated WSL distribution instance. **Block the C2 IP/Domain** identified by the payload. |
| **Application Control** | **Restrict WSL Execution:** Control which users can launch the subsystem. | Use **Windows Defender Application Control (WDAC)** or **AppLocker** to **block the execution of `wsl.exe`** for standard users or restrict its execution only from known, whitelisted administrative scripts. |
| **Process Control** | **Restrict Command Line Arguments:** Alert on high-entropy or encoded commands passed to WSL. | Configure EDR rules to alert on **`wsl.exe` execution** where the command line contains **base64-encoded strings**, or long sequences of high-entropy data that are passed as arguments to `bash -c`. |
| **Logging and Auditing** | **Cross-Environment Visibility:** Ensure EDR can map Linux processes back to the Windows process tree. | Mandate **PowerShell Event ID 4104 (Script Block Logging)** to capture the initial Windows script, and use an **EDR/Linux Auditd** solution that provides deep **process lineage correlation** between the Windows and WSL environments. |
