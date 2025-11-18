# SOC Investigation Spine: Modern LOLBIN – Winget Package Abuse – T1218 & T1105

**Explanation:** This playbook analyzes the abuse of the **Windows Package Manager (`winget.exe`)**, a signed Microsoft utility, to download and execute malicious payloads (T1105). Attackers use `winget` to install a custom or trojanized package from a public or private repository. Since `winget.exe` is a trusted, signed binary, its execution often bypasses application whitelisting. The subsequent execution of the malicious package's installer or post-install script provides the attacker with a high-trust foothold. The most reliable **Anchor Point** is the **execution of `winget.exe` with suspicious parameters** followed immediately by an **unusual file creation or network connection** initiated by the package's contents.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1059 (Execution) | **Endpoint:** Initial foothold achieved via a dropper or script that launches the `winget` command. | **Process Event:** Execution of a process (e.g., `cmd.exe`, `powershell.exe`) that executes the `winget` command. |
| **Execution / Foothold** | T1218 (Signed Binary Proxy Execution) | **Process/Command Line:** The dropper executes `winget.exe` to pull the malicious package. | **Command Line IOC:** Execution of **`winget.exe install <PackageID> -s <Source>`** where the PackageID or Source is suspicious/untrusted. |
| **Package Abuse (ANCHOR)**| **T1105 (Ingress Tool Transfer)** | **Network/File:** `winget.exe` downloads the malicious package file (e.g., MSI, EXE) and executes its installer/post-install script. | **Network Flow:** Outbound connection from `winget.exe` or an installer process to a **suspicious download URL**. **File Event:** Creation of a new executable/DLL in the temporary installation directory. |
| **Lateral Movement / Persistence** | T1547 (Boot/Logon AutoStart) / T1053 (Scheduled Task) | **Process/Registry:** The payload (installed by the package) establishes persistence or performs reconnaissance. | **Event ID 7045/4698:** Creation of a new Windows Service or Scheduled Task by the payload executable. |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2 Channel) | **Network:** The malicious component establishes C2 and exfiltrates data. | **Network Log:** Outbound HTTPS/HTTP connection from the final payload process to an external C2 IP or domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & File IOCs

1.  **Winget Command Line Anomaly:** The most critical IOC is the **Command Line Execution** of `winget.exe`. Focus on:
    * **`install` subcommand:** This indicates an attempt to introduce new software.
    * **Suspicious Source (`-s` or `--source`):** The use of a non-default, unverified, or custom package repository URL (e.g., a short-lived attacker domain) is a strong indicator of abuse.
    * **Unusual Package ID:** The Package ID targeted is unknown, generic, or mimics a legitimate package name (`Microsoft.Updates`, `SystemUtility`).
2.  **Process Creation Chain (Post-Winget):** `winget.exe` often spawns an installer process (e.g., `msiexec.exe`, `setup.exe`). The subsequent behavior of this installer process is key. Look for:
    * The installer process (Parent) spawning **`cmd.exe` or `powershell.exe` (Child)** immediately after installation, indicating the execution of a malicious post-install script.
    * The creation of an **unusual file path** pointing to the malicious payload in a temporary Winget cache location.
3.  **File System Artifacts (Installer Logs):** Examine the **Winget logs** (`%LOCALAPPDATA%\Microsoft\WinGet\Packages`) for the package manifest. The manifest will reveal the **exact download URL** of the package (the C2 download server) and the **installer type/switches** used.

### Network and Identity IOCs

1.  **Network Connection from Winget:** Network logs should be analyzed for **outbound HTTPS/HTTP traffic** originating from `winget.exe` or the subsequent installer process (`msiexec.exe`) destined for the **suspicious source URL** identified in the command line or manifest.
2.  **C2 Beaconing:** After the package installation, the final payload executable will initiate C2 communication. Monitor network logs for **repetitive, low-volume connections** (beaconing) from the newly dropped payload process to a high-reputation or newly registered C2 domain.
3.  **Identity Context:** Determine the **user context** under which `winget.exe` was run. Since `winget` often uses the credentials of the logged-on user, the scope of persistence and lateral movement will be tied to that user's privileges.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Remove the persistence and payload, and block the malicious source. | **Block the malicious Package ID** and the **Source URL** in the network perimeter devices. **Quarantine the installed payload file** and any persistence mechanisms it created. |
| **Application Control** | **Restrict LOLBIN Execution:** Control the execution environment of built-in tools like `winget.exe`. | Use **Windows Defender Application Control (WDAC)** or **AppLocker** to **restrict the execution of `winget.exe`** to only necessary administrative groups, or block its use entirely for standard users. |
| **Configuration Control** | **Source Restriction:** Limit the package repositories users can query. | Configure **Winget Group Policies** to **disable or restrict the addition of untrusted, non-Microsoft package sources** to prevent attackers from using custom repositories. |
| **Process Monitoring** | **Baseline Child Processes:** Alert on unexpected child processes spawned by installers. | Configure EDR rules to generate high-severity alerts when **`msiexec.exe` or `setup.exe`** (or the Winget process itself) spawns **`cmd.exe`, `powershell.exe`, or `certutil.exe`**. |
