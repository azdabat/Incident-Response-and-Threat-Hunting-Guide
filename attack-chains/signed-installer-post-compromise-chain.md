# SOC Investigation Spine: Signed Installer Post-Install C2 Behaviour – T1218 & T1553.002

**Explanation:** This playbook analyzes a complex supply chain or trojanized installer attack where a legitimate, digitally **signed installer** (MSI/EXE) is used as the initial execution vector. The installer contains both the benign software and a malicious component (e.g., an embedded DLL or script) that is executed by the installer process *after* the signature has been validated. The immediate goal is the establishment of a **Command and Control (C2)** channel for further instructions, blending malicious traffic with legitimate installation network activity. The most reliable **Anchor Point** is the **suspicious process anomaly** where the signed installer's process (e.g., `msiexec.exe` or `setup.exe`) spawns an unexpected child process that immediately initiates network activity.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 (Spearphishing Attachment) or T1195 (Supply Chain Compromise) | **Email/Endpoint:** User downloads or executes a tampered, but digitally signed, installer file. | **File Event:** Installer file creation; **File Attribute:** Valid digital signature present. |
| **Execution / Foothold** | T1218 (Signed Binary Proxy Execution) / T1553.002 (Digital Signature Spoofing) | **Process:** The signed installer process executes the embedded malicious payload or script. | **Process Event:** `MSIEXEC.EXE` or `SETUP.EXE` spawns an unusual child process (e.g., `cmd.exe`, `powershell.exe`). |
| **Post-Install C2 (ANCHOR)**| **T1071.001 (Web Protocols)** | **Network/Process:** The unexpected child process (or a dropped DLL) initiates an **outbound C2 connection** immediately after the benign software installation completes. | **Network Flow:** Outbound connection from the *child process* to an external, untrusted IP/domain, often using HTTP/S or DNS tunneling. |
| **Lateral Movement / Persistence** | T1547 (Boot/Logon AutoStart) / T1053 (Scheduled Task) | **Registry/Task Logs:** The payload establishes persistence before receiving the first tasking command from the C2. | **Event ID 4698/7045:** Creation of a new Scheduled Task or Windows Service by the installer's child process. |
| **Impact / Data Staging** | T1083 (File Reconnaissance) | **File/Process:** C2 directs the payload to begin reconnaissance or staging data for exfiltration. | **Process Anomaly:** The payload process executes suspicious commands (`whoami`, `net group`) or performs mass file enumeration. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Network IOCs

1.  **Suspicious Child Process Spawn:** The highest-fidelity IOC is a **process creation event** where the **Parent Process is the signed installer** (`msiexec.exe`, `setup.exe`, or a vendor-specific installer wrapper) and the **Child Process is an anomalous binary** or scripting host:
    * **Suspicious Children:** `CMD.EXE`, `POWERSHELL.EXE`, `RUNDLL32.EXE`, `REGSVR32.EXE`, or an unknown executable dropped in a temporary location.
    * **Context:** This activity occurs *after* the core installation logic has typically completed, but *before* the installer process terminates.
2.  **Immediate Outbound Connection:** The process that is spawned must be monitored for network activity. If this child process makes an immediate **outbound connection** to a C2 IP/domain that is *not* related to the software vendor (e.g., license check, update), this is a critical network IOC. The C2 domain is often **newly registered** (Domain Age < 30 days) to avoid reputation checks.
3.  **Digital Signature Discrepancy:** The installer file itself will have a valid signature (e.g., from Microsoft or a legitimate vendor). However, the **executable or script component that performs the C2 connection will likely be unsigned** or have a different, invalid signature, revealing the malicious component.

### File and Identity IOCs (Post-C2)

1.  **File System Artifacts (Payload Dropping):** Look for the creation of new, unexpected executable or DLL files in non-standard, user-writable locations (`C:\ProgramData`, `C:\Users\Public`). These files represent the dropped C2 agent, often using names that mimic legitimate files (e.g., `servicehost.exe`).
2.  **Persistence Artifacts:** Check the **Registry** and **Task Scheduler** logs for modifications made by the spawned child process. Since installers often run with elevated privileges (SYSTEM/Administrator), the C2 agent may set up **SYSTEM-level persistence** (e.g., HKLM Run Keys, or a SYSTEM Scheduled Task).
3.  **Identity Context:** Determine the **user context** under which the installer ran. If the user was an **Administrator** or the installer requested **UAC elevation**, the C2 agent will have high privileges, drastically increasing the severity and scope of potential impact.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Remove the persistence mechanism and prevent further C2 communication. | **Block the C2 IP/Domain** at the perimeter firewall. **Remove the malicious service/scheduled task** created by the agent. **Quarantine the dropped payload file** and update signatures. |
| **Execution Control** | **Monitor and Restrict Child Processes:** Implement controls to scrutinize processes spawned by trusted installers. | Configure EDR rules to alert on **any instance** where a digitally signed installer process (`msiexec.exe`, `setup.exe`) spawns a scripting host (`powershell.exe`, `cmd.exe`) or networking tool (`curl.exe`, `bitsadmin.exe`). |
| **Code Integrity** | **Whitelisting/Signature Control:** Prevent the execution of the unsigned malicious payload. | Use **Windows Defender Application Control (WDAC)** to restrict execution to binaries with valid, approved vendor signatures. Block execution from user-writable and temporary directories. |
| **Installer Management** | **Hash/Trust Verification:** Only permit the installation of software with verified hashes from trusted internal sources. | Implement internal process requiring the **pre-analysis and hashing** of all external installers before distribution, checking against known good hashes. |
