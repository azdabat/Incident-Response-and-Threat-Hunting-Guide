# SOC Investigation Spine: SAM/SECURITY Hive Export – T1003.002

**Explanation:** This playbook analyzes the technique of exporting the **SAM (Security Account Manager)** and **SECURITY** registry hives to steal local user NTLM password hashes and keys needed to decrypt them (the Boot Key). Attackers typically leverage built-in Windows commands like `reg.exe` or volume shadow copy utilities to bypass file locking and then copy the hive files (`\Windows\System32\config\SAM` and `\SECURITY`) to a staging directory for exfiltration. The most reliable **Anchor Point** is the **execution of registry export commands** or **shadow copy utilities** followed immediately by the creation of new, large files in temporary directories.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078 (Valid Accounts) | **Endpoint/Identity:** Attacker compromises the host with standard user or administrator credentials. | **Logon Event:** Successful logon to the host, potentially from an unusual IP address. |
| **Execution / Foothold** | T1059 (Command-Line Scripting) | **Process:** The attacker runs commands to gain necessary permissions or execute the dump utility. | **Process Event:** Execution of `CMD.EXE` or `POWERSHELL.EXE` with non-standard arguments. |
| **Hive Export (ANCHOR)**| **T1003.002 (Security/SAM Database)** | **Process/File:** Execution of a utility to access or save the critical registry hives. | **Command Line IOC:** Execution of **`reg save HKLM\SAM ...`** or **`vssadmin create shadow`** followed by file copy (`copy.exe`). |
| **Staging / Compression** | T1560.001 (Archive via Utility) | **File:** The attacker stages the copied hive files in a single, compressed archive for stealthy exfiltration. | **File Event:** Creation of large files (`sam.txt`, `security.txt`, or `creds.zip`) in temporary directories (`C:\Windows\Temp`). |
| **Impact / Exfiltration** | T1041 (Exfiltration Over C2) | **Network:** The attacker transfers the compressed archive containing the stolen hashes off-network. | **Network Log:** Outbound connection from the staging host to an external C2 IP or cloud storage service. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & File IOCs

1.  **Registry Save Command:** The most direct IOC is the command-line execution of **`reg.exe`** with the `save` subcommand specifically targeting the **`HKLM\SAM`** or **`HKLM\SECURITY`** keys.
    * **Command Line IOC:** `reg save hklm\sam C:\temp\sam.dat`
    * The parent process should be scrutinized to determine if the execution was legitimate or initiated by a suspicious shell/script.
2.  **Shadow Copy Interaction (T1003.003):** If the attacker used the Volume Shadow Copy Service to access locked files, look for the execution of **`vssadmin.exe create shadow`** or similar commands, followed immediately by **`copy.exe`** targeting files in the shadow copy path (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy...`).
3.  **File Creation Anomaly:** The creation of new files named `sam.hiv`, `security.hiv`, `sam.dat`, or `security.dat` in user-writable, temporary, or public directories (`C:\ProgramData`, `C:\Windows\Temp`) is a critical file IOC. These files should be the exact size of the actual registry hives.

### Identity and Network IOCs

1.  **Required Privilege:** Identify the **integrity level** and **user account** under which the hive export command ran. Successful export of these hives requires **SYSTEM** or **Administrator** privileges; if the initial command ran under a standard user, a privilege escalation event must have preceded the export.
2.  **Authentication After Exfil:** Immediately following the hive export and staging, check Identity logs for **failed login attempts** across peer systems, followed by **successful lateral movement** using credentials that could have been cracked from the stolen hashes (Pass-the-Hash/Pass-the-Ticket).
3.  **C2 Traffic:** Review network logs for outbound connections from the compromised host, specifically looking for the transfer of a newly created, compressed archive (e.g., `archive.zip`) to an unusual destination IP, indicating data exfiltration.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Invalidate credentials and remove the means of hash theft. | **Force password reset** for any accounts present on the system (since local hashes are compromised). **Isolate the host** to prevent lateral movement. |
| **Credential Protection** | **Enable Credential Guard:** Utilize virtualization-based security to isolate LSASS and prevent access to sensitive secrets, which also helps protect SAM/SECURITY. | Ensure **Windows Defender Credential Guard** is enabled on all endpoints via Group Policy. |
| **Command Control** | **Restrict Access to Built-in Utilities:** Limit the ability of standard users or suspicious processes to execute utilities used for dumping. | Use **AppLocker** or **WDAC** to prevent the execution of `reg.exe` or `vssadmin.exe` with suspicious command-line arguments. |
| **Logging** | **System Auditing:** Ensure detailed logging is enabled for process creation and registry access. | Mandate **Process Command Line Logging** and high-fidelity **Registry Object Access Auditing** for the `\config\SAM` and `\SECURITY` hive paths. |
