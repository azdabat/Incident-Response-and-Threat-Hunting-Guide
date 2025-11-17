# Incident Response Playbook – Registry Run / Startup Folder Persistence

This playbook addresses the highly common and fundamental **Persistence** technique (TA0003) where an attacker modifies Windows startup mechanisms to ensure their malicious payload (or a script that downloads it) executes automatically every time the user logs on or the system boots. This is primarily achieved by modifying **Registry Run keys** (T1547.001) or dropping files into the **Startup Folder** (T1547.001).

**MITRE ATT&CK Tactic:** Persistence (TA0003)
**Technique:** Boot or Logon Autostart Execution (T1547.001)
**Critical Threat:** The attacker has established a reliable long-term presence on the compromised endpoint, allowing them to maintain access despite reboots or session timeouts.

---

## 1. L2 Analyst Actions (Initial Triage & Persistence Location)

The L2 analyst must confirm that the registry or file system modification is unauthorized and identify the initial process that created the persistence mechanism.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the modification is tied to any documented, expected application installation, patch, or approved system management tool (e.g., VPN client, update utility). **Reject any persistence created by unknown files or scripts.**
2.  **Persistence Location Check (MDE Focus):** Identify the exact location of the persistence mechanism using **`RegistryEvents`** or **`FileEvents`**. Common locations include:
    * **Registry:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
    * **Registry (System-wide):** `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
    * **File System:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`
3.  **Parent Process Identification:** Determine the process that initiated the creation of the registry key or file drop. This **Parent Process** is the key to tracing the initial access (e.g., `powershell.exe`, `cmd.exe`, or an application exploit).
4.  **Payload Analysis:** Identify the file being executed by the persistence mechanism (the **Payload Path**). Note its name, hash, and whether it points to a standard system location (`System32`) or an unusual hidden directory.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The user whose context the persistence was created under).
* **Time Range:** The $\pm1$ hour surrounding the persistence creation event.
* **Full Process Chain:** The initial access vector (if known) leading to the Parent Process that created the key/file.
* **Persistence Artifact:** The full registry path and value name **OR** the full file path and hash of the executable dropped in the Startup folder.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **Persistence is created with elevated privileges** (HKLM key) or by a system account. **Severity is High.**
* The execution chain leading to the persistence mechanism is unknown or already flagged as malicious (e.g., a suspicious PowerShell script).
* The persistence mechanism points to a file with an **unknown hash** or one that immediately makes an external network connection.
* **Similar persistence mechanisms** are discovered on multiple hosts.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Initial Access Link)

The L3 analyst must dismantle the persistence mechanism and trace the initial infection path that allowed the creation of the persistence.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Corroboration:** Trace the Parent Process identified in Section 1.1 back to the **Initial Access** vector (T1566): Was it a phishing document macro, a compromised service, or a remote execution attempt (like PSExec or RDP)?
2.  **Payload Intent:** Analyze the file or command line that the persistence artifact executes. Is it a:
    * **Loader:** Downloads a stage 2 payload from the network.
    * **Backdoor:** Executes a beaconing C2 connection.
    * **Credential Stealer:** Attempts to dump hashes on startup.
3.  **Registry/File Modification Audit:** Use **`RegistryEvent`** and **`FileEvent`** tables to search for *other* related persistence attempts (e.g., WMI Event Consumers, Scheduled Tasks) established around the same time. Adversaries rarely use just one method.
4.  **User Access Review:** Determine what the user did **after** the persistence was created. Did they interact with any sensitive data or establish new network connections?

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1547.001 Confirmed):** The attack has moved past execution into the long-term phase of persistence.
2.  **Scope the Incident:** The scope includes the **host where persistence was created**, the **initial access host** (if different), and any subsequent targets accessed using the compromised account.

---

## 3. Containment – Recommended Actions (Removal & Sanitization)

Containment must focus on immediate and complete removal of the persistence artifact to prevent re-execution upon reboot.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Disable Persistence:** Remediate the persistence artifact:
    * **Registry:** Immediately **delete the suspicious Run key value** using Live Response (or manual cleanup if host is offline).
    * **Startup Folder:** **Delete the dropped file** from the Startup folder.
3.  **Payload Quarantine:** Quarantine the file referenced by the persistence mechanism (if it was a physical file on disk) and **block its hash** organization-wide.
4.  **Credential Revocation:** Reset/revoke the credentials of the affected user (`AccountName / UPN`), assuming the next stage of the payload will be credential theft upon next logon.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must prevent unauthorized writes to critical system startup locations.

1.  **Control Failure Analysis:** Identify which control failed: **Prevention** (allowing the malicious initial access), or **Registry/File Monitoring** (failing to block the write operation to the critical key/folder).
2.  **Propose and Track Improvements:**
    * **ASR Deployment:** Implement the **Attack Surface Reduction (ASR) Rule** to block potentially dangerous write operations: **"Block persistence through Windows Management Instrumentation (WMI)"** (to catch related persistence) and general protection against unauthorized registry modifications.
    * **Application Control (WDAC/AppLocker):** Use Application Control to prevent known malicious executables from running at all, regardless of where they are executed from.
    * **Group Policy Restrictions:** Implement policies to restrict write access to the shared `ProgramData` Startup folder to only administrative accounts.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that Persistence is the **final confirmation** of a successful breach. Train analysts to prioritize tracking the **Parent Process** to uncover the initial access method.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query explicitly hunts for creation or modification events in the most common and effective Registry Run keys, which are mandatory for Persistence detection.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Registry Run Key Persistence (T1547.001)
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
// Filter for common Run keys (HKU for user, HKLM for system-wide)
| where RegistryKey has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run\",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
    @"\Software\Policies\Microsoft\Windows\System\Scripts" // Logon/Logoff Scripts
)
| where isnotempty(RegistryValueData)
| extend Payload = RegistryValueData
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, Payload, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
Concluding Remarks: The Foothold is Secured

Persistence is the point where the attacker moves from a momentary intrusion to a secured foothold. They are betting that even if you find and clean the active process, you won't find the mechanism that re-launches it.

Don't Stop at Termination: If you only kill the running process but leave the Registry Run key, the attacker will be back as soon as the user reboots or logs in. Persistence removal must be part of your containment routine.

It's a Trail, Not a Single Event: The true danger isn't the persistence itself, but what it reveals about the Initial Access (IA). Use the Parent Process to pivot immediately into your IA logs (Email, Web Proxy, LOLBIN execution).

Hardening the Foundation: The long-term fix is to harden the core Windows startup locations. Restrict who can write to those registry keys and folders. If a non-admin process can't write to the Run key, the most common form of persistence is defeated.
