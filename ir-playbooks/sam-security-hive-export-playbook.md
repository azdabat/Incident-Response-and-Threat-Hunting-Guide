# Incident Response Playbook – SAM/SECURITY Hive Export

This playbook addresses the highly critical **Credential Access** technique where an attacker, having achieved administrative or system-level access, steals local password hashes by exporting or copying the **Security Account Manager (SAM)** and **SECURITY** Registry Hives (T1003.002). This provides the attacker with local NTLM hashes for all users on the host, which can be cracked offline or used for Pass-the-Hash attacks.

**MITRE ATT&CK Tactic:** Credential Access (TA0006), Defense Evasion (TA0005)
**Technique:** OS Credential Dumping: SAM and LSA Secrets (T1003.002), Data from Local System (T1005)
**Critical Threat:** Complete compromise of local accounts on the machine, enabling unauthorized lateral movement using stolen credentials. On Domain Controllers, exporting the NTDS.dit file is the domain equivalent (addressed in the DCSync playbook).

---

## 1. L2 Analyst Actions (Initial Triage & Evidence Collection)

The L2 analyst must confirm the unauthorized access to and export of these highly sensitive registry hives.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether any documented change, approved auditing tool, or backup process involves the legitimate export of the SAM/SECURITY hives. **Reject any process that is not a known, signed, and authorized backup utility.**
2.  **API Call/Process Check (MDE Focus):** Identify the process that initiated the hive export. Look for:
    * **Registry Tooling:** Execution of `reg.exe` or `regedit.exe` with `SAVE` or `EXPORT` arguments targeting the SAM/SECURITY paths.
    * **Volume Shadow Copy:** Execution of `vssadmin.exe` to create shadow copies, which is often used to get an unlockable copy of the hive files.
    * **Credential Dumping Tools:** Execution of known dumping tools like `Mimikatz` or `LSASecrets` accessing these files.
3.  **File Creation/Staging:** Check the file system events (`FileEvents`) for the creation of new files named `SAM.hiv`, `SECURITY.hiv`, or similar names in unusual locations (e.g., `%TEMP%`, user profiles, public folders) before they are exfiltrated.
4.  **Privilege Context:** Note the security context (`AccountName`) under which the export was executed. This operation requires **System or Administrator privileges**, confirming a high-level compromise has already occurred.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The privileged account used to run the export command).
* **Time Range:** The $\pm1$ hour surrounding the hive file creation.
* **Full Process Chain:** The parent process (e.g., `cmd.exe` or `powershell.exe`) and the full command line used to execute the registry export utility (`reg.exe`, `vssadmin.exe`).
* **Staged Files:** The full path and hash of the exported files (`SAM`, `SECURITY`) before deletion or exfiltration.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed export of the SAM/SECURITY hives to an unauthorized location. **Severity is Critical.**
* The compromised host is a **Domain Controller** (the SAM equivalent is NTDS.dit, indicating a catastrophic compromise).
* The persistence or initial access vector leading to this export is unknown or highly sophisticated.
* Evidence of **data transfer/exfiltration** of the exported hive files (T1041).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Compromise Scope)

The L3 analyst must assume all local credentials on the machine are compromised and focus on tracing the attacker's use of these hashes.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Vector:** Trace the execution chain back from the `reg.exe` or `vssadmin.exe` command to the initial foothold (e.g., exploitation, RDP, or malicious macro).
2.  **Exfiltration Confirmation:** Use network logs (`DeviceNetworkEvents`) to confirm whether the exported hive files were successfully transferred off the host (T1041). This confirms the credentials are now in the attacker's hands.
3.  **Lateral Movement Audit:** Since all local credentials are now compromised, audit the network for **Pass-the-Hash (PtH)** attempts originating from the source host. Look for authentication events to other systems using NTLM hashes or other alternate authentication material (T1550).
4.  **Targeted Account Analysis:** Identify all local accounts on the system whose hashes were stolen. Prioritize any service accounts or local administrator accounts.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1003.002 Confirmed):** High-impact credential theft.
2.  **Scope the Incident:** The scope includes the **host where the hives were stolen** and **any other host** where the attacker attempted to use the stolen local administrator hash for lateral movement.

---

## 3. Containment – Recommended Actions (Identity & Host Integrity)

Containment must focus on breaking the connection, cleaning the staged files, and invalidating the stolen NTLM hashes.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Cleanup Staged Data:** Delete all staged hive files (`SAM.hiv`, `SECURITY.hiv`, etc.) from the temporary directory to prevent further exfiltration attempts.
3.  **Credential Invalidation:** **Force an immediate, complex password reset** for *every single local account* on the affected machine, especially the built-in Local Administrator account. The stolen hashes are now useless.
4.  **System-wide Block:** If the attacker used a specific tool or script (e.g., `Mimikatz`), block the hash of that tool organization-wide.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must secure the critical local identity infrastructure and prevent unauthorized system-level reads.

1.  **Control Failure Analysis:** Identify which control failed: **Prevention** (allowing the adversary to gain administrative access), or **Credential Protection** (lack of LSA protection or Credential Guard).
2.  **Propose and Track Improvements:**
    * **Credential Guard Deployment:** Implement **Windows Defender Credential Guard** on all applicable endpoints. While primarily for LSASS, it contributes to overall credential integrity.
    * **LSA Protection:** Ensure **Local Security Authority (LSA) protection** is enabled to prevent unauthorized processes from reading or writing to the LSA/Registry secrets.
    * **Application Control:** Use **WDAC** to strictly control which binaries (especially command line utilities like `reg.exe` and `vssadmin.exe`) can be executed by non-administrative processes.
    * **Local Admin Standardization:** Randomize local administrator passwords across all workstations using **LAPS (Local Administrator Password Solution)** or an equivalent. Stolen hashes will then be unique to the specific host.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that SAM/SECURITY hive export is typically an initial action after administrative access is achieved.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query focuses on the highly suspicious process execution and command line arguments used to export the hive files, often via `reg.exe` or `vssadmin.exe`.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for SAM/SECURITY Hive Export (T1003.002)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in ("reg.exe", "vssadmin.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine has_all ("save", "hklm\\sam") or ProcessCommandLine has_all ("save", "hklm\\security") // reg save commands
| where ProcessCommandLine has_any ("shadowcopy", "shadowstorage", "create") // vssadmin abuse for copying locked files
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
Concluding Remarks: Credentials are the Critical Asset

Exporting the SAM/SECURITY hives is the digital equivalent of stealing the master key ring for every local account on that machine. The attacker is no longer concerned with persistence; they are focused on lateral movement and escalation.

Act on the Privilege: This attack confirms the attacker already has System or Administrator privileges. Your priority is not just to clean the hash, but to understand how they got that high in the first place.

LAPS is Your Friend: If your organization uses LAPS, the impact is minimized because each host has a unique local admin hash. If you are not using LAPS, assume the attacker can now log into every other machine in your network using that stolen, default Local Admin hash.

The Follow-Up is PtH: Immediately pivot to hunting for Pass-the-Hash attempts. The hive export is only a reconnaissance and staging step—the real damage comes when they use the stolen credentials to jump to a server.
