# Incident Response Playbook – SMB / PsExec-style ADMIN$ Lateral Movement

This playbook addresses the use of **Server Message Block (SMB)** and administrative shares (like **ADMIN$** and **C$**) combined with remote execution tools like **PsExec** (T1569.002) for **Lateral Movement (T1021.002)**. Attackers utilize legitimate Windows features, often with stolen or compromised privileged credentials, to remotely stage a payload (copy it to `ADMIN$`) and then execute it by creating a remote service.

**MITRE ATT&CK Tactic:** Lateral Movement (TA0008), Execution (TA0002)
**Technique:** Remote Services: SMB/Windows Admin Shares (T1021.002), Service Execution (T1569.002)
**Critical Threat:** Covert, high-speed execution of malicious code on a remote target with SYSTEM or Administrator privileges, often bypassing network boundary controls that are blind to internal SMB traffic.

---

## 1. L2 Analyst Actions (Initial Triage & Network Trace)

The L2 analyst must confirm that the remote file write and execution chain is unauthorized.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the activity is tied to any documented deployment (SCCM, PDQ Deploy, or administrative script) that uses PsExec or similar remote execution capabilities. **Reject remote execution commands originating from user workstations or unauthorized scripts.**
2.  **Source Process Check:** Identify the **Initiating Process** on the source machine. Was it a known tool like `PsExec.exe`, `psexecsvs.exe`, `wmic.exe`, or a custom script executed via `powershell.exe` or `cmd.exe`?
3.  **Target Activity:** On the target machine, look for two key events that must occur sequentially:
    * **File Write:** A file creation/write operation (`FileEvent`) to the `C:\Windows\ADMIN$` share (or the `C:\` share) that typically drops the executable payload (e.g., `PSEXECSVC.exe`, `random.exe`).
    * **Remote Service Creation:** A subsequent service creation event (e.g., Event ID 4697 or `DeviceRegistryEvents`) indicating that the dropped file was immediately registered and executed as a service (T1543.003).
4.  **Credential Context:** Note the **AccountName** used for the SMB session. PsExec requires administrator privileges; therefore, this confirms the attacker is operating with elevated access.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId` (The target/victim machine).
* `AccountName` / **`UPN`** (The compromised administrator account).
* **Time Range:** The $\pm1$ hour surrounding the SMB write operation.
* **Execution Artifacts:** The **Source Device IP/Name**, the **Dropped File Name and Hash** on the target (`ADMIN$` share), and the **Service Name** created to execute it.
* **Movement Map:** The source machine's process chain leading to the PsExec command.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed use of PsExec or equivalent tools using **Tier 0** (Domain Admin) credentials. **Severity is Critical.**
* The remote execution is followed immediately by the execution of a **payload with a known malicious hash**.
* The activity appears as **"fan-out"** lateral movement (one source machine successfully targets multiple hosts rapidly).
* The target host is a **critical infrastructure system** (Domain Controller, Exchange Server, Database Server).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Movement Map)

The L3 analyst must assume the attacker is moving rapidly and must map the entire lateral movement chain.

### 2.1 Full Attack Chain Reconstruction

1.  **Movement Map:** Trace the full hop-by-hop path of the attack. If `ServerA` used PsExec on `ServerB`, and `ServerB` immediately PsExec-ed `ServerC`, all three are compromised.
2.  **Initial Access Corroboration:** Trace the compromised administrator credentials back to the source host where they were likely stolen (Credential Dumping, LSASS access) or the initial access vector (Phishing).
3.  **Payload Intent:** Analyze the payload file that was staged and executed. Determine its function (e.g., backdoor installation, credential dumping, ransomware pre-staging).
4.  **Targeted Discovery:** Review activity on the *target* host immediately after execution. Look for follow-on discovery commands (`whoami`, `ipconfig`, `net group domain admins`) executed by the malicious service/process.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1021.002 Confirmed):** High-impact lateral movement leading to code execution with high privileges.
2.  **Scope the Incident:** The scope includes **all hosts** in the lateral movement chain (source and targets), the **compromised administrative identity**, and all **staged payload files**.

---

## 3. Containment – Recommended Actions (Identity, Network, & Execution Kill)

Containment must break the adversary's path, terminate the running process, and invalidate the stolen credentials.

1.  **Isolate Affected Hosts:** **MANDATORY** isolate the source machine (where PsExec was launched) and all immediate target hosts from the network using MDE.
2.  **Credential Revocation:** **IMMEDIATE** password reset for the compromised administrator account (`AccountName / UPN`) to prevent further lateral movement attempts. Enforce logoff/token revocation across the domain.
3.  **Stop and Remove Service:** On the target host(s), identify and **terminate the malicious process** spawned by the temporary service. Delete the corresponding service definition and remove the temporary executable payload (e.g., `PSEXECSVC.exe`) from the `ADMIN$` share.
4.  **Block Payload:** Block the hash of the payload file organization-wide.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must reduce the surface area for remote code execution and limit the power of administrative credentials.

1.  **Control Failure Analysis:** Identify which control failed: **Identity/PAM** (failing to protect the administrative credentials), or **Network/Host Configuration** (allowing remote admin shares and high privileges).
2.  **Propose and Track Improvements:**
    * **Tiered Access/GPO:** Implement strong access controls so that the compromised credentials cannot authenticate to higher-tier systems.
    * **Local Admin Password Solution (LAPS):** Ensure LAPS is deployed and enforced on all workstations and servers. This randomizes the local admin hash, making PtH against the local admin account useless for lateral movement.
    * **Application Control (WDAC/AppLocker):** Implement application control policies to block unauthorized execution of tools like `PsExec.exe`, `psexecsvs.exe`, and other remote execution utilities.
    * **SMB Protocol Hardening:** Disable SMBv1 and ensure SMB signing is enforced across all sensitive endpoints to reduce certain man-in-the-middle attacks.
3.  **Documentation and Knowledge Transfer:** Update playbooks, emphasizing the importance of tracing the entire **SMB session chain** to accurately map the incident scope.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query is designed to identify the tell-tale signs of PsExec or remote administrative share abuse: the file creation on a remote target's `ADMIN$` or `C$` share, followed immediately by remote execution. The query also checks for access to other sensitive shares, as requested.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for PsExec/SMB Admin Share Lateral Movement (T1021.002, T1569.002)
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
// 1. Look for file creation on standard administrative shares (ADMIN$ points to C:\Windows)
| where FileName in ("PSEXECSVC.exe", "random.exe", "temp.exe") // Common temporary files
| where FolderPath matches regex @'(C:\\Windows\\|C:\\)[^\\]+$' or FolderPath has_any ('ADMIN$', 'C$') // Target ADMIN$ (C:\Windows) or C$ (root drive)
| extend DroppedFileName = FileName
| extend DroppedFilePath = FolderPath
| project DeviceName, AccountName, InitiatingProcessFileName, DroppedFileName, DroppedFilePath, DroppedFileHash=SHA1, DroppedTime=Timestamp
| join kind=inner (
    // 2. Correlate with subsequent remote service creation on the same host
    DeviceRegistryEvents
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has @"services\" and RegistryValueData has_any ("C:\\Windows\\", "PSEXECSVC.exe")
    | project TargetDeviceName=DeviceName, RegistryCreateTime=Timestamp
) on $left.DeviceName == $right.TargetDeviceName
// 3. Ensure the service creation occurs shortly after the file drop
| where RegistryCreateTime between (DroppedTime .. DroppedTime + 1m)
| project DroppedTime, RegistryCreateTime, DeviceName, AccountName, InitiatingProcessFileName, DroppedFileName, DroppedFileHash, DroppedFilePath
| order by DroppedTime desc
```
Concluding Remarks: The Ultimate Living-Off-the-Land Attack

PsExec and SMB-based lateral movement are highly effective because they use legitimate, necessary administrative protocols (SMB port 445) and often leverage native Windows credentials. This is a classic "Living-Off-the-Land" technique.

Focus on the Sequence: The key is the one-two punch: File Write (via SMB) -> Remote Service Creation (via PsExec/SCM). That sequence is almost always malicious if not tied to an approved deployment tool.

The Credential is King: This attack cannot happen without a privileged credential. Your highest priority is finding out where that administrator password or hash was stolen and immediately invalidating it.

ADMIN$ vs. C$: Attackers often use ADMIN$ (which maps to C:\Windows) or C$ (which maps to C:\) to stage files. Your hunting must monitor both and, crucially, look for access to other sensitive default shares like IPC$ (used for remote named pipes) or custom application shares that store sensitive data. Blocking the initial credential compromise is the only long-term solution.
