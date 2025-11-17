# Incident Response Playbook – Data Staging via Utility Archivers (T1560)

This document is a consolidated guide for L2/L3 SOC Analysts and Threat Hunters, covering the full IR lifecycle for post-compromise data staging using archive utilities.

**MITRE ATT&CK Tactic:** Collection (TA0009), Exfiltration (TA0010)
**Technique:** Archive Collected Data (T1560)
**Tools:** `7z.exe`, `WinRAR.exe`, `zip.exe`, `tar.exe`

---

## 1. L2 Analyst Actions (Initial Triage & Validation)

The goal is to validate the alert, determine the scope, and identify critical characteristics that justify escalation.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Immediately confirm whether any documented change or approved maintenance (e.g., scheduled backups, application migration) could explain the execution of archive utilities (`7z.exe`, `WinRAR.exe`, etc.).
2.  **Process Lineage Review:** Examine EDR/SIEM logs for suspicious parents, such as `cmd.exe`, `powershell.exe`, or non-standard scripting engines.
3.  **Command Line Review:** Scrutinize the full command line for flags indicating **password protection** (`-p`), file splitting, or targeting sensitive system directories (`C:\Windows\System32\config`, database folders).

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for documentation and L3 handover:

* `DeviceName` / `DeviceID`
* `AccountName` / **`UPN`** (User Principal Name)
* **Time Range:** Collect all logs and alerts within a forensic window of **$\pm24$ hours** around the detection time.
* **Alert Context:** All related alerts on the same host/user (e.g., discovery, enumeration).
* **Artifacts:** The full path and hash (SHA256) of the created archive file.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* `Severity` is **Medium or High**.
* The affected host/user is **sensitive** (e.g., Domain Controller, Tier-0 Server, privileged account).
* The archive file is **$>50$ MB** and created from disparate sensitive directories.
* The command line indicates **password protection** or **file splitting**.
* A subsequent network connection (particularly to external file sharing services) is observed immediately after the archive is created.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Scoping)

The L3 analyst reconstructs the full attack narrative, classifies the activity, and establishes the incident scope.

### 2.1 Full Incident Chain Reconstruction

1.  **Preceding Execution (Initial Access & Discovery):** Trace backward to confirm the entry point and hunt for precursor discovery commands (`whoami`, `nltest`, `dir /s`).
2.  **Subsequent Activity (Exfiltration Attempt):** Trace forward from the archive creation. Look for high-volume outbound network traffic to non-corporate IPs or C2 beaconing activity. Check for file deletion/removal following network activity.
3.  **Persistence:** Search for newly created scheduled tasks, services, or registry run keys set by the process that initiated the staging.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Benign/Expected:** Consistent with known operational workflows.
    * **Misconfiguration / Risky Operational Pattern:** Legitimate tool misused by a non-privileged user (policy violation).
    * **Malicious Intrusion (Hands-on-Keyboard):** Process chain involves suspicious binaries, targets high-value data, and is followed by exfiltration attempts. **MITRE T1560 confirmed.**
2.  **Scoping:** Determine the **volume and classification** of data staged, all **affected hosts** (source and lateral targets), and whether **Exfiltration** (T1041 / T1567) was successful.

---

## 3. Containment – Recommended Actions

Containment aims to stop the immediate threat, prevent further data loss, and preserve forensic integrity.

1.  **Endpoint Isolation:** **MANDATORY** isolate affected endpoints immediately if the activity is classified as Malicious or involves High-Severity assets.
2.  **Credential Revocation:** Reset/revoke all affected user credentials (local passwords, domain passwords, cloud sessions) and **immediately enforce MFA**.
3.  **Binary Constraint:** Block or constrain the involved archive utilities (e.g., specific renamed hashes of `7z.exe`) using application control policies (WDAC, AppLocker, EDR policy).
4.  **Cloud Session:** For cloud-related staging, immediately revoke all active sessions and access tokens for the compromised identity/app registration.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation focuses on eliminating the root cause and hardening controls to prevent recurrence.

1.  **Control Failure Analysis:** Identify which security control failed (Endpoint, Identity, DLP, etc.) and document the failure point.
2.  **Propose and Track Improvements:**
    * Implement new, refined **detection logic** (e.g., SIEM rule) to specifically alert on archive utilities when they access a high number of unique file paths or compress files from multiple distinct user profiles.
    * Update **hardening baselines** (GPO/Intune/CIS benchmarks) to restrict the execution of utility archivers by non-privileged users.
    * Rework **Identity Governance** to implement Just-in-Time (JIT) access policies.
3.  **Documentation and Knowledge Transfer:** Update this playbook, SOPs, Threat Models, and the Knowledge Base with lessons learned and new TTP variations.

---

## 5. Threat Hunting Queries (KQL Focus)

These are sample KQL fragments for hunting this behavior across EDR/SIEM platforms.

### 5.1 Common Command Line Artifacts to Hunt

Search for process creation events containing these specific command line strings:

| Tool | Common Attacker Flags/Syntax |
| :--- | :--- |
| **7z.exe** | `7z a *.* -p* -mhe=on` (password/hide metadata) |
| **Rar.exe** | `rar a -p* -ep1` (password/exclude base path) |
| **Zip.exe** | `zip -er *.*` (encrypted zip archive creation) |
| **Tar.exe** | `tar -czvf *` (compressed tar creation, less common on Windows) |

### 5.2 Hunting Query Example (KQL Only)

A high-fidelity hunt query that looks for archive tool execution and links it to the creation of a large archive file (over 100MB).

```kql
// KQL Query for Staging Detection in Microsoft Defender XDR / Sentinel
let StagingTools = dynamic(['7z.exe', 'rar.exe', 'tar.exe', 'zip.exe']);
DeviceProcessEvents
| where FileName in (StagingTools)
| where ProcessCommandLine has_any (".zip", ".7z", ".rar", ".tar.gz") // Command line confirms archive creation
| where not(AccountName in ('System', 'IT_Admin_Account', 'Backup_Service'))
| join kind=leftouter (
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar" or FileName endswith ".tar.gz"
    | where FileSize > 100000000 // Stage 1: File size > 100MB
    | project DeviceId, InitiatingProcessId, FileName, FileSize
) on $left.DeviceId == $right.DeviceId and $left.ProcessId == $right.InitiatingProcessId
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    StagingTool=FileName,
    ArchiveName=FileName1,
    ArchiveSize=FileSize1,
    ParentProcess=InitiatingProcessFileName
| order by Timestamp desc
