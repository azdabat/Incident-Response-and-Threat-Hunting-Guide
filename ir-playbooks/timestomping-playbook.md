# Incident Response Playbook – File Timestomping Behaviour

This playbook addresses the detection of **File Timestomping (T1070.006)**, a high-priority **Defense Evasion** technique. Attackers use this method to modify the Modification, Access, and Creation (MAC) timestamps of a malicious file to match those of a legitimate file already present on the system (e.g., a system binary). The goal is to make the malicious file appear older or blend in, thereby rendering simple chronological timeline analysis ineffective during a forensic investigation.

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005), Discovery (TA0007)
**Technique:** Indicator Removal: File Timestomp (T1070.006)
**Critical Threat:** The attacker is actively trying to contaminate the integrity of the forensic evidence, potentially causing analysts to miss the true time of compromise and the critical first execution events.

---

## 1. L2 Analyst Actions (Initial Triage & True Time Identification)

The L2 analyst must rely on the EDR's raw event logs, which capture the true file creation time *before* the stamping occurred, to establish the original timeline.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the process that performed the timestamp change (e.g., a PowerShell script) is related to an approved maintenance or forensic tool that intentionally alters file metadata. **Reject any unauthorized process performing this action.**
2.  **Stamping Process Identification:** Identify the specific executable or script that called the timestamp modification API. Look for the following common utilities or actions:
    * **PowerShell:** Execution of commands like `Set-ItemProperty`, `Set-FileTime`, or similar cmdlets targeting file properties.
    * **Native Tools:** Execution of `cmd.exe` or `powershell.exe` calling external utilities (`touch.exe`, or custom executables).
    * **API Calls:** Look for direct calls to the Windows API function **`SetFileTime`** in process activity logs.
3.  **True Creation Time Extraction:** This is the most critical step. The EDR often logs the file write/creation event separately. **Compare the file system's current Creation/Modification time against the EDR's recorded initial write time.** If they differ significantly, timestomping is confirmed.
4.  **Target File Analysis:** What is the hash and path of the file whose timestamp was modified? Is it a newly dropped executable, a DLL, or a script used for persistence?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The account that ran the stamping process).
* **Time Range:** The $\pm1$ hour surrounding the **stamping action**.
* **Artifacts:** The full path and hash of the **stamped file**, the **Process Path/Hash** that performed the stamp, and the **True Initial Write Time** recorded by the EDR.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed file timestomping action on an unknown or suspicious executable. **Severity is Critical.**
* Timestomping is observed on files located in **system directories** (`C:\Windows\System32`) or **critical user profile paths**.
* The stamping process is run with **high privileges** (SYSTEM, Administrator).
* Similar activity appears on **multiple hosts**, indicating an automated malware deployment.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Timeline Reconstruction)

The L3 analyst must disregard the file's current timestamp and reconstruct the accurate attack timeline based on surrounding evidence.

### 2.1 Full Attack Chain Reconstruction

1.  **Identify Real Deployment Time:** Use the EDR's initial file write event (the **True Initial Write Time** from L2) as the actual time the file landed on the system. Use this as the anchor point for the rest of the investigation.
2.  **Source File Identification:** If the attacker copied the time from a legitimate file, identify the **source file** whose MAC times were stolen. This provides insight into the attacker's target file selection for blending in.
3.  **Preceding Activity:** Trace the full execution chain leading up to the file drop. This should link the timestomped file back to the **Initial Access Vector** (e.g., a phishing payload or vulnerability exploitation) that delivered it.
4.  **Subsequent Activity:** Timestomping is a preparation step. Analyze the file's first execution and any subsequent activity (e.g., persistence creation, C2 beaconing) that occurred **immediately after the stamp**.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1070.006 Confirmed):** A clear indicator of a high-effort attacker attempting to hide their tracks.
2.  **Scope the Incident:** The scope includes the **host**, the **compromised user account**, the **initial access vector**, and all files involved in the malicious chain.

---

## 3. Containment – Recommended Actions (Evidence Preservation)

Containment must prioritize the preservation of the EDR's immutable event logs, as the file system evidence is now tainted.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Preserve Log Data:** Ensure the EDR/SIEM logs for the host are flagged for **long-term preservation** to maintain the record of the **True Initial Write Time** and the **stamping action**.
3.  **Delete Payload:** Remove the malicious, time-stamped file from the system.
4.  **Credential Revocation:** Reset/revoke the credentials of the user account used to execute the payload, as they were the compromised context.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the operating system against arbitrary manipulation of file metadata.

1.  **Control Failure Analysis:** Identify which control failed: **Forensic Integrity** (lack of immutable logging of true file creation), or **Detection Logic** (failing to flag the execution of utilities like `Set-ItemProperty` in a suspicious context).
2.  **Propose and Track Improvements:**
    * **Disable/Restrict Timestomping Utilities:** Use **WDAC** or **ASR** rules to constrain the use of script-based or third-party utilities that can perform file time manipulation, especially when run from non-system processes.
    * **Enhanced API Auditing:** Verify that the EDR/auditing solution is capturing **`SetFileTime` API calls**. Create a specific high-fidelity detection rule for any process not in an approved list (e.g., system updaters, backup tools) calling this API.
    * **Log Integrity:** Review the EDR logging configuration to ensure the **initial file creation event** (which contains the true timestamp) cannot be altered or overwritten.
3.  **Documentation and Knowledge Transfer:** Update playbooks, emphasizing that during an incident, all file timestamps must be treated as **suspect** and validated against the EDR's original file write event logs.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for direct command line evidence of Timestomping using common scripting utilities, which often expose the attempt to modify file properties.

### 5.1 Hunting Query Example (KQL Only)

```Markdown

# Incident Response Playbook – File Timestomping Behaviour

This playbook addresses the detection of **File Timestomping (T1070.006)**, a high-priority **Defense Evasion** technique. Attackers use this method to modify the Modification, Access, and Creation (MAC) timestamps of a malicious file to match those of a legitimate file already present on the system (e.g., a system binary). The goal is to make the malicious file appear older or blend in, thereby rendering simple chronological timeline analysis ineffective during a forensic investigation.

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005), Discovery (TA0007)
**Technique:** Indicator Removal: File Timestomp (T1070.006)
**Critical Threat:** The attacker is actively trying to contaminate the integrity of the forensic evidence, potentially causing analysts to miss the true time of compromise and the critical first execution events.

---

## 1. L2 Analyst Actions (Initial Triage & True Time Identification)

The L2 analyst must rely on the EDR's raw event logs, which capture the true file creation time *before* the stamping occurred, to establish the original timeline.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the process that performed the timestamp change (e.g., a PowerShell script) is related to an approved maintenance or forensic tool that intentionally alters file metadata. **Reject any unauthorized process performing this action.**
2.  **Stamping Process Identification:** Identify the specific executable or script that called the timestamp modification API. Look for the following common utilities or actions:
    * **PowerShell:** Execution of commands like `Set-ItemProperty`, `Set-FileTime`, or similar cmdlets targeting file properties.
    * **Native Tools:** Execution of `cmd.exe` or `powershell.exe` calling external utilities (`touch.exe`, or custom executables).
    * **API Calls:** Look for direct calls to the Windows API function **`SetFileTime`** in process activity logs.
3.  **True Creation Time Extraction:** This is the most critical step. The EDR often logs the file write/creation event separately. **Compare the file system's current Creation/Modification time against the EDR's recorded initial write time.** If they differ significantly, timestomping is confirmed.
4.  **Target File Analysis:** What is the hash and path of the file whose timestamp was modified? Is it a newly dropped executable, a DLL, or a script used for persistence?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The account that ran the stamping process).
* **Time Range:** The $\pm1$ hour surrounding the **stamping action**.
* **Artifacts:** The full path and hash of the **stamped file**, the **Process Path/Hash** that performed the stamp, and the **True Initial Write Time** recorded by the EDR.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed file timestomping action on an unknown or suspicious executable. **Severity is Critical.**
* Timestomping is observed on files located in **system directories** (`C:\Windows\System32`) or **critical user profile paths**.
* The stamping process is run with **high privileges** (SYSTEM, Administrator).
* Similar activity appears on **multiple hosts**, indicating an automated malware deployment.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Timeline Reconstruction)

The L3 analyst must disregard the file's current timestamp and reconstruct the accurate attack timeline based on surrounding evidence.

### 2.1 Full Attack Chain Reconstruction

1.  **Identify Real Deployment Time:** Use the EDR's initial file write event (the **True Initial Write Time** from L2) as the actual time the file landed on the system. Use this as the anchor point for the rest of the investigation.
2.  **Source File Identification:** If the attacker copied the time from a legitimate file, identify the **source file** whose MAC times were stolen. This provides insight into the attacker's target file selection for blending in.
3.  **Preceding Activity:** Trace the full execution chain leading up to the file drop. This should link the timestomped file back to the **Initial Access Vector** (e.g., a phishing payload or vulnerability exploitation) that delivered it.
4.  **Subsequent Activity:** Timestomping is a preparation step. Analyze the file's first execution and any subsequent activity (e.g., persistence creation, C2 beaconing) that occurred **immediately after the stamp**.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1070.006 Confirmed):** A clear indicator of a high-effort attacker attempting to hide their tracks.
2.  **Scope the Incident:** The scope includes the **host**, the **compromised user account**, the **initial access vector**, and all files involved in the malicious chain.

---

## 3. Containment – Recommended Actions (Evidence Preservation)

Containment must prioritize the preservation of the EDR's immutable event logs, as the file system evidence is now tainted.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Preserve Log Data:** Ensure the EDR/SIEM logs for the host are flagged for **long-term preservation** to maintain the record of the **True Initial Write Time** and the **stamping action**.
3.  **Delete Payload:** Remove the malicious, time-stamped file from the system.
4.  **Credential Revocation:** Reset/revoke the credentials of the user account used to execute the payload, as they were the compromised context.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the operating system against arbitrary manipulation of file metadata.

1.  **Control Failure Analysis:** Identify which control failed: **Forensic Integrity** (lack of immutable logging of true file creation), or **Detection Logic** (failing to flag the execution of utilities like `Set-ItemProperty` in a suspicious context).
2.  **Propose and Track Improvements:**
    * **Disable/Restrict Timestomping Utilities:** Use **WDAC** or **ASR** rules to constrain the use of script-based or third-party utilities that can perform file time manipulation, especially when run from non-system processes.
    * **Enhanced API Auditing:** Verify that the EDR/auditing solution is capturing **`SetFileTime` API calls**. Create a specific high-fidelity detection rule for any process not in an approved list (e.g., system updaters, backup tools) calling this API.
    * **Log Integrity:** Review the EDR logging configuration to ensure the **initial file creation event** (which contains the true timestamp) cannot be altered or overwritten.
3.  **Documentation and Knowledge Transfer:** Update playbooks, emphasizing that during an incident, all file timestamps must be treated as **suspect** and validated against the EDR's original file write event logs.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for direct command line evidence of Timestomping using common scripting utilities, which often expose the attempt to modify file properties.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for File Timestomping Behaviour (T1070.006)
DeviceProcessEvents
| where Timestamp > ago(7d)
// Look for processes that are often used to manipulate file metadata
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
// Target common command line arguments used for changing MAC times
| where ProcessCommandLine has_any ("Set-ItemProperty", "CreationTime", "LastWriteTime", "Set-FileTime", "touch.exe")
// Filter out known benign administration/imaging scripts if necessary
| where not (ProcessCommandLine has "known_backup_script.ps1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```
Concluding Remarks: Hiding in Plain Sight

Timestomping is the digital equivalent of an intruder cleaning up their footprints. When you see it, it's a strong confirmation that you are dealing with a capable, targeted attacker who understands forensic evasion.

The EDR is the Source of Truth: Your single most reliable piece of evidence is the initial file write event recorded by your EDR/SIEM. Always compare the file system time with the log time.

Pivot to the Parent: Because timestomping is always one of the last steps, the true forensic value lies in tracing the process backward. Find the parent process that created the file, and you'll find the root cause of the infection.

Forensic Discipline: When dealing with a timestomped file, treat all its file system metadata as unreliable and rely exclusively on the immutable EDR log data for timeline reconstruction.kql
// KQL Query for File Timestomping Behaviour (T1070.006)
DeviceProcessEvents
| where Timestamp > ago(7d)
// Look for processes that are often used to manipulate file metadata
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
// Target common command line arguments used for changing MAC times
| where ProcessCommandLine has_any ("Set-ItemProperty", "CreationTime", "LastWriteTime", "Set-FileTime", "touch.exe")
// Filter out known benign administration/imaging scripts if necessary
| where not (ProcessCommandLine has "known_backup_script.ps1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```
