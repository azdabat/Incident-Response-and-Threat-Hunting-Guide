# Incident Response Playbook – Process Hollowing / PE-swap

This playbook addresses **Process Hollowing (or Process Replacement)**, a sophisticated defense evasion technique where an attacker creates a legitimate, benign process in a suspended state, hollows out its memory space, and injects and executes malicious code within the trusted container (T1055.012). This allows the malicious code to run under the identity and security context of a whitelisted application (like `svchost.exe` or `explorer.exe`), severely degrading endpoint detection capabilities.

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005), Execution (TA0002)
**Technique:** Process Injection (T1055.012), Reflective Code Loading (T1620)
**Critical Threat:** A highly stealthy payload has achieved execution and memory persistence, masquerading as a legitimate Windows service, making it difficult to detect and often requiring specialized memory analysis.

---

## 1. L2 Analyst Actions (Initial Triage & Suspicious State Check)

The L2 analyst must focus on identifying the anomalous state of the process—a benign file executing code that does not match its disk hash, or unusual thread activity.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether any documented change or approved application deployment uses legitimate **code injection** techniques (e.g., specific security agents or proprietary monitoring tools). **Reject executions where the process behavior does not match its expected baseline.**
2.  **Process Anomalies (MDE Focus):** Using **`DeviceProcessEvents`** and related tables, look for the following characteristics in the suspected process (often a common Windows binary):
    * **Suspended/Resumed:** The process was initially created in a **suspended state** (`CreateProcess` with the `CREATE_SUSPENDED` flag).
    * **Unusual Child Process:** The process's activity (network connections, file writes) suddenly changes or spawns a suspicious child process that does not match its original program.
3.  **Cross-Process Events:** Look for precursor events (T1055) showing the malicious parent process calling specific Windows APIs on the victim process, such as **`NtUnmapViewOfSection`**, **`WriteProcessMemory`**, and **`SetThreadContext`** (these are the core building blocks of hollowing).
4.  **Baseline Mismatch:** Check the reported **Process Hash** or **Code Signature** of the running process. While the on-disk file is legitimate, the memory content will not match its original hash/signature.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The user running the parent process).
* **Time Range:** The $\pm1$ hour surrounding the initial process creation (when the process was suspended).
* **Target & Injector:** The PID, full path, and hash of both the **Hollowed Target Process** (e.g., `svchost.exe`) and the **Malicious Injector/Parent Process**.
* **API Call Trace:** Evidence of the critical injection API calls (`WriteProcessMemory`, `SetThreadContext`).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed sequence of **`CreateProcess` (Suspended)** followed by **`WriteProcessMemory`** into that process. **Severity is Critical.**
* The compromised process (the victim) is a **system-critical service** (e.g., `lsass.exe`, `winlogon.exe`, high-privilege `svchost.exe`).
* The injected code makes an unauthorized **network connection** or accesses the **Registry/LSASS memory**.
* The attack is widespread, affecting multiple hosts via the same signature mismatch.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Memory Analysis)

The L3 analyst must confirm the injection, identify the final payload, and determine the initial execution vector leading to the injector.

### 2.1 Full Attack Chain Reconstruction

1.  **Injector Identification:** Trace the malicious parent process (the injector) back to its initial access vector (e.g., Phishing, LOLBIN execution, or a software vulnerability).
2.  **Memory Artifacts (Forensics):** Since the malicious code is fileless in the target process, an endpoint memory dump is typically required to analyze the injected region. Focus on:
    * **Executable Regions:** Analyze the memory region written to by `WriteProcessMemory` for any identifiable payload headers, strings, or import tables.
    * **Threat Signature:** Identify the specific family of malware (e.g., banking Trojan, TrickBot, custom backdoor) by its characteristics in memory.
3.  **Payload Intent:** Determine what the injected code is attempting to do:
    * **C2 Communication:** Where is the injected code connecting?
    * **Credential Theft:** Is it targeting local processes for hash dumping?
    * **Persistence:** Is it attempting to survive a reboot (e.g., creating a service or scheduled task)?
4.  **Timeline Correlation:** Correlate the injection event with any preceding credential theft or lateral movement attempts.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1055.012 Confirmed):** High-stealth execution mechanism used to evade detection.
2.  **Scope the Incident:** The scope includes the **initial injector host, the hollowed target process**, and any subsequent systems accessed using stolen credentials or the C2 channel.

---

## 3. Containment – Recommended Actions (Targeted EDR Action)

Containment must focus on breaking the execution chain by isolating the host and ensuring the injected code cannot survive a memory flush.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE immediately.
2.  **Terminate the Hollowed Process:** Locate the PID of the hollowed process (e.g., the anomalous `svchost.exe`) and **forcibly terminate it**. This kills the malicious execution instantly, as the code is running entirely in that process's memory space.
3.  **Payload Isolation:** If the initial injector file (the file that performed the hollowing) is identified, immediately quarantine the file and block its hash across the organization.
4.  **Credential Revocation:** Reset/revoke the credentials of the user account (`AccountName / UPN`) that ran the initial malicious injector, assuming the primary payload was a credential stealer.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must focus on implementing kernel-level monitoring and advanced endpoint controls to detect and prevent memory manipulation.

1.  **Control Failure Analysis:** Identify which control failed: **EDR Behavioral Monitoring** (failing to link the API call chain), or **Application Control** (failing to block the initial injector process).
2.  **Propose and Track Improvements:**
    * **Kernel-Level Integrity:** Ensure **Windows Defender Exploit Guard (Control Flow Guard/CFG)** is enabled across endpoints, as it can help prevent some forms of unauthorized code execution within a process's memory.
    * **Process Creation Hardening:** Implement an ASR rule or custom MDE detection specifically to alert on **suspicious calls to `WriteProcessMemory` or `SetThreadContext`** targeting common Windows processes (`svchost.exe`, `explorer.exe`).
    * **Application Control (WDAC):** Use **Windows Defender Application Control (WDAC)** to strictly limit which executables are allowed to run, thus preventing the initial malicious injector process from launching.
3.  **Documentation and Knowledge Transfer:** Update playbooks, and create a centralized knowledge base entry detailing the common benign processes targeted by hollowing in the environment (e.g., which specific `svchost.exe` or `RuntimeBroker.exe` processes are usually abused).

---

## 5. Threat Hunting Queries (KQL Focus)

Detecting Process Hollowing reliably requires correlating multiple low-level API calls that MDE captures. This query targets the core behavioral chain: a process writing to the memory of another.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Process Hollowing Indicators (T1055.012)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| project CreationTime=Timestamp, DeviceName, InitiatingProcessId, TargetProcessId=ProcessId, TargetProcessName=FileName
| join kind=inner (
    DeviceProcessEvents
    | where ActionType == "ProcessApiCall"
    | where TargetProcess in ('svchost.exe', 'explorer.exe', 'RuntimeBroker.exe') // Common hollowed targets
    | where ProcessApiCallName has_any ("WriteProcessMemory", "NtUnmapViewOfSection", "SetThreadContext")
    | project ApiCallTime=Timestamp, TargetProcessName=TargetProcess, TargetProcessId=ProcessId, CallerProcessName=InitiatingProcessFileName
) on $left.TargetProcessId == $right.TargetProcessId
| where ApiCallTime between (CreationTime .. CreationTime + 30s) // The API calls must follow creation closely
| summarize by CreationTime, ApiCallTime, DeviceName, TargetProcessName, CallerProcessName, InitiatingProcessId
| order by CreationTime desc
```

Concluding Remarks: Looking Beyond the File Hash:

Process Hollowing represents the adversary's commitment to Defense Evasion. The file on disk is clean, the process name is trusted, but the code running inside is pure venom. This attack requires you to stop relying on traditional file-hash detections.

Focus on Behavior, Not Identity: You need to train your eye to look for the behavioral signature: a trusted process behaving abnormally (suspicious network calls, unusual child spawning) preceded by memory manipulation API calls. The API sequence is the immutable evidence.

The Memory Dump Mandate: This is one of the few attacks where a simple disk image won't suffice. If you suspect hollowing, you need to initiate a memory dump and analysis to recover the true payload that's living only in RAM.

Hollow Out the Attacker: Your remediation efforts must target the integrity of system memory. Implementing and verifying controls like Credential Guard and Exploit Guard is your best defense against having your trusted processes turned into weapons.
