# Incident Response Playbook – Scheduled Task Persistence

This playbook addresses one of the most stealthy and resilient **Persistence** techniques: the creation of an unauthorized **Scheduled Task (T1053.005)**. Attackers use the native Windows `schtasks.exe` or PowerShell cmdlets to set up tasks that execute their payload (or a script to re-download it) at specific times, during system startup, or upon a user logon, ensuring long-term access to the compromised endpoint.

**MITRE ATT&CK Tactic:** Persistence (TA0003), Execution (TA0002)
**Technique:** Scheduled Task/Job (T1053.005)
**Critical Threat:** The attacker has a reliable, often privileged, mechanism to re-establish a presence on the machine, which can execute with elevated rights and is typically missed by standard antivirus scans.

---

## 1. L2 Analyst Actions (Initial Triage & Task Confirmation)

The L2 analyst must confirm that the task is unauthorized and identify the exact payload path and trigger condition.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the task name, action, or user context matches any known, approved maintenance window, patch management, or third-party monitoring tool deployment. **Reject tasks with obfuscated names (e.g., random GUIDs or legitimate-sounding names like "WindowsUpdater") that point to unusual execution paths.**
2.  **Creation Process Check (MDE Focus):** Identify the parent process that **created** the task using **`DeviceProcessEvents`** (looking for `schtasks.exe` or `powershell.exe`) and **`DeviceProcessEvents`** (looking for the task creation event). This chain reveals the initial access vector.
3.  **Task Analysis:** Inspect the suspicious task's parameters:
    * **Trigger:** Is it set to run **At Logon**, **At Startup**, or on a **Repeated Interval** (e.g., every 15 minutes)?
    * **Action:** What is the full command line executed? Look for encoded commands or paths pointing to temporary/hidden directories (e.g., `C:\Users\Public\temp\`) instead of standard `Program Files`.
    * **User Context:** Does the task run as **SYSTEM**, a non-admin user, or the compromised user's account? Higher privileges mean higher risk.
4.  **Payload Status:** Check the status of the file that the Scheduled Task is configured to run. Is it present? What is its hash? Is it flagged by the EDR?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The account used to create the task).
* **Time Range:** The $\pm1$ hour surrounding the task creation event.
* **Full Process Chain:** The process tree leading to the creation of the scheduled task.
* **Task Artifact:** The **Task Name**, the **Task Path** (e.g., `\Microsoft\Windows\Defrag\ScheduledTaskName`), the **Task Action** (the full command line being run), and the **Execution User Context**.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed task created to run with **SYSTEM** or high-privileged Domain Admin credentials. **Severity is Critical.**
* The Scheduled Task's action involves **network communication** (e.g., downloading a file) or immediately spawning another suspicious process.
* The task creation is directly linked to an **initial access vector** (e.g., a macro execution or RDP session).
* **Similar tasks** are discovered across multiple endpoints or servers.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Initial Access Link)

The L3 analyst must assume the task is part of a complex chain and prioritize its safe termination before the next scheduled run.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Corroboration:** Trace the Parent Process that executed `schtasks.exe` back to the **Initial Access** method (T1566) or **Execution** method (T1059) that preceded it. This is the root cause.
2.  **Task XML Analysis:** Retrieve the raw XML file associated with the task (usually located in `C:\Windows\System32\Tasks`). This can reveal more detailed, potentially obfuscated, task definitions that the MDE logs may have summarized.
3.  **Payload Analysis and Deconstruction:** Analyze the payload file or script referenced by the task. Determine its functionality: backdoor, beacon, keylogger, or downloader. If it's a script, decode and analyze its content.
4.  **Secondary Persistence:** Scheduled Tasks are often used to deploy *other* forms of persistence (e.g., creating a Registry Run key) or for lateral movement. Check the system logs for activity immediately following the task's first run.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1053.005 Confirmed):** The attack is in the long-term Persistence phase.
2.  **Scope the Incident:** The scope includes the **host where the task was created**, the **compromised identity** used for creation, and any **staged payload files** referenced by the task.

---

## 3. Containment – Recommended Actions (Task Termination & Removal)

Containment must focus on immediate task termination and removal to prevent re-execution and the resulting payload delivery.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Disable/Delete Task:** Immediately **delete the suspicious Scheduled Task** using `schtasks /delete` or the MDE Live Response task remediation action. **Do not just disable it; delete it entirely.**
3.  **Quarantine Payload:** Quarantine and delete the file referenced in the task's action (the malicious executable or script) and **block its hash** organization-wide.
4.  **Credential Revocation:** If the task was configured to run under a specific user account (and not SYSTEM), reset/revoke the credentials of that account, as the task may expose the user's stored password.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the environment by restricting the use of task creation utilities and improving logging on this vector.

1.  **Control Failure Analysis:** Identify which control failed: **Execution Prevention** (allowing the malicious script to run `schtasks.exe`), or **Logging Configuration** (failing to capture the full command line of the task action).
2.  **Propose and Track Improvements:**
    * **Process Blacklisting/Constraining:** Use **Windows Defender Application Control (WDAC)** or a custom MDE rule to restrict the execution of `schtasks.exe` and related binaries (`at.exe`) to only approved administrative groups.
    * **Task Creation Logging:** Ensure **Task Scheduler Operational and Security Events** (specifically Event ID 4698 - A scheduled task was created) are being collected and ingested by Sentinel for comprehensive, native tracking of task creation.
    * **Task Deletion Audit:** Create a detection rule to alert on **Event ID 4702** (A scheduled task was updated/deleted) immediately following task creation, as attackers often try to delete their own tracks.
3.  **Documentation and Knowledge Transfer:** Update playbooks, and emphasize that Scheduled Tasks are a common method for achieving persistence with **elevated privileges**, a detail that often differentiates them from simple Registry Run key persistence.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query focuses on finding the creation of Scheduled Tasks by looking for the execution of the native Windows `schtasks.exe` utility with the `/create` parameter.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Scheduled Task Creation (T1053.005)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" // Command to create a new scheduled task
| where ProcessCommandLine has_any ("/tn", "/tr") // Must specify Task Name (/tn) and Task Run Action (/tr)
| extend TaskName = extract(@"/tn\s+""?([^\s""]+)""?", 1, ProcessCommandLine)
| extend TaskAction = extract(@"/tr\s+""?([^\s""]+)""?", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, TaskName, TaskAction, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

```
Concluding Remarks: The Silent Time Bomb

A Scheduled Task is a silent, automated time bomb the attacker leaves behind. It grants them a durable foothold that will execute their code even if they lose control of the immediate session.

Check the Command Line: The most important detail is the /tr (Task Run) parameter in the schtasks command line. That's the malicious payload they want to execute.

Privilege is Paramount: Always check if the task is set to run as SYSTEM. If it is, that task grants the attacker full control of the machine upon the next trigger, turning a user compromise into a system compromise.

Look at the System Log: For confirmation and detail, the Task Scheduler events in the Windows Event Log are the final source of truth. Your KQL hunting query gets you 90% there, but the raw event data confirms the exact settings.
