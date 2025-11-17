# Incident Response Playbook – WSL Cron-based Persistence

This playbook addresses **Persistence (TA0003)** and **Execution (TA0002)** using **Windows Subsystem for Linux (WSL)**, specifically leveraging the **Cron scheduling daemon (T1053.003)** within the Linux distribution. Attackers use WSL to establish a native, fileless, and cross-platform persistence mechanism. By modifying a user's crontab entry, they can schedule the execution of a malicious script or binary within the Linux environment, which can then interact with the Windows host, all while running under the trusted `wsl.exe` or `init` processes.

**MITRE ATT&CK Tactic:** Persistence (TA0003), Execution (TA0002), Defense Evasion (TA0005)
**Technique:** Scheduled Task/Job: Cron (T1053.003), Implicit Execution via Windows Subsystem for Linux (WSL)
**Critical Threat:** A cross-platform persistence method is active, allowing the attacker to re-execute code upon specific time intervals or system reboots, often bypassing traditional Windows-only EDR persistence checks.

---

## 1. L2 Analyst Actions (Initial Triage & Environment Vetting)

The L2 analyst must confirm that the Cron job is malicious and not part of an authorized Linux-based automation or internal tooling.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the WSL environment or the specific Cron job is tied to any documented, authorized developer tooling, CI/CD pipeline, or monitoring script. **Reject any Cron job that executes highly obfuscated commands, connects to external IPs, or runs from a non-standard user's crontab.**
2.  **Execution Context Check:** Review the Windows execution logs. The execution chain will look like: **`svchost.exe`** (or a system service) **-> `wsl.exe` (or `wslhost.exe`) -> `init` -> Cron daemon -> malicious command.** The presence of `wsl.exe` spawning subsequent processes outside of a direct user console session is suspicious.
3.  **Cron Payload Inspection:** Identify the command or script being executed by the Cron job. Look for:
    * **External Downloads:** Commands like `curl` or `wget` pulling content from non-approved IPs/domains.
    * **Windows Interaction:** Commands that use the **`/mnt/c/`** path or directly call Windows executables (`cmd.exe`, `powershell.exe`) from within the WSL environment.
    * **Obfuscation:** High entropy, base64-encoded strings, or excessive use of pipes and variable redirection.
4.  **User Identity:** Identify the user whose crontab was modified. Was it a high-privilege user or a standard developer account?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The Windows user context of the running WSL session).
* **Time Range:** The $\pm12$ hours surrounding the Cron job execution or the time of the Cron file modification.
* **Artifacts:** The **WSL distribution name** (e.g., Ubuntu, Kali), the **Full Cron Job entry** (the time schedule and the command), and the **Source Process** that originally modified the crontab file (the Initial Access vector).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed Cron job execution that initiates **outbound network connections** or executes a **base64-encoded command** on the Windows host. **Severity is Critical.**
* The Cron job executes as the **Linux root user** or a highly privileged system account.
* The activity is observed on a **critical server** or a host that does not have an authorized need for WSL.
* Similar activity appears on **multiple endpoints**.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Cross-Platform Remediation)

The L3 analyst must assume the attacker has executed code with high privilege and focus on eliminating the persistence within the Linux environment.

### 2.1 Full Attack Chain Reconstruction

1.  **Crontab Modification Trace:** Determine the exact time and method used to modify the crontab file (usually `/var/spool/cron/crontabs/<user>`). This links the persistence to the **Initial Access Vector**.
2.  **Payload Analysis:** Analyze the executed script or command (the consumer of the Cron job). Determine its primary function:
    * **C2:** Is it beaconing to an external IP?
    * **Lateral Movement:** Is it trying to access network shares or credentials using Windows tools?
    * **Dropper:** Is it dropping a secondary malicious binary onto the Windows filesystem (e.g., in a temporary directory)?
3.  **WSL Integrity Check:** Review the WSL filesystem for other unauthorized binaries or scripts, particularly in common Linux persistence locations (`/etc/rc.local`, systemd services, or user home directories).
4.  **Scope the Environment:** Identify the type of data the attacker may have accessed via the Cron job execution, especially if it mounted the user's home drive via `/mnt/c/Users/<User>`.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1053.003 Confirmed):** Cross-platform persistence and execution achieved.
2.  **Scope the Incident:** The scope includes the **host**, the **malicious Cron job entry**, the **WSL distribution**, and the **malicious script/binary** used by the Cron job.

---

## 3. Containment – Recommended Actions (Persistence Kill & Isolation)

Containment must break the Linux-based persistence and limit the WSL environment's ability to communicate with the Windows host.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Persistence Kill (Crontab Removal):** **IMMEDIATELY** stop the Cron daemon (`sudo service cron stop`) and then **remove the malicious entry** from the affected user's crontab using the command: `crontab -r`.
3.  **Payload Removal:** If the Cron job executes a script or binary (either in WSL or on the Windows side), **delete that file and its hash**.
4.  **WSL Control (Temporary):** If WSL is not required for business function, **temporarily disable the WSL service** or **unregister the compromised distribution** (`wsl --unregister <DistroName>`).
5.  **Credential Revocation:** Reset/revoke affected credentials, especially if the Cron job ran with high privileges or attempted to access domain resources.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the Windows host against Linux-based execution and restrict WSL's capabilities.

1.  **Control Failure Analysis:** Identify which control failed: **EDR Behavioral Monitoring** (failing to connect the `wsl.exe` execution to the malicious action), or **Initial Access/Privilege Control** (allowing the attacker to modify the crontab).
2.  **Propose and Track Improvements:**
    * **WSL Restriction:** Implement a **WDAC or AppLocker policy** that allows `wsl.exe` to run but **prevents it from launching suspicious child processes** (e.g., `powershell.exe`, `cmd.exe`, `certutil`) unless explicitly authorized.
    * **Command Line Auditing:** Refine detection logic to specifically flag **`wsl.exe` or `bash.exe` execution followed by outbound network connections** or the use of **Linux download utilities** (`curl`, `wget`) with suspicious parameters.
    * **WSL Configuration:** If authorized, configure WSL to run as a **standard user** by default and enforce strong Linux security practices (e.g., auditing Cron changes).
    * **File Integrity Monitoring:** Implement File Integrity Monitoring (FIM) for the crontab directories to alert on unauthorized modifications to scheduled jobs.
3.  **Documentation and Knowledge Transfer:** Update the Persistence Playbook and train analysts on how to perform basic **Linux triage commands** (`crontab -l`, `history`, `ls -la`) within a remote WSL environment.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for the primary signature of WSL persistence: the Windows processes responsible for running Linux commands spawning suspicious child processes.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for WSL Cron-based Execution (T1053.003)
DeviceProcessEvents
| where Timestamp > ago(7d)
// 1. Target the Windows processes that host the Linux environment
| where InitiatingProcessFileName in ("wsl.exe", "wslhost.exe", "bash.exe")
// 2. Identify the subsequent suspicious processes launched
| where FileName in ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "certutil.exe", "bitsadmin.exe")
// 3. Look for strong indicators of malicious behavior
| where ProcessCommandLine has_any (
    "/mnt/c/", // Explicitly accessing the Windows file system
    "http://", "https://" // Outbound network connections
)
| extend ExecutionUser = AccountName
| extend LaunchedCommand = ProcessCommandLine
| project Timestamp, DeviceName, ExecutionUser, FileName, LaunchedCommand, InitiatingProcessCommandLine
| order by Timestamp desc
```
Concluding Remarks: The Dual-Identity Threat

The abuse of WSL for persistence is a dual-identity attack. The initial execution comes from a trusted Windows process, but the persistence mechanism is entirely Linux-native. You need to think in two operating system languages.

It’s an Inversion: The attacker is using Linux tools (cron, curl) to attack the Windows operating system. Your detection rules must account for Windows binaries spawning Linux tools that then spawn Windows binaries again.

The crontab is the Key: The fastest way to contain this threat is to delete the malicious entry from the crontab file. If you kill the Cron job, you kill the persistence.

Harden the Bridge: WSL is a bridge. You must harden the bridge's endpoints by restricting what wsl.exe is allowed to execute on the Windows side using application control.
