# Incident Response Playbook – WSL-based Execution and Scripting

This playbook addresses **Execution (TA0002)** and **Defense Evasion (TA0005)** where attackers utilize the **Windows Subsystem for Linux (WSL)** as a modern Living-Off-the-Land Binary (LOLBIN). Attackers use `wsl.exe` or `bash.exe` to execute Linux commands (`curl`, `wget`, `python3`) for payload delivery, staging, and executing Windows binaries (like `powershell.exe`) from the highly trusted Linux environment. This technique leverages the trusted cross-platform bridge to bypass standard Windows security policies.

**MITRE ATT&CK Tactic:** Execution (TA0002), Defense Evasion (TA0005)
**Technique:** Implicit Execution via Windows Subsystem for Linux (WSL), Scripting (T1059)
**Critical Threat:** An attacker is using a native, trusted Windows feature (`wsl.exe`) to execute code from a Linux context, obscuring the true payload source and often avoiding detection from tools focused only on Windows command-line analysis.

---

## 1. L2 Analyst Actions (Initial Triage & Execution Trace)

The L2 analyst must confirm that the activity within the WSL environment is unauthorized and used to conduct malicious actions on the Windows host.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the process chain involving `wsl.exe` is tied to any documented, authorized developer tooling, CI/CD, or administrative script. **Reject any execution that involves downloading content from external, non-approved IPs/domains, or that executes Windows administrative commands.**
2.  **Execution Signature:** Identify the suspicious process chain, which typically involves **`wsl.exe`** or **`bash.exe`** spawning a **Windows-native binary** (`powershell.exe`, `cmd.exe`, `certutil.exe`). This cross-OS spawning is the primary indicator of abuse.
3.  **Command Line Inspection (Linux Side):** Review the command line arguments passed to `wsl.exe` or `bash.exe`. Look for:
    * **Download Utilities:** The use of Linux tools like **`curl`**, **`wget`**, or **`python3`** being used to download executables or scripts.
    * **Obfuscation/Encoding:** Heavily encoded shell commands or long strings passed to `bash -c`.
    * **Mount Access:** Explicit access to the Windows file system via the **`/mnt/c/`** path.
4.  **Child Process Vetting (Windows Side):** Examine the child process spawned by the Linux environment. Does it have suspicious command-line arguments (e.g., base64, IEX) or a known malicious hash?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The Windows user context of the running WSL session).
* **Time Range:** The $\pm1$ hour surrounding the WSL execution event.
* **Artifacts:** The **Full command line** of the `wsl.exe` process, the **Full command line** of the spawned Windows child process (`powershell.exe`), and the **Hash of any dropped file** in the Windows environment.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed instance of **`wsl.exe`** executing a Windows binary with a **base64-encoded command line** or utilizing download utilities for external content. **Severity is Critical.**
* The activity is observed on a **critical server** or a host that is not used for development/testing.
* The execution chain involves elevated Windows privileges (e.g., the Windows child process runs as SYSTEM).
* Similar activity appears on **multiple hosts**, indicating a spreading campaign.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Payload Analysis)

The L3 analyst must assume the attacker has executed code with high privilege and must determine the payload's source and intent.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Vector (Preceding Execution):** Trace the activity backward from the initial `wsl.exe` execution. How did the attacker gain access to execute the WSL command (e.g., compromised browser, phishing, or a malicious document executing a script)?
2.  **Payload Source and Decoding:** If the Linux command downloaded content, retrieve the URL or IP. If the Windows command was base64-encoded, **decode the command line** to understand the true payload (e.g., C2 beaconing, credential dumping, persistence creation).
3.  **File Staging:** Check both the Windows file system (e.g., `%TEMP%`) and the mounted Linux file system (accessible via `/mnt/c/`) for staged scripts or binaries dropped by the WSL command.
4.  **Post-Execution Activity:** Analyze subsequent activity spawned by the malicious Windows process. Look for:
    * **Persistence:** Creation of Scheduled Tasks, Run Keys, or WMI subscriptions.
    * **Network Connections:** Outbound C2 connections or internal scanning activity.
    * **Discovery:** Execution of commands to map the network or domain.
5.  **Scope the Environment:** Determine if the attacker gained access to the actual Linux filesystem and if persistence was established there (e.g., via Cron, as detailed in the separate playbook).

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1059 Confirmed):** Cross-platform scripting and execution used for defense evasion.
2.  **Scope the Incident:** The scope includes the **host**, the **malicious command/script content**, the **Linux distribution instance**, and any **persistence mechanisms** established on either the Windows or Linux side.

---

## 3. Containment – Recommended Actions (Execution Kill & Service Control)

Containment must break the current execution chain and severely limit the ability of the WSL environment to function as an attack platform.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Process Termination:** **IMMEDIATELY** terminate the malicious child process (e.g., `powershell.exe`) and, if necessary, the parent **`wsl.exe`** process.
3.  **WSL Control (Temporary):** If the threat is severe and business impact allows:
    * **Unregister Distribution:** Unregister the compromised Linux distribution (`wsl --unregister <DistroName>`) to wipe the Linux environment clean.
    * **Disable Feature:** Temporarily disable the "Windows Subsystem for Linux" Windows feature.
4.  **Credential Revocation:** Reset/revoke affected credentials, as the execution may have occurred with the user's current privileges, potentially leading to credential exposure.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must implement strict controls on what the WSL environment is allowed to execute on the Windows host.

1.  **Control Failure Analysis:** Identify which control failed: **Application Control** (failing to prevent **`wsl.exe`** from launching a malicious script/binary), or **Network Filtering** (allowing the Linux environment to download malicious payloads).
2.  **Propose and Track Improvements:**
    * **WDAC/AppLocker Enforcement:** Implement a **WDAC or AppLocker policy** that allows **`wsl.exe`** to execute only if it does **not** launch highly suspicious Windows binaries (`powershell.exe`, `cmd.exe`) or binaries with suspicious command lines (e.g., base64, IEX). This breaks the attack chain.
    * **Restrict WSL Network Access:** Implement firewall rules or proxy policies to restrict **outbound network connections** originating from the WSL virtual network adapter to only whitelisted management or update domains.
    * **Command Line Auditing:** Refine detection logic to flag any instance of **`wsl.exe` or `bash.exe`** using **`certutil`**, **`bitsadmin`**, or **`IEX`** in their command lines, as these are strong indicators of malicious staging.
    * **Disable Unnecessary Feature:** If WSL is not required, permanently disable the Windows feature to remove the attack surface entirely.
3.  **Documentation and Knowledge Transfer:** Update the Execution Playbook and train analysts on the common WSL/Linux utilities used for download and execution (`curl`, `wget`, `python3`).

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for the signature of a malicious cross-OS payload delivery: the Linux environment executing a Windows binary with high-risk command-line arguments.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for WSL-based Execution (TA0002, T1059)
DeviceProcessEvents
| where Timestamp > ago(7d)
// 1. Target the Windows processes that host the Linux execution
| where InitiatingProcessFileName in ("wsl.exe", "wslhost.exe", "bash.exe")
// 2. Identify the Windows binaries being launched by the Linux environment
| where FileName in ("powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe", "cscript.exe")
// 3. Look for strong indicators of malicious payload delivery/execution in the child process
| where ProcessCommandLine has_any (
    "-EncodedCommand", // Base64 encoding
    "Invoke-Expression", // IEX
    "DownloadString", 
    "/mnt/c/", // Explicitly accessing the Windows file system
    "http://", "https://" // Potential download attempts
)
| extend ExecutionUser = AccountName
| extend LaunchedCommand = ProcessCommandLine
| project Timestamp, DeviceName, ExecutionUser, FileName, LaunchedCommand, InitiatingProcessCommandLine
| order by Timestamp desc
```
Concluding Remarks: The Best of Both Worlds

The abuse of WSL represents a major shift in attack methodology, combining the stealth of Linux tooling with the access of a trusted Windows binary. It's a perfect example of a modern, multi-stage attack.

It’s the Junction Point: Your attention must be focused on the moment wsl.exe spawns the Windows child process. That is the point of no return where the Linux payload executes on the Windows system.

Never Trust wsl.exe's Children: Since wsl.exe is a legitimate binary, you must place your security reliance on the behavior and command line of its child processes. If it's launching an encoded PowerShell script, it's hostile.

Control the Bridge: The most robust long-term defense is using Application Control (WDAC/AppLocker) to restrict the execution privileges of processes launched by the WSL bridge.
