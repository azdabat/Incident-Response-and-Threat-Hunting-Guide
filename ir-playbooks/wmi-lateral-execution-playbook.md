# Incident Response Playbook – WMI-based Lateral Execution

This playbook addresses **Lateral Movement (TA0008)** and **Execution (TA0002)** using **Windows Management Instrumentation (WMI)** (T1021.006). Attackers leverage compromised credentials to execute commands remotely on target systems using the WMI protocol, often via tools like `wmic.exe` or PowerShell cmdlets (`Invoke-WmiMethod`). WMI is a trusted native Windows component, allowing attackers to execute payloads under the guise of legitimate system administration, typically spawning malicious child processes from the highly trusted **`wmiprvse.exe`** (WMI Provider Host).

**MITRE ATT&CK Tactic:** Lateral Movement (TA0008), Execution (TA0002)
**Technique:** Remote Services: Windows Management Instrumentation (T1021.006)
**Critical Threat:** Confirmed credential compromise and highly stealthy command execution on a remote target, indicating hands-on-keyboard activity that is hard to detect due to the use of trusted system binaries.

---

## 1. L2 Analyst Actions (Initial Triage & Protocol Validation)

The L2 analyst must confirm that the WMI session was unauthorized and used to deliver a malicious payload, focusing on the execution context on the **Destination Host**.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the remote command execution is tied to any documented, scheduled, or emergency administrative script, patching activity, or deployment. **Reject any execution of commands that involve downloading code, base64 encoding, or known malicious hashes.**
2.  **Network and Protocol Check:** Identify the **Source Host** (the pivoting point) and the **Destination Host** (the victim). WMI traffic typically starts over **Port 135 (DCOM/RPC)** and then moves to dynamic ports.
3.  **Execution Signature (Destination Host):** Review process creation logs on the **Destination Host**. Look for the **`wmiprvse.exe`** process spawning suspicious child processes, which is the primary indicator of WMI-based execution:
    * **Suspicious Child Processes:** Look for `powershell.exe` (often with long, base64-encoded command lines), `cmd.exe`, or non-system executables being launched.
4.  **Credential Check:** Identify the **Account Name** used for the remote session. Is this a privileged admin, a service account, or a recently compromised user?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId` (Both Source and Destination Hosts).
* `AccountName` / **`UPN`** (The compromised identity used for WMI execution).
* **Time Range:** The $\pm1$ hour surrounding the remote execution event.
* **Artifacts:** The **Source Host IP**, the **Full Command Line** executed by the child process of `wmiprvse.exe`, and the **Execution Hash** of any dropped payload.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed unauthorized command execution over WMI. **Severity is Critical.**
* The command execution involves **base64 encoding** or known **payload delivery utilities** (`certutil`, `bitsadmin`, `IEX`).
* The source or destination host is a **Domain Controller** or a **Critical Server** (Tier 0 asset).
* The compromised identity is a **Domain Administrator** or highly privileged service account.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Timeline Reconstruction)

The L3 analyst must assume the attacker has achieved control over the credential and is moving systematically through the network.

### 2.1 Full Attack Chain Reconstruction

1.  **Credential Source (Source Host Focus):** Trace the activity on the **Source Host** backward. How was the credential for the WMI session obtained? (e.g., Lsass dump, credential scraping, or phishing). This is the key to identifying the true point of ingress.
2.  **Payload Analysis:** Decode any base64-encoded command lines executed on the destination host. Determine the payload's intent, focusing on:
    * **Persistence:** Was a new Scheduled Task or WMI Event Subscription created?
    * **Credential Access:** Was the remote command used to dump credentials from the new victim machine?
    * **Discovery:** Execution of detailed domain reconnaissance commands.
3.  **WMI Query Analysis:** If the WMI method was used via PowerShell, review the full command line to identify the specific WMI class and method called (e.g., `Win32_Process::Create`).
4.  **Scope the Domain:** Review WMI execution logs across the entire domain for other successful or failed execution attempts using the **compromised account**.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1021.006 Confirmed):** Hands-on-keyboard lateral movement using compromised credentials and fileless execution.
2.  **Scope the Incident:** The scope includes the **initial compromised host**, the **final victim host**, all **intermediate hosts** the attacker may have touched, and the **compromised credential**.

---

## 3. Containment – Recommended Actions (Credential Kill & Execution Vector Block)

Containment must focus on invalidating the compromised credentials and stopping the execution vector.

1.  **Isolate Endpoint:** **MANDATORY** isolate the **Destination Host** where the malicious payload was executed.
2.  **Credential Revocation:** **IMMEDIATELY** reset/revoke the password for the **compromised identity**. If it's a service account, suspend the account before resetting the password to prevent application failure, then update all services using it.
3.  **Remove Persistence:** Search for and **remove all persistence mechanisms** (Scheduled Tasks, WMI Event Subscriptions, services) created by the executed remote command.
4.  **Block Lateral Movement:**
    * **Firewall Rule:** On all critical endpoints, configure the firewall to **deny inbound RPC traffic (Port 135)** from all but a defined list of administrative hosts or jump servers.
    * **AppLocker/WDAC:** Implement a rule to prevent **`wmiprvse.exe`** from spawning new instances of suspicious utilities like `powershell.exe` or `cmd.exe` when the command line contains high-risk strings (like base64).

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must enforce a least-privilege identity model and restrict remote administrative execution.

1.  **Control Failure Analysis:** Identify which control failed: **Identity Management** (credential theft/weak credentials), or **Endpoint Protection** (failing to detect the process tree of `wmiprvse.exe` spawning a shell).
2.  **Propose and Track Improvements:**
    * **Credential Hardening:** Enforce **Just-in-Time (JIT)** administrative access and use **Privileged Access Workstations (PAW)** for all remote management. Implement MFA for all administrative accounts.
    * **Network Segmentation:** Use host firewalls (GPO/Intune) to enforce that **WMI traffic (RPC/DCOM)** is only allowed from administrative subnets.
    * **Endpoint Detection Tuning:** Implement a high-fidelity detection rule that specifically flags **`wmiprvse.exe` spawning a child process** that has a **base64-encoded command line** or calls known LOLBIN utilities.
    * **PowerShell Logging:** Ensure **full PowerShell Script Block Logging and Module Logging** is enabled across all endpoints to capture and decode all remote commands.
3.  **Documentation and Knowledge Transfer:** Update the Identity Governance policy and the Threat Model, emphasizing WMI as a high-risk lateral movement tool that requires strict network and identity controls.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for the signature of a malicious WMI execution: the `wmiprvse.exe` process spawning a shell with suspicious command-line arguments.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for WMI Lateral Execution (T1021.006)
DeviceProcessEvents
| where Timestamp > ago(7d)
// 1. Target the WMI execution host process
| where InitiatingProcessFileName =~ "wmiprvse.exe"
// 2. Identify suspicious child processes spawned by the remote session
| where FileName in ("powershell.exe", "cmd.exe", "mshta.exe")
// 3. Look for strong indicators of malicious payload delivery/execution
| where ProcessCommandLine has_any (
    "-EncodedCommand", // Base64 encoding
    "Invoke-Expression", // IEX
    "DownloadString", 
    "certutil", "bitsadmin", // Native download utilities
    "lsass" // Credential access attempts
)
| extend RemoteUser = InitiatingProcessAccountName
| extend AttackerCommand = ProcessCommandLine
| project Timestamp, DeviceName, RemoteUser, FileName, AttackerCommand, InitiatingProcessCommandLine
| order by Timestamp desc
```
Concluding Remarks: The Invisible Bridge

WMI is one of the most stealthy and powerful techniques an attacker can use because it bypasses many security controls that rely on monitoring file creation or unsigned binaries.

The Chain is Key: The only way to prove malicious intent is by showing the full chain: Compromised Credential -> Remote WMI Call -> wmiprvse.exe -> Malicious Command.

Decoded Commands are Gold: Always prioritize decoding the command line. This is the only way to know the attacker's true mission on the victim host.

Containment is Credential-Focused: Because WMI requires credentials, the fastest and most effective containment action is always to reset the password of the compromised user account.
