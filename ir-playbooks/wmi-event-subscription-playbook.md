# Incident Response Playbook – WMI Event Subscription Persistence

This playbook addresses the detection of **WMI Event Subscription Persistence (T1546.003)**. Attackers use Windows Management Instrumentation (WMI), a trusted native component, to establish a persistent, stealthy backdoor. They create a "triple threat": an **Event Filter** (which defines the trigger, e.g., system startup, user logon), a **Consumer** (the payload command to execute), and a **Binding** (which links the two). This method allows code execution without dropping a visible binary or creating typical registry entries, running the payload under the highly trusted `WmiPrvSE.exe` process.

**MITRE ATT&CK Tactic:** Persistence (TA0003), Defense Evasion (TA0005)
**Technique:** Event Triggered Execution: Windows Management Instrumentation Event Subscription (T1546.003)
**Critical Threat:** A highly stealthy, fileless, and system-level persistence mechanism has been established, allowing the attacker to re-execute code upon specific events (like boot-up) even if the initial payload file is removed.

---

## 1. L2 Analyst Actions (Initial Triage & Context Vetting)

The L2 analyst must confirm that the WMI objects created are malicious and not part of authorized management tooling (like SCCM, monitoring, or inventory scripts).

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the WMI objects (Filter, Consumer, or Binding) are associated with any documented, authorized administrative tool, monitoring script, or security agent deployment. **Reject any object that uses ambiguous names, base64 encoding, or commands pointing to user-writable directories.**
2.  **Object Naming Inspection:** Review the names of the three WMI components:
    * **Filter:** Look for generic or suggestive names (e.g., "UpdaterFilter," "ErrorMonitor," "ServiceCheck").
    * **Consumer:** Review the payload (the command to execute). Malicious consumers often contain **obfuscated PowerShell** (base64) or instructions to download external content.
3.  **WMI Activity Source:** Identify the process that **created** the WMI event subscription. Was it `powershell.exe`, `cmd.exe`, or a binary that was executed as part of the initial access? (The execution is often done via `wmic.exe` or `powershell.exe` command-line).
4.  **Payload Location:** If the Consumer executes a binary, verify the location of that binary. If it resides in a user profile, `%TEMP%`, or a publicly writable directory, it is highly suspicious.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The account that **created** the WMI subscription).
* **Time Range:** The $\pm24$ hours surrounding the **creation of the subscription**.
* **Artifacts:** The full **Query (WQL)** used in the Filter, the **Command Payload** in the Consumer, and the **Names of the three WMI objects**.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed WMI Consumer containing **base64-encoded command lines** or references to known malicious file paths. **Severity is Critical.**
* The WMI Filter is configured to trigger on **system startup or user logon**.
* The subscription was created on a **Domain Controller** or a **Critical Infrastructure Server**.
* The subscription was created by a **non-administrator account** and runs with system privileges.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Cleanup)

The L3 analyst must assume the persistence is active and focus on identifying the original point of entry and the payload's intent before removal.

### 2.1 Full Attack Chain Reconstruction

1.  **Creation Traceback:** Trace the activity backward from the creation of the WMI subscription. This is often the final step of the initial access phase. What was the preceding event (e.g., Lsass dump, lateral movement via WinRM)?
2.  **Decode the Payload:** If the Consumer contains obfuscated code, **decode the command line** (e.g., base64) to understand the full extent of the attacker's secondary payload (e.g., C2 beacon, keylogger deployment).
3.  **WMI Namespace Check:** Confirm which WMI namespace the persistence was created in (e.g., `root\cimv2` is common). Look for similar subscriptions in other, less frequently monitored namespaces.
4.  **Execution Analysis:** The WMI payload executes via `WmiPrvSE.exe`. Check the process creation logs for `WmiPrvSE.exe` spawning the malicious Consumer payload (e.g., `powershell.exe`). This confirms successful activation and execution.
5.  **Scope the Environment:** Use WMI management tools (`wmic` or PowerShell) to check other high-value servers for similar named or structured WMI subscriptions.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1546.003 Confirmed):** High-stealth, fileless persistence established.
2.  **Scope the Incident:** The scope includes the **host**, the **identity that created the persistence**, the **source/destination of the command in the Consumer**, and all other endpoints where similar persistence objects are discovered.

---

## 3. Containment – Recommended Actions (Persistence Kill)

Containment must focus on the surgical removal of the three WMI persistence objects and then addressing the execution environment.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **WMI Object Removal:** **IMMEDIATELY and surgically** remove the three malicious WMI components using `wmic` or PowerShell, specifically using their full path and names to delete them. This is the **persistence kill**.
    * **Filter Removal:** `wmic /namespace:\\root\cimv2 path __EventFilter where name="<FilterName>" delete`
    * **Consumer Removal:** `wmic /namespace:\\root\cimv2 path CommandLineEventConsumer where name="<ConsumerName>" delete`
    * **Binding Removal:** `wmic /namespace:\\root\cimv2 path __FilterToConsumerBinding where Filter="__EventFilter.Name=\"<FilterName>\"" delete`
3.  **Process Termination:** Terminate the process that was spawned by the WMI Consumer (e.g., the malicious `powershell.exe` instance).
4.  **Credential Revocation:** Reset/revoke the credentials of the account used to **create** the persistence, as that account was compromised to initiate the attack.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must focus on strictly limiting WMI access and ensuring WMI activity is properly audited.

1.  **Control Failure Analysis:** Identify which control failed: **Auditing** (failing to capture the creation of the persistence objects), or **Privilege Control** (allowing a user to create system-level persistence).
2.  **Propose and Track Improvements:**
    * **WMI Auditing:** Enforce and verify that **WMI activity auditing** is enabled, specifically for the `Create`, `Modify`, and `Delete` methods on the WMI classes used for event subscriptions.
    * **Detection Tuning:** Implement a high-fidelity detection rule that flags any WMI Consumer containing **known malicious strings** (e.g., `IEX`, `DownloadString`, base64 strings) or pointing to **user-writable file paths**.
    * **Restrict WMI Creation:** Review and restrict the permissions on the WMI namespaces to limit which user accounts can create event filters, consumers, and bindings. Only approved management accounts should have this capability.
    * **PSRP Logging:** Ensure full PowerShell Script Block and Module Logging is enabled to capture and decode any PowerShell payload that the WMI Consumer attempts to execute.
3.  **Documentation and Knowledge Transfer:** Update the Persistence Playbook and train analysts to use **`wmic` or `Get-WmiObject`** commands to quickly enumerate and verify WMI objects during a live incident.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for the execution of the WMI host process (`WmiPrvSE.exe`) spawning suspicious child processes, which is the final execution step of the WMI persistence chain.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for WMI Event Subscription Execution (T1546.003)
DeviceProcessEvents
| where Timestamp > ago(7d)
// 1. Target the process that executes the malicious payload
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
// 2. Identify the suspicious payload being launched
| where FileName in ("powershell.exe", "cmd.exe", "mshta.exe")
// 3. Look for strong indicators of malicious behavior in the command line
| where ProcessCommandLine has_any (
    "-EncodedCommand", // Base64 encoding
    "Invoke-Expression", // IEX
    "DownloadString",
    "certutil", "bitsadmin"
)
| extend ExecutionUser = AccountName

```
Concluding Remarks: The Invisible Backdoor

WMI persistence is one of the most difficult types of persistence to find because it is fileless and uses a core Windows feature. The attacker's code isn't on the disk; it's a configuration entry in the operating system's object repository.

Don't Look at the Disk: When dealing with WMI persistence, stop looking for files! The threat is the WMI object itself. Your primary containment step must be the surgical deletion of the Filter, Consumer, and Binding.

The Process Context: The giveaway is always WmiPrvSE.exe acting as the parent process to a malicious command (powershell.exe). This is the execution signature you must prioritize in your detection rules.

Clean the Source: Remember that WMI objects were created by a compromised account on a different system. Your ultimate remediation requires finding that initial point of compromise.
| extend LaunchedCommand = ProcessCommandLine
| project Timestamp, DeviceName, ExecutionUser, FileName, LaunchedCommand, InitiatingProcessCommandLine
| order by Timestamp desc
