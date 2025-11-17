# Incident Response Playbook – Malicious Service Creation Persistence

This playbook addresses the creation of an unauthorized **Service (T1543.003)** for **Persistence** and **Defense Evasion**. Attackers use utilities like `sc.exe` or the Service Control Manager API to create a new, often masqueraded, Windows Service. Since services run automatically and often with **SYSTEM** privileges, this is a highly effective, resilient, and high-impact method of maintaining long-term, high-privilege access.

**MITRE ATT&CK Tactic:** Persistence (TA0003), Privilege Escalation (TA0004), Execution (TA0002)
**Technique:** Windows Service (T1543.003), Service Execution (T1569.002)
**Critical Threat:** A system-level backdoor is established, granting the attacker automatic, high-privilege code execution upon system boot, making remediation extremely difficult without specific administrative actions.

---

## 1. L2 Analyst Actions (Initial Triage & Service Metadata)

The L2 analyst must focus on the creation process and the suspicious metadata of the new service.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the service name, binary path, and display name are tied to any approved software installation, vendor update, or administrative deployment. **Reject services with suspicious names (e.g., misspelled legitimate services like "windeos" or "svshost") or those pointing to non-standard executable paths (e.g., `%TEMP%`, hidden directories).**
2.  **Creation Process Check (MDE Focus):** Identify the parent process that created the service. Look for:
    * **Service Control Utility:** Execution of `sc.exe` with the `create` argument.
    * **Installer Tooling:** Execution of `cmd.exe` or `powershell.exe` making calls to the Service Control Manager API.
3.  **Service Configuration Analysis:** Inspect the service parameters immediately:
    * **`ServiceFileName`:** The full path of the malicious binary the service executes.
    * **`StartType`:** Is it set to **Automatic**? This guarantees execution upon reboot.
    * **`ServiceAccount`:** Does it run as **LocalSystem**? This guarantees maximum privileges.
    * **`Display Name` / `Description`:** Is the description vague or mimicking a known Microsoft service?
4.  **Payload Status:** Check the status of the malicious binary (`ServiceFileName`). Is the file present? Has it been scanned and flagged by the EDR?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The administrator account used to create the service, required for this type of action).
* **Time Range:** The $\pm1$ hour surrounding the service creation event.
* **Service Artifact:** The **Service Name**, the **Service Binary Path** (`ServiceFileName`), and the **Service Account** (e.g., `LocalSystem`).
* **Full Process Chain:** The process tree leading to the service creation command (`sc.exe` or equivalent).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed service creation with **LocalSystem** privileges pointing to an unauthorized or unknown binary. **Severity is Critical.**
* The malicious service has already successfully **executed** and made an **external network connection** (C2).
* The service creation is linked to a **Domain Administrator** or other Tier 0 account compromise.
* **Service creation activity** is observed on multiple critical servers or Domain Controllers.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Payload Neutralization)

The L3 analyst must focus on the high privileges of the service and dismantle its ability to execute.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Corroboration:** Trace the creation process back to the initial access or privilege escalation method used to gain the necessary administrator rights to create a service.
2.  **Payload Analysis:** Analyze the malicious service binary (`ServiceFileName`):
    * **Intent:** What is its function (e.g., remote access Trojan, keylogger, lateral movement utility)?
    * **IOC Extraction:** Extract all known Indicators of Compromise (C2 URLs, domains, hashes) from the binary.
3.  **Lateral Movement Audit:** If the malicious service has run, check if it was used to execute code on other systems (e.g., using `psexec` or WMI to jump laterally).
4.  **Alternate Persistence Check:** Check for other persistence mechanisms created by the same attacker (Registry Run keys, Scheduled Tasks) to ensure complete removal.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1543.003 Confirmed):** High-impact persistence and privilege escalation.
2.  **Scope the Incident:** The scope includes the **host with the service**, the **compromised administrative identity**, and any subsequent systems accessed by the service's payload.

---

## 3. Containment – Recommended Actions (Service Termination & Removal)

Containment must immediately stop the service execution and remove its ability to run again.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Stop and Delete Service:** **MANDATORY**
    * Use `sc.exe stop [ServiceName]` to terminate the running process.
    * Use `sc.exe delete [ServiceName]` to remove the service definition from the SCM database and the Registry.
3.  **Quarantine Payload:** Quarantine and delete the service binary file (`ServiceFileName`) and **block its hash** organization-wide.
4.  **Credential Revocation:** Reset/revoke the credentials of the account used to **create** the service, as this account is confirmed compromised.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the operating system against unauthorized service creation.

1.  **Control Failure Analysis:** Identify which control failed: **Privilege Access Management** (allowing administrative access to create the service), or **Application Control** (failing to block the execution of the malicious service binary).
2.  **Propose and Track Improvements:**
    * **Application Control (WDAC):** Use **Windows Defender Application Control (WDAC)** to strictly restrict the creation and execution of service binaries. This is the **strongest preventative measure**.
    * **Restrict `sc.exe`:** Implement a monitoring or constraint rule to specifically alert/block non-approved processes from executing `sc.exe` with the `create` parameter.
    * **LAPS for Service Accounts:** Ensure any local service accounts used by legitimate applications have randomized passwords via LAPS.
    * **Service Creation Logging:** Ensure **Security Event ID 4697** (A service was installed in the system) is actively ingested by Sentinel for comprehensive, native tracking of service creation.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, highlighting that service creation is often done using a compromised administrator account, making it critical to trace the initial compromise chain.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query targets the execution of `sc.exe` with the `/create` parameter, which is the native and most common way attackers create services for persistence.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Malicious Service Creation (T1543.003)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any ("create", "config", "binpath") // Service creation or modification commands
| where ProcessCommandLine has "binpath=" // Focus on the binary path definition
| extend ServiceName = extract(@"\s+create\s+(\w+)\s+", 1, ProcessCommandLine)
| extend ServicePath = extract(@"binpath=""?([^\s""]+)""?", 1, ProcessCommandLine) // Extract the path to the executable
| project Timestamp, DeviceName, AccountName, ServiceName, ServicePath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
Concluding Remarks: Highest Privilege, Highest Priority

Malicious Service Creation is a Level 4 Emergency. This isn't just persistence; it's system-level persistence, often giving the attacker the highest possible privileges on the machine (LocalSystem).

Execution Guarantee: A malicious service is guaranteed to run on the next system boot, making the compromise highly resilient. Your first priority is deletion, not just stopping, to prevent the next run.

The Privilege Pivot: Since creating a service requires admin rights, this event confirms a prior privilege escalation or the compromise of a highly privileged account. You must now pivot to trace how those credentials were stolen or escalated.

Look at the Path: The most reliable indicator is the binpath (binary path). If that path leads to a temporary folder or a newly dropped, unknown executable, it's almost certainly malicious.
