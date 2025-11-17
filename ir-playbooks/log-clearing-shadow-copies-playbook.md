# Incident Response Playbook – Log Clearing and Shadow Copy Deletion (T1070.001 / T1490)

This playbook is triggered by high-severity alerts indicating an attacker is attempting to remove forensic evidence (log clearing) and destroy victim recovery capability (Shadow Copy deletion). This is a definitive action by an adversary attempting a full cleanup before or after primary objectives (like Ransomware or Exfiltration).

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005), Impact (TA0040)
**Technique:** Clear Windows Event Logs (T1070.001), Inhibit System Recovery (T1490)
**Critical Threat:** Loss of forensic data integrity and destruction of Volume Shadow Copies (VSS) which prevents local system recovery.

---

## 1. L2 Analyst Actions (Initial Triage & Forensic Preservation)

The L2 analyst must prioritize isolating the host immediately, as the primary objective of this action is to delay or defeat the incident response effort.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** **Strictly verify** whether any documented, approved maintenance or security tool could explain the event log clearing (`wevtutil cl`) or VSS deletion (`vssadmin delete shadows`). These actions are rarely benign.
2.  **Process Context:** Identify the **process and parent** responsible. Look specifically for:
    * **`wevtutil.exe`** execution with the `cl` (clear) command.
    * **`vssadmin.exe`** execution with the `delete shadows` or `resize shadowstorage` commands.
    * Use of PowerShell cmdlets like `Clear-EventLog`.
3.  **Audit Log Check:** Despite the `wevtutil cl` command, check the **Security Event Log (ID 1102)** immediately for a record of the log clear operation. This is often the final evidence available locally.
4.  **Time Alignment:** Note the **exact time** of the defense evasion. Look for any suspicious activity (like credential access or lateral movement attempts) that occurred immediately **before** this timestamp.

### 1.2 Minimal Triage Data Collection (Criticality: Extreme)

Forensic data is being actively destroyed. Capture this data *before* isolation if possible, or immediately upon isolation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`**
* **Time Range:** The $\pm1$ hour forensic window **preceding** the earliest tamper event.
* **Process Snapshot:** The full command line and hash of the `wevtutil.exe` and `vssadmin.exe` executions.
* **Log Archive:** Export any available **Non-Windows Event Logs** (e.g., Application, Custom, EDR Telemetry) from the host before the disk is touched.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed execution of `vssadmin.exe delete shadows` or `wevtutil cl System / Application / Security`. **Severity is High.**
* The initiating process is a **non-system binary** or a **script host** (`powershell.exe`, `cmd.exe`).
* The user account responsible is **non-administrator** but successfully performed the action (implying privilege escalation already occurred).
* The event log check reveals a large gap in log coverage, suggesting an early, successful tamper.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Scope Restoration)

The L3 analyst focuses on recovering data from external sources and determining the true objective (Ransomware, Data Destruction, or Covert Access).

### 2.1 Full Attack Chain Reconstruction

1.  **Log Reconstruction:** Focus on recovering the erased history using **external sources**:
    * **Domain Controller Logs:** Check the DC Security Log for logins/activity from the compromised host/user.
    * **External SIEM/Log Aggregation:** Pull all relevant logs (Firewall, Proxy, EDR telemetry) to determine activity during the period of local log loss.
    * **EDR/Agent Logs:** Check the EDR agent's internal logs for API calls or process events the attacker attempted to erase.
2.  **VSS Recovery Assessment:** Determine the severity of the Impact (T1490). Confirm whether the deletion was successful and assess the impact on the organization's backup strategy.
3.  **Precursor Activity Analysis:** Based on reconstructed logs, determine the attacker's primary action immediately before the cleanup:
    * **Ransomware:** Preceded by large-scale file enumeration/access.
    * **Covert Access:** Preceded by lateral movement or key export.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1070.001 / T1490 Confirmed):** The highest indicator of aggressive attacker intent, usually preceding a catastrophic event like ransomware deployment or total data destruction.
2.  **Scope the Incident:** Determine the **full time window of lost visibility**. Identify the primary **Impact** category (System Recovery Loss) and any evidence of the attacker's main objective (e.g., encryption keys, data exfiltration points).

---

## 3. Containment – Recommended Actions (Aggressive Defense)

Containment must focus on immediately stopping the Impact phase and securing future forensic integrity.

1.  **Endpoint Isolation:** **MANDATORY** isolate affected endpoints immediately.
2.  **Credential Revocation:** Reset/revoke affected credentials, as the attacker had elevated privileges to perform the actions.
3.  **Service Disruption:** If other systems are affected, suspend any related administrative services or network shares the compromised host/user was interacting with.
4.  **Binary Constraint:** Block the specific use case: Implement an EDR rule to **prevent all execution** of `vssadmin.exe` with the `delete` command, and place strict alerts on any use of `wevtutil.exe cl`.
5.  **Recovery Backup:** Initiate a **full forensic backup** of the current host state immediately, regardless of VSS status, to ensure no further changes are made.

---

## 4. Remediation & Hardening – Strategic Improvements

Focus on reinforcing log preservation, VSS protection, and reducing the capability for local defense evasion.

1.  **Control Failure Analysis:** Identify which control failed: **Endpoint Hardening** (allowing `vssadmin` execution), **Log Forwarding** (failing to preserve logs externally), or **EDR Detection** (not blocking the initial suspicious command).
2.  **Propose and Track Improvements:**
    * **Log Preservation:** Enforce **immediate, external log forwarding** to the SIEM for all critical Event Logs (System, Security, Application) with a fail-safe mechanism.
    * **VSS Protection:** Implement **Immutable Backup Solutions** and utilize EDR's VSS protection features to prevent non-system processes from modifying/deleting Shadow Copies.
    * **Execution Restriction:** Implement **WDAC/AppLocker policies** that explicitly deny the execution of `vssadmin` commands for non-system accounts, or restrict `wevtutil` command line arguments to approved values only.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that log clearing and VSS deletion are the "Point of No Return" and must be treated with the highest severity.

---

## 5. Threat Hunting Queries (KQL Focus)

These KQL fragments target the command line executions that constitute log clearing and recovery inhibition. The focus is on processes with administrative access using specific, malicious arguments.

### 5.1 Hunting Query Example (KQL Only)

This query tightly focuses on the most critical evidence of system impact and defense evasion in a single flow.

```kql
// KQL Query for Log Clearing (T1070) or Shadow Copy Deletion (T1490)
DeviceProcessEvents
| where InitiatingProcessFileName in ('vssadmin.exe', 'wevtutil.exe', 'powershell.exe')
| where InitiatingProcessCommandLine has_any ('delete shadows', 'cl System', 'Clear-EventLog')
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
Concluding Remarks: Strategic Resilience Against Destruction:
This playbook demonstrates a sophisticated understanding that an attacker's goal is often not just to compromise data, but to achieve plausible deniability and system paralysis. When presenting this work, showcase the following critical insights:

The Log Forwarding Imperative: Highlight that in a log clearing scenario, local forensic data is effectively gone. Your strategic response relies entirely on the successful implementation of real-time, immutable external log forwarding (to a SIEM or cold storage). This turns a local catastrophe into a controlled, analyzable event.

Targeting the Impact: Emphasize that T1490 (Shadow Copy Deletion) is a primary indicator of a Ransomware payload being deployed next. Prioritizing the isolation and binary blocking of the process that deletes VSS is the most effective containment action against data encryption.

Defense Through Restriction: Your remediation strategy should show maturity by moving past simple detection to Proactive Prevention. Restricting the execution of administrative utilities like vssadmin.exe with specific malicious arguments is the most powerful control against this particular TTP.
