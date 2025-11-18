# SOC Investigation Spine: WMI Event Subscription Persistence – T1546.003

**Explanation:** This playbook analyzes the sophisticated persistence technique that utilizes **WMI Event Subscriptions** (T1546.003). This is a fileless method where the attacker registers a permanent, three-part trigger-action mechanism within the WMI repository: a **Filter** (the event query), a **Consumer** (the payload/script to execute), and a **Binding** (linking the Filter to the Consumer). Execution is managed entirely by the **WMI Provider Host (`WmiPrvSE.exe`)** process, making it extremely difficult to detect without deep WMI logging. The most reliable **Anchor Point** is the **creation of the permanent WMI event subscription** itself, logged in the WMI-Activity operational logs.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078 (Valid Accounts) / T1068 (Privilege Escalation) | **Endpoint/Identity:** Attacker gains code execution and obtains **Administrator/SYSTEM** privileges (required for permanent subscriptions). | **Logon Event:** Successful high-privilege logon to the target host. |
| **Execution / Foothold** | T1059 (Command-Line Scripting) | **Process:** The attacker executes `wmic.exe` or PowerShell cmdlets (`New-WmiFilter`, `Set-WmiInstance`) to create the persistence components. | **Process Event:** Execution of **`wmic.exe`** or **`powershell.exe`** with WMI-related command-line arguments. |
| **WMI Persistence (ANCHOR)**| **T1546.003 (WMI Event Subscription)** | **WMI Logs/Process:** The creation of the Filter, Consumer (payload), and Binding is recorded in the operational WMI logs. | **WMI-Activity Operational Log:** **Event ID 5858/5859** showing object creation (`__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`). |
| **Execution After Trigger** | T1059 (Scripting) | **Process:** The WMI service detects the trigger event, causing the WMI Provider Host to execute the payload. | **Process Anomaly:** **`WmiPrvSE.exe` Parent** → **`cmd.exe` or `powershell.exe` Child**. |
| **Impact / Lateral Movement** | T1021 (Remote Services) / T1041 (Exfiltration) | **Network/Identity:** The payload executes, performs reconnaissance, or establishes a C2 channel. | **Network Log:** Outbound connection from the payload process to an external C2 IP or domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence WMI & Process IOCs

1.  **WMI Event Log Artifacts (The WMI Tell):** The most critical evidence is found within the **Microsoft-Windows-WMI-Activity/Operational Log**. L3 analysts must inspect the following events:
    * **Event ID 5858/5859:** Records activity related to the WMI provider. Look for the creation of WMI objects:
        * **`__EventFilter`:** Examine the `Query` field. Suspicious queries include common persistence triggers like `SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA 'Win32_LogonSession' and TargetInstance.LogonType = 2` (User Logon).
        * **`__EventConsumer`:** Examine the `CommandLineTemplate` or `ScriptText` field. This reveals the actual payload (e.g., encoded PowerShell, a reference to a dropped executable).
        * **`__FilterToConsumerBinding`:** Confirms the malicious link between the filter and consumer.
    * **Suspicious Namespace:** WMI is heavily namespaced. Malicious activity is often found in non-standard or highly targeted namespaces.
2.  **Process Chain Anomaly:** When the persistence mechanism triggers, the execution chain is unique and highly suspicious:
    * **Parent Process:** **`WmiPrvSE.exe`** (WMI Provider Host, runs with high privileges).
    * **Child Process:** **`powershell.exe`**, **`cmd.exe`**, or a custom payload.
    * **Context:** A WMI host process directly spawning a command shell is a definitive sign of WMI abuse.
3.  **Process Command Line:** The command line of the spawned child process will contain the full payload, often highly obfuscated or base64 encoded, which must be decoded to understand the final objective.

### File, Network, and Identity IOCs

1.  **Repository File Analysis:** While fileless, WMI event subscriptions are stored in the **WMI repository** (`%windir%\System32\wbem\Repository`). A forensic image of this file can be analyzed for evidence of the malicious objects.
2.  **Network Activity:** The final payload (executed by the WMI chain) will attempt to establish communication. Check network logs for any outbound connections originating from the payload process to an **external C2 IP/Domain**.
3.  **Identity/Privilege Context:** Trace the user account used to create the permanent subscription. Creating permanent WMI event subscriptions requires **SYSTEM or Administrator** privileges, confirming that privilege escalation occurred prior to this phase.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Remove the persistence mechanism and block the execution chain. | **Delete the malicious WMI objects** (Filter, Consumer, Binding) using `wmic` or the `Remove-WmiObject` cmdlet. **Block the C2 IP/Domain** identified by the payload. |
| **Logging** | **Mandate Detailed WMI Logging:** Ensure all WMI object creation and modifications are captured. | **Enable and Ingest** the **Microsoft-Windows-WMI-Activity/Operational Log** into the SIEM and create alerts for **Event ID 5858/5859** with creation/deletion operations. |
| **Process Control** | **Restrict Process Spawning:** Block the WMI host process from executing command shells. | Configure EDR rules to **alert or block** the **`WmiPrvSE.exe` process from spawning any child process** that is a command interpreter (`cmd.exe`, `powershell.exe`) or a networking utility (`certutil.exe`). |
| **Principle of Least Privilege** | **Restrict WMI Write Access:** Limit which users can write to the WMI repository. | Use **WMI security descriptors** to limit write access on sensitive namespaces to only necessary administrative service accounts. |
