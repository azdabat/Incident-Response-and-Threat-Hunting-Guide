# Incident Response Playbook – ETW / AMSI Tampering Behaviour (T1562.001 / T1562.006)

This playbook addresses high-priority alerts for defense evasion techniques where an adversary attempts to blind the security stack by disabling or hooking Windows tracing and scanning capabilities. Successful tampering indicates a high-risk malicious process is executing.

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005)
**Technique:** Disable or Modify Tools (T1562.001), Impair Defenses (T1562.006)
**Critical Link:** Memory manipulation or API hooking of core Windows DLLs (`amsi.dll`, `ntdll.dll`) by a suspicious process.

---

## 1. L2 Analyst Actions (Initial Triage & Scope Confirmation)

The L2 analyst must validate the alert, confirm the target security mechanism (AMSI or ETW), and quickly isolate the malicious process that executed the tamper.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Immediately confirm whether a documented, approved security update or EDR maintenance could have temporarily interfered with tracing/scanning services (highly unlikely for a true tamper event).
2.  **Process Context:** Identify the **process** (and its **parent**) that performed the tampering operation. This is the source of the high-risk activity.
3.  **Target Analysis:** Determine *what* was tampered with:
    * **AMSI Tamper:** Signals an attempt to run an obfuscated script (PowerShell, VBScript) without detection. Look for injection into `amsi.dll`.
    * **ETW Tamper:** Signals an attempt to avoid EDR/Sysmon logging of API calls (e.g., credential theft, process injection). Look for hooks in `ntdll.dll` or event provider manipulation.
4.  **Command Line Review:** Scrutinize the process command line for highly suspicious, encoded, or parameter-heavy commands, which often precede tampering.

### 1.2 Minimal Triage Data Collection (Forensic Priority)

The tampering event destroys visibility, so fast, targeted data collection is critical:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`**
* **Time Range:** The **exact timestamp** of the tampering event, plus a forensic window of **$\pm1$ hour** *before* the tamper (to capture the initial access).
* **Process Snapshot:** The **full memory dump** of the malicious process and its parent, if possible, before termination.
* **Payload Artifacts:** The hash (SHA256) of the initial loader/executable that initiated the tamper.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed successful AMSI or ETW tamper, regardless of user context. This is a **High Severity** indicator of advanced threat actor behavior.
* The tampering process is a **script host** (`powershell.exe`, `wscript.exe`) or a **common loader** (`rundll32.exe`, `explorer.exe`).
* The tampering process immediately proceeds with **credential access** (LSASS interaction) or **process injection** into a critical system process.
* Similar activity appears on **multiple, disparate hosts**.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Remediation)

The L3 analyst focuses on the root cause, determining the type of threat actor (commodity vs. APT), and restoring security integrity.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access & Delivery:** Identify the full chain: Email/Web Download -> Loader -> Tampering Process. Recover the initial payload used to defeat the controls.
2.  **Tamper Technique Analysis:**
    * **AMSI Bypass:** Analyze memory to identify the specific bypass method used (e.g., memory patching, signature modification, reflection). Determine the **payload** that ran *after* AMSI was disabled.
    * **ETW Unhooking:** Identify which security function/API was targeted (e.g., `NtReadVirtualMemory`, `CreateRemoteThread`). This reveals the subsequent goal (e.g., evasion during injection).
3.  **Post-Tamper Activity:** Trace forward *despite* the reduced visibility. Look for events that *should* have been logged but weren't, such as:
    * Network connections (C2).
    * File creation in system directories.
    * User/System enumeration commands.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Commodity Malware:** Simple string-based AMSI bypasses often signal commodity threats (e.g., common loaders, basic info-stealers).
    * **Advanced Threat Actor (APT):** Sophisticated, direct memory hooking of ETW or kernel callbacks. **MITRE T1562 Confirmed.**
2.  **Scope the Incident:** The scope must assume full compromise. Confirm whether the compromised identity was used for lateral movement or persistence *before* the tamper was detected.

---

## 3. Containment – Recommended Actions (Maximum Severity)

Containment must be immediate, aggressive, and assumes a persistent threat.

1.  **Endpoint Isolation:** **MANDATORY** isolate affected endpoints immediately to prevent lateral movement and C2 communication.
2.  **Hard Memory Reset:** Force a reboot of the affected machine to clear memory resident malware and reset the state of patched DLLs (AMSI/ETW hooks are usually temporary).
3.  **Credential Revocation:** Reset/revoke affected user credentials, as the primary goal post-tamper is often credential access.
4.  **Binary Constraint:** **MANDATORY** block the hash of the initiating process and the signature of any related malicious files across all endpoints.
5.  **Environment Constraint:** For scripting languages, enforce **Constrained Language Mode** for PowerShell or apply **AppLocker/WDAC** to prevent the execution of scripts from non-approved directories (e.g., Temp, Downloads).

---

## 4. Remediation & Hardening – Strategic Improvements

Focus on strengthening the foundational security sensors to prevent blind spots.

1.  **Control Failure Analysis:** Identify which control failed (e.g., EDR's ability to detect the memory patch, or insufficient logging of PowerShell script blocks).
2.  **Propose and Track Improvements:**
    * **Detection Logic:** Implement new, refined **detection logic** to alert on suspicious memory modification/write events targeting `amsi.dll` or `ntdll.dll`.
    * **Telemetry Density:** Enable and enforce **PowerShell Script Block Logging** (to capture script content *before* it hits AMSI) and **Process Tampering Events** in EDR policies.
    * **Hardening Baselines:** Proactively deploy **Windows Defender Credential Guard** and **Hypervisor-Protected Code Integrity (HVCI)** to make memory tampering significantly harder.
3.  **Documentation and Knowledge Transfer:** Update this playbook, SOPs, and the Threat Model, focusing on how new threat groups are leveraging advanced evasion techniques against kernel-level telemetry.

---

## 5. Threat Hunting Queries (KQL Focus)

These KQL fragments target common memory and execution events indicative of AMSI/ETW tampering attempts.

### 5.1 Hunting Query Example (KQL Only)

This query focuses on suspicious write operations to critical security DLLs, which is the mechanism used for both AMSI and ETW bypass.

```kql
// KQL Query for Suspicious Memory Write to Security DLLs (AMSI/ETW Hooking)
let TargetDLLs = dynamic(['\\windows\\system32\\amsi.dll', '\\windows\\system32\\ntdll.dll']);
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any ("powershell", "cmd.exe", "mshta.exe") // Common loaders for evasion
| join kind=inner (
    DeviceEvents
    // Look for remote thread creation or memory write/modification events
    | where ActionType in ("ProcessTamperingReported", "RemoteThreadCreated", "ModuleLoad") 
    | where TargetFileName has_any (TargetDLLs)
    // Filter out known EDR/Security solution FPs
    | where not(InitiatingProcessFileName has_any ("MsMpEng.exe", "SenseCng.exe", "edr_update_service.exe"))
    | project InitiatingProcessId, TargetFileName, InitiatingProcessCommandLine, TamperTime=Timestamp
) on InitiatingProcessId
| project
    TamperTime,
    DeviceName,
    AccountName,
    TamperSource=InitiatingProcessFileName,
    TamperTarget=TargetFileName,
    InitiatingProcessCommandLine
| order by TamperTime desc
```
Concluding Remarks: Mastering the Evasion Challenge
Responding to ETW/AMSI tampering demonstrates a deep understanding of advanced defense evasion. When presenting this work, emphasize the following to highlight your expertise:

Zero-Visibility Mindset: Highlight that successful tampering requires the analyst to operate under a "blind spot," making pre-tamper artifacts (Triage Data) the most valuable forensic evidence.

Defense-in-Depth: Stress that hardening is not just about detection, but using layered controls like HVCI and Constrained Language Mode to prevent the tampering attempt from succeeding in the first place.

The DLL Lifespan: Explain the necessity of rebooting (Containment Action 2) to ensure the memory-resident hooks are removed and the system integrity is fully restored, a key step often missed in commodity playbooks.
