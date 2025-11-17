# Incident Response Playbook – Phishing → Office Macro → LOLBIN Chain

This playbook is triggered by alerts indicating a malicious chain of execution: a **Microsoft Office application** (Word, Excel) spawning a **Command Interpreter** or **Living Off the Land Binary (LOLBIN)** to achieve execution, typically after a user opens a weaponized document delivered via **Phishing**.

**MITRE ATT&CK Tactic:** Initial Access (TA0001), Execution (TA0002), Defense Evasion (TA0004)
**Technique:** T1566.001 (Phishing), T1204.002 (Malicious File), T1059.001 (PowerShell), T1218 (Signed Binary Proxy Execution)
**Critical Threat:** A user has been successfully compromised, and the attacker has achieved their first stage of code execution on the endpoint, leading directly to payload delivery and persistence.

---

## 1. L2 Analyst Actions (Initial Triage & Execution Validation)

The L2 analyst must confirm the full execution chain and verify the legitimacy of the LOLBIN execution.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether any expected administrative script or internal software deployment uses this exact chain (`Office App` -> `LOLBIN`). **Reject any execution where the Office App is the parent.**
2.  **Parent-Child Confirmation:** Immediately confirm the parent process of the malicious execution using **`DeviceProcessEvents`**. The chain must be: **`WINWORD.EXE` / `EXCEL.EXE`** -> **`CMD.EXE`** / **`POWERSHELL.EXE`** -> **Malicious Payload/Network Connection.**
3.  **Email Investigation (Sentinel/M365 Defender):** Use **`EmailEvents`** and **`EmailAttachmentInfo`** to trace the originating email: sender, subject, delivery time, and any related quarantine/phishing policy hits.
4.  **LOLBIN Command Line:** Capture the full command line arguments of the LOLBIN (`powershell.exe`, `certutil.exe`, `mshta.exe`, etc.). Look for encoded commands (Base64), external network calls, or suspicious file writing to the `%TEMP%` directory.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The compromised user who opened the document).
* **Time Range:** The $\pm1$ hour surrounding the initial Macro execution (`OfficeApp` launch).
* **The Full Chain:** The process tree showing Parent/Child PIDs, Hashes, and full command lines for all processes from the Office App to the final payload drop.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** successful network connection is made by the child LOLBIN process (downloading payload). **Severity is High.**
* The execution chain results in a new **Persistence Mechanism** (Registry Run Key, Scheduled Task) being created.
* The file was executed by a **sensitive user** (executive, privileged admin).
* The attack is confirmed to be **targeted** (low volume, specific subject lines, high social engineering effort).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Payload Recovery)

The L3 analyst focuses on payload identification, persistence dismantling, and lateral movement review.

### 2.1 Full Attack Chain Reconstruction

1.  **Payload Recovery:** Identify the URL or IP used by the LOLBIN to download the secondary payload. Attempt to retrieve the file hash and content from the sandbox or EDR cache.
2.  **In-Depth Analysis:** If PowerShell was used, decode the Base64 command (often used with `-EncodedCommand`) to understand the exact payload delivery method (e.g., using `certutil -urlcache -f`, `Invoke-WebRequest`, or `BITSAdmin`).
3.  **Post-Execution Activity:** Audit the user's host for the following post-access activities:
    * **Credential Access (T1003):** Access to `lsass.exe` memory.
    * **Discovery (T1082):** Execution of commands like `whoami`, `ipconfig`, `net group domain admins`.
    * **Persistence Creation (T1547):** Creation of new artifacts in the Startup folder or Registry run keys.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (Confirmed):** This execution chain is overwhelmingly indicative of initial access by an adversary.
2.  **Scope the Incident:** Determine if the attacker immediately attempted **lateral movement** using the compromised credentials or if the payload was designed for specific **data staging/exfiltration**.

---

## 3. Containment – Recommended Actions (Chain Disruption)

Containment must break the kill chain at the endpoint and block the delivery mechanism.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using the MDE isolation feature immediately.
2.  **Block IOCs:** Block the **Hash** of the downloaded payload and the **Destination URL/IP** used for download across the firewall and MDE Custom Indicators list.
3.  **Credential Revocation:** Reset/revoke the affected user's credentials (`AccountName / UPN`), as they are often harvested by the first stage payload.
4.  **ASR Enforcement (Immediate Hardening):** Implement or activate the **Attack Surface Reduction (ASR) Rule** to block the following actions on the compromised endpoint: **"Block Office applications from creating child processes."**

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must focus on eliminating the user's ability to trigger the execution and removing the reliance on vulnerable LOLBINs.

1.  **Control Failure Analysis:** Identify which control failed: **Email Gatewa**y (missing the attachment), **User Training** (clicking Enable Content), or **Endpoint Configuration** (Macro execution was permitted).
2.  **Propose and Track Improvements:**
    * **Macro Policy Hardening:** Implement GPO/Intune policy to set the trust level for macros to **"Disable all macros with notification"** or, ideally, **"Disable all macros without notification"** for files from the internet zone.
    * **ASR Deployment:** Deploy the **"Block Office applications from creating child processes"** ASR rule globally in Audit Mode, then Enforce Mode once baseline testing is complete.
    * **PowerShell Hardening:** Enforce **Constrained Language Mode** on all non-administrative endpoints to severely restrict the capabilities of PowerShell scripts executed by unapproved applications.
3.  **Documentation and Knowledge Transfer:** Update playbooks, and ensure threat hunting focuses on the specific parent-child relationships seen in this incident.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query is the definitive method in MDE/Sentinel to find this chain: Office application starting a command line utility.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Office Macro Spawning LOLBIN (T1204.002)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in ('winword.exe', 'excel.exe', 'powerpnt.exe', 'visio.exe')
| where FileName in ('cmd.exe', 'powershell.exe', 'mshta.exe', 'certutil.exe', 'wmic.exe', 'bitsadmin.exe')
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName, ReportId
```
Concluding Remarks: Stopping the Macro Epidemic:

This attack chain—Phishing to Macro to LOLBIN—is the most common initial access route you will face. It's effective because it exploits the trust relationship between the user and Microsoft Office.

The Chain is the IOC: You are looking for an anomalous parent-child relationship. In a healthy environment, Office applications do not launch command interpreters. This is a high-fidelity alert every single time.

Containment vs. Remediation: Your containment goal is to kill the active payload and isolate the host. Your remediation goal must be to kill the Macro entirely using ASR rules and Macro policy changes. If the macro can't run, this entire attack vector dies.

Pivot to Email: Never stop at the endpoint. Immediately pivot your search to EmailEvents in Sentinel. Finding the original phishing email allows you to quarantine it for all other users and identify the true scope of the campaign. This is how you stop the next victim.
