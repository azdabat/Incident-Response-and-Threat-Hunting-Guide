# Incident Response Playbook – Modern LOLBIN – Winget Package Abuse

This playbook addresses the use of **Microsoft Windows Package Manager (`winget.exe`)** for **Execution (T1204.002)**, **Defense Evasion (T1218)**, and potentially **Data Staging/Exfiltration**. Attackers abuse `winget` by having it install malicious software, or packages that contain post-install scripts designed to execute payloads, bypassing application whitelisting checks because `winget.exe` is a trusted, signed Microsoft binary (a modern LOLBIN).

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005), Execution (TA0002)
**Technique:** Malicious File Content (T1204.002), Signed Binary Proxy Execution (T1218), Trusted Developer Utility (T1543.003)
**Critical Threat:** The attacker leverages a native system tool to download and execute arbitrary code, often achieving persistence and avoiding detection from tools that trust Microsoft-signed binaries implicitly.

---

## 1. L2 Analyst Actions (Initial Triage & Package Vetting)

The L2 analyst must confirm that the package installed via `winget` is unauthorized and contains malicious code.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the package installation is tied to any documented deployment process (Intune, SCCM, GPO) or standard user software request. **Reject any package installation initiated from a non-standard process or script.**
2.  **Command Line Inspection:** Review the full command line arguments used with `winget.exe`. Look for:
    * **`winget install <package_id>`:** Installation of a known malicious, or highly suspicious package ID.
    * **`winget source add`:** Modification of the official package sources to point to an attacker-controlled repository (high-confidence threat).
3.  **Parent Process Check:** Identify the process that spawned `winget.exe`. Was it `cmd.exe`, `powershell.exe`, or a custom script? **Execution under a legitimate user process is highly suspicious for a background deployment tool.**
4.  **Payload Analysis:** Trace the activity immediately following the `winget install` command. The install process may drop and execute:
    * **Child Processes:** Look for `winget.exe` spawning subsequent processes like `cmd.exe`, `powershell.exe`, or known infostealer/persistence executables.
    * **File Drops:** Note where the package files were installed, often in temporary user-writable directories.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The account that ran `winget.exe`).
* **Time Range:** The $\pm1$ hour surrounding the `winget.exe` execution.
* **Artifacts:** The **Full `winget.exe` command line**, the **Installed Package ID**, the **Installation Directory Path**, and the **Hash of any suspicious child process** spawned.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed installation of an unverified package followed by **host-level command execution**. **Severity is Critical.**
* The command line includes `winget source add` pointing to a **non-Microsoft URL**.
* The activity is observed on a **privileged user's host** or a **server**.
* The installation resulted in the execution of a binary with a **known malicious hash**.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Initial Access Link)

The L3 analyst must assume the attacker has executed code with high privilege and must identify the persistence and C2 channels established by the installed package.

### 2.1 Full Attack Chain Reconstruction

1.  **Package Source Investigation:** If the source was modified (`winget source add`), investigate the attacker-controlled repository URL to understand other available packages and potential victims.
2.  **Package Manifest Review:** Analyze the package's **installer type** and **post-install actions**. The malicious behavior is often defined in the package's manifest file, which can include scripts for persistence.
3.  **Persistence Analysis:** Determine what artifacts were dropped by the package installation. Look for the creation of:
    * **Scheduled Tasks (T1053.005):** Tasks set to execute the payload periodically.
    * **Registry Run Keys (T1547.001):** Entries that launch the payload on logon.
    * **New Services (T1543.003):** Malicious services running under the user's or SYSTEM context.
4.  **Network Activity:** Review network connections (`DeviceNetworkEvents`) immediately after installation. Does the payload beacon out to a C2 server?

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1204.002 Confirmed):** Execution via a trusted proxy.
2.  **Scope the Incident:** The scope includes the **host**, the **compromised user account**, the **malicious package repository/ID**, and all **persistence mechanisms** established.

---

## 3. Containment – Recommended Actions (Execution Kill & Source Block)

Containment must break the persistence and block the trusted binary from accessing unverified external resources.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Process Termination & Removal:** Terminate all child processes spawned by the malicious `winget` package installation. Remove the persistence mechanisms (tasks, registry entries) and the installed package files.
3.  **Block Package Repository:** If the attacker used a custom source (`winget source add`), **IMMEDIATELY** block access to that external URL at the network perimeter (firewall/proxy).
4.  **Restrict `winget` (Temporary):** If the attack vector is active, consider **temporarily blocking all execution of `winget.exe`** using AppLocker or WDAC until a long-term control is implemented.
5.  **Credential Revocation:** Reset/revoke affected credentials, especially if the installation required elevated privileges.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must enforce stricter application control, specifically targeting the behavior of trusted system utilities.

1.  **Control Failure Analysis:** Identify which control failed: **Application Control** (failing to prevent the code execution *after* `winget` was launched), or **Network Filtering** (allowing connection to the malicious package repository).
2.  **Propose and Track Improvements:**
    * **WDAC/AppLocker Enforcement:** Implement a **WDAC or AppLocker policy** that allows `winget.exe` to run, but uses the **Path Rule** to **deny** `winget.exe` (or its child processes) from writing or executing files from user-writable directories (e.g., `%TEMP%`, `%APPDATA%`) or the installation target directory.
    * **Source Hardening:** Configure endpoints to **trust only the official Microsoft winget source**. Audit regularly for unauthorized source additions using the KQL below.
    * **Command Line Auditing:** Refine detection logic to specifically flag **`winget.exe` execution followed immediately by non-standard process spawns** (`certutil`, `bitsadmin`, `powershell -e`).
    * **Service Account Review:** If `winget` was executed under a system account, review that account's privileges and access.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model to include `winget` as a high-risk modern LOLBIN, requiring behavioral, not just signature-based, monitoring.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for evidence of `winget.exe` being used to install or configure suspicious external sources, a key pre-attack step.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Winget Package Abuse (T1204.002, T1218)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "winget.exe"
| extend CommandLine = ProcessCommandLine
// 1. Look for commands that indicate configuration modification or installation
| where CommandLine has_any ("install", "source add", "import")
| extend ParentProcess = InitiatingProcessFileName
| extend UserContext = AccountName
| extend CommandArguments = split(CommandLine, " ")
// 2. Identify modification of sources to non-Microsoft URLs (high-confidence threat)
| where CommandLine has "source add"
    and CommandLine !contains "[https://cdn.winget.microsoft.com/](https://cdn.winget.microsoft.com/)"
    and CommandLine has "http" // Check for any network URL being added
| project Timestamp, DeviceName, UserContext, ParentProcess, CommandLine
| order by Timestamp desc
```
Concluding Remarks: The Wolf in Sheep's Clothing

The abuse of winget.exe is a perfect example of a modern, low-footprint attack. The attacker is using a system feature built for IT efficiency as a weapon.

It’s the Aftermath that Matters: The alert will be on the trustworthy winget.exe process. Your job is to look at the child processes and file drops that occurred immediately afterward. What did the "delivery truck" leave behind?

Restrict the Source: The best long-term defense against winget abuse is controlling where it's allowed to download content from. If you can force it to only use trusted, official Microsoft sources, you drastically limit the attack surface.

New LOLBIN: As Microsoft introduces more trusted native tools, expect them to be weaponized. Your controls must move from whitelisting tools to whitelisting behavior.
