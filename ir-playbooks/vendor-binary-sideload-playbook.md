# Incident Response Playbook – Vendor Binary → DLL Sideloading (Native)

This playbook addresses the highly stealthy **DLL Sideloading (T1574.001)** technique. Attackers exploit legitimate, signed, and trusted vendor executables (the host binary, often a Microsoft or security tool) by placing a malicious DLL in a location where the legitimate binary is configured to search for a missing, dependent library. When the legitimate, trusted binary executes, it **sideloads** the malicious DLL, executing the attacker's code under the trusted binary's security context, effectively bypassing application whitelisting and EDR behavioral checks.

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005), Execution (TA0002), Privilege Escalation (TA0004)
**Technique:** DLL Search Order Hijacking (T1574.001), Signed Binary Proxy Execution (T1218)
**Critical Threat:** The malicious payload runs with the trust and privileges of a legitimate application, making standard signature-based controls ineffective and forensic timeline analysis highly complicated.

---

## 1. L2 Analyst Actions (Initial Triage & Trust Verification)

The L2 analyst must confirm that the trusted parent process is loading a library from an unexpected and unauthorized location.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the process or the DLL file is tied to any documented update, patch, or approved vendor software install. **Reject any execution of a DLL from a non-standard location (e.g., user profiles, temporary directories, or a network share).**
2.  **The Tell-Tale Trio:** Identify the three critical components of a sideloading attack:
    * **The Trusted Host Binary:** The legitimate, signed EXE (e.g., `cmd.exe`, `explorer.exe`, or a vendor's update utility).
    * **The Sideloaded DLL:** The malicious library (often mimicking a legitimate name like `version.dll` or `dbghelp.dll`).
    * **The Execution Context:** The malicious DLL is executed by the trusted binary, which will be logged by the EDR as the parent process.
3.  **DLL Path Inspection:** Check the file path of the loaded DLL. Is it being loaded from a location outside of the standard system path (`C:\Windows\System32` or the application's true installation directory)? **This is the primary indicator of sideloading.**
4.  **Process Behavior:** What does the trusted host binary do *after* loading the DLL? Look for immediate suspicious activity like external network connections (C2 beaconing) or spawning new, malicious child processes.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The account that ran the trusted binary).
* **Time Range:** The $\pm1$ hour surrounding the DLL load event.
* **Artifacts:** The **Trusted Binary Path and Hash**, the **Malicious DLL Path and Hash**, the **True Creation Time** of the malicious DLL (must be determined from EDR logs, not file metadata).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed loading of a non-system DLL from a non-system path (e.g., user profile, AppData) by a Microsoft or security vendor binary. **Severity is Critical.**
* The malicious DLL immediately initiates a **network connection** or **spawns a new, unsigned process**.
* The sideloading occurred using a binary on a **server** or a **privileged administrative workstation**.
* Similar activity appears on **multiple hosts**, indicating a targeted campaign.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Payload Analysis)

The L3 analyst must assume the attacker has executed code with high privilege and must determine the payload's intent.

### 2.1 Full Attack Chain Reconstruction

1.  **DLL Original Source:** Trace the file creation event for the malicious DLL backward. How and when did the DLL land in that suspicious directory? This connects the sideloading back to the **Initial Access Vector** (e.g., Phishing, Lsass dump, or vulnerability exploit).
2.  **Export/Function Analysis:** Determine the specific export function in the DLL that the trusted binary called (this is advanced but critical). The attacker's code runs within this function.
3.  **Behavior of the DLL:** Analyze the activity of the running process *after* the DLL load. This is the attacker's actual payload. Look for:
    * **Persistence:** Creation of new services or run keys by the trusted process.
    * **Credential Dumping:** Attempts to access memory of `lsass.exe`.
    * **Discovery:** Execution of reconnaissance commands.
4.  **Scope the Vulnerability:** Determine if the trusted binary is **known to be vulnerable** to DLL Sideloading. If so, identify all other instances of this binary in the environment.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1574.001 Confirmed):** High-stealth execution using a defense evasion technique.
2.  **Scope the Incident:** The scope includes the **host**, the **malicious DLL and its hash**, the **vulnerable trusted binary**, and potentially **other hosts** where the vulnerable binary is installed, which may be pre-staged for attack.

---

## 3. Containment – Recommended Actions (Targeted Removal and Patching)

Containment must remove the malicious component while planning the permanent fix for the underlying vulnerability.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Kill and Quarantine:** **IMMEDIATELY** terminate the trusted host binary process and quarantine the **malicious DLL file**. If the host binary is a critical system file, ensure it is not deleted.
3.  **Vulnerability Mitigation:**
    * If a **patch** exists for the vulnerable trusted binary, apply it immediately to the affected host (if patch application is safe while isolated).
    * If no patch exists, consider **blocking execution** of the trusted host binary entirely until a patch is available, or use **AppLocker/WDAC** to deny execution of *any* DLL from the suspicious path.
4.  **Credential Revocation:** Reset/revoke affected credentials, as the malicious code likely ran with high privileges, making credential compromise a strong possibility.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the system's DLL search path resolution and application control policy.

1.  **Control Failure Analysis:** Identify which control failed: **Application Whitelisting** (failed because the host binary was trusted), or **Configuration** (the trusted binary was vulnerable to search order hijacking).
2.  **Propose and Track Improvements:**
    * **Application Control Policy:** Implement **WDAC** or **AppLocker** rules to explicitly **deny execution of any DLL files from common user-writable or temporary directories** (e.g., `C:\Users\*\AppData`, `%TEMP%`) unless signed by a trusted vendor. This prevents the initial drop.
    * **Path Environment Hardening:** Review the system and user environment variables to ensure dangerous directories are not added to the **DLL search path**.
    * **Vulnerability Tracking:** Create a list of all known DLL-sideloading vulnerable binaries within the organization and track their patching status or implement host-based execution restrictions.
    * **New Detection Logic:** Create a new EDR rule that alerts on a known, vulnerable **Trusted Host Binary** executing **any DLL** that is not located in its official installation directory or `C:\Windows\System32`.
3.  **Documentation and Knowledge Transfer:** Update playbooks, emphasizing the need to analyze **DLL Load Events** during any investigation, as sideloading bypasses most execution-based monitoring.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for the precise signature of DLL Sideloading: a commonly abused, trusted executable loading a DLL from a user-writable path.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for DLL Sideloading (T1574.001)
DeviceImageLoadEvents
| where Timestamp > ago(7d)
// 1. Target the trusted, high-trust executables that are often abused
| where InitiatingProcessFileName in ("svchost.exe", "rundll32.exe", "explorer.exe", "mshta.exe") // Common Windows processes
    or InitiatingProcessFileName endswith ".exe" and InitiatingProcessSignature contains "Microsoft" // Any Microsoft signed binary
// 2. Identify the malicious DLL being loaded (the 'Image' is the DLL)
| where Image endswith ".dll"
// 3. Crucial: Check for loading from suspicious, non-standard directories
// This list covers common user-writable and temporary locations
| where FolderPath has_any (
    "\\Users\\", "\\AppData\\Local\\Temp\\", "\\ProgramData\\", "\\Intel\\", 
    "\\PerfLogs\\", "\\Recycle.Bin\\", "\\temp\\", "C:\\Windows\\Tasks\\"
)
// 4. Exclude known benign or false-positive DLL loads from these paths
| where not(Image has "known_legitimate_vendor_log.dll") 
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, LoadedImage=Image, LoadedPath=FolderPath, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```
Here is the final playbook for handling one of the trickiest forms of defense evasion: DLL Sideloading.

Markdown

# Incident Response Playbook – Vendor Binary → DLL Sideloading (Native)

This playbook addresses the highly stealthy **DLL Sideloading (T1574.001)** technique. Attackers exploit legitimate, signed, and trusted vendor executables (the host binary, often a Microsoft or security tool) by placing a malicious DLL in a location where the legitimate binary is configured to search for a missing, dependent library. When the legitimate, trusted binary executes, it **sideloads** the malicious DLL, executing the attacker's code under the trusted binary's security context, effectively bypassing application whitelisting and EDR behavioral checks.

**MITRE ATT&CK Tactic:** Defense Evasion (TA0005), Execution (TA0002), Privilege Escalation (TA0004)
**Technique:** DLL Search Order Hijacking (T1574.001), Signed Binary Proxy Execution (T1218)
**Critical Threat:** The malicious payload runs with the trust and privileges of a legitimate application, making standard signature-based controls ineffective and forensic timeline analysis highly complicated.

---

## 1. L2 Analyst Actions (Initial Triage & Trust Verification)

The L2 analyst must confirm that the trusted parent process is loading a library from an unexpected and unauthorized location.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the process or the DLL file is tied to any documented update, patch, or approved vendor software install. **Reject any execution of a DLL from a non-standard location (e.g., user profiles, temporary directories, or a network share).**
2.  **The Tell-Tale Trio:** Identify the three critical components of a sideloading attack:
    * **The Trusted Host Binary:** The legitimate, signed EXE (e.g., `cmd.exe`, `explorer.exe`, or a vendor's update utility).
    * **The Sideloaded DLL:** The malicious library (often mimicking a legitimate name like `version.dll` or `dbghelp.dll`).
    * **The Execution Context:** The malicious DLL is executed by the trusted binary, which will be logged by the EDR as the parent process.
3.  **DLL Path Inspection:** Check the file path of the loaded DLL. Is it being loaded from a location outside of the standard system path (`C:\Windows\System32` or the application's true installation directory)? **This is the primary indicator of sideloading.**
4.  **Process Behavior:** What does the trusted host binary do *after* loading the DLL? Look for immediate suspicious activity like external network connections (C2 beaconing) or spawning new, malicious child processes.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The account that ran the trusted binary).
* **Time Range:** The $\pm1$ hour surrounding the DLL load event.
* **Artifacts:** The **Trusted Binary Path and Hash**, the **Malicious DLL Path and Hash**, the **True Creation Time** of the malicious DLL (must be determined from EDR logs, not file metadata).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed loading of a non-system DLL from a non-system path (e.g., user profile, AppData) by a Microsoft or security vendor binary. **Severity is Critical.**
* The malicious DLL immediately initiates a **network connection** or **spawns a new, unsigned process**.
* The sideloading occurred using a binary on a **server** or a **privileged administrative workstation**.
* Similar activity appears on **multiple hosts**, indicating a targeted campaign.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Payload Analysis)

The L3 analyst must assume the attacker has executed code with high privilege and must determine the payload's intent.

### 2.1 Full Attack Chain Reconstruction

1.  **DLL Original Source:** Trace the file creation event for the malicious DLL backward. How and when did the DLL land in that suspicious directory? This connects the sideloading back to the **Initial Access Vector** (e.g., Phishing, Lsass dump, or vulnerability exploit).
2.  **Export/Function Analysis:** Determine the specific export function in the DLL that the trusted binary called (this is advanced but critical). The attacker's code runs within this function.
3.  **Behavior of the DLL:** Analyze the activity of the running process *after* the DLL load. This is the attacker's actual payload. Look for:
    * **Persistence:** Creation of new services or run keys by the trusted process.
    * **Credential Dumping:** Attempts to access memory of `lsass.exe`.
    * **Discovery:** Execution of reconnaissance commands.
4.  **Scope the Vulnerability:** Determine if the trusted binary is **known to be vulnerable** to DLL Sideloading. If so, identify all other instances of this binary in the environment.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1574.001 Confirmed):** High-stealth execution using a defense evasion technique.
2.  **Scope the Incident:** The scope includes the **host**, the **malicious DLL and its hash**, the **vulnerable trusted binary**, and potentially **other hosts** where the vulnerable binary is installed, which may be pre-staged for attack.

---

## 3. Containment – Recommended Actions (Targeted Removal and Patching)

Containment must remove the malicious component while planning the permanent fix for the underlying vulnerability.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Kill and Quarantine:** **IMMEDIATELY** terminate the trusted host binary process and quarantine the **malicious DLL file**. If the host binary is a critical system file, ensure it is not deleted.
3.  **Vulnerability Mitigation:**
    * If a **patch** exists for the vulnerable trusted binary, apply it immediately to the affected host (if patch application is safe while isolated).
    * If no patch exists, consider **blocking execution** of the trusted host binary entirely until a patch is available, or use **AppLocker/WDAC** to deny execution of *any* DLL from the suspicious path.
4.  **Credential Revocation:** Reset/revoke affected credentials, as the malicious code likely ran with high privileges, making credential compromise a strong possibility.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the system's DLL search path resolution and application control policy.

1.  **Control Failure Analysis:** Identify which control failed: **Application Whitelisting** (failed because the host binary was trusted), or **Configuration** (the trusted binary was vulnerable to search order hijacking).
2.  **Propose and Track Improvements:**
    * **Application Control Policy:** Implement **WDAC** or **AppLocker** rules to explicitly **deny execution of any DLL files from common user-writable or temporary directories** (e.g., `C:\Users\*\AppData`, `%TEMP%`) unless signed by a trusted vendor. This prevents the initial drop.
    * **Path Environment Hardening:** Review the system and user environment variables to ensure dangerous directories are not added to the **DLL search path**.
    * **Vulnerability Tracking:** Create a list of all known DLL-sideloading vulnerable binaries within the organization and track their patching status or implement host-based execution restrictions.
    * **New Detection Logic:** Create a new EDR rule that alerts on a known, vulnerable **Trusted Host Binary** executing **any DLL** that is not located in its official installation directory or `C:\Windows\System32`.
3.  **Documentation and Knowledge Transfer:** Update playbooks, emphasizing the need to analyze **DLL Load Events** during any investigation, as sideloading bypasses most execution-based monitoring.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for the precise signature of DLL Sideloading: a commonly abused, trusted executable loading a DLL from a user-writable path.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for DLL Sideloading (T1574.001)
DeviceImageLoadEvents
| where Timestamp > ago(7d)
// 1. Target the trusted, high-trust executables that are often abused
| where InitiatingProcessFileName in ("svchost.exe", "rundll32.exe", "explorer.exe", "mshta.exe") // Common Windows processes
    or InitiatingProcessFileName endswith ".exe" and InitiatingProcessSignature contains "Microsoft" // Any Microsoft signed binary
// 2. Identify the malicious DLL being loaded (the 'Image' is the DLL)
| where Image endswith ".dll"
// 3. Crucial: Check for loading from suspicious, non-standard directories
// This list covers common user-writable and temporary locations
| where FolderPath has_any (
    "\\Users\\", "\\AppData\\Local\\Temp\\", "\\ProgramData\\", "\\Intel\\", 
    "\\PerfLogs\\", "\\Recycle.Bin\\", "\\temp\\", "C:\\Windows\\Tasks\\"
)
// 4. Exclude known benign or false-positive DLL loads from these paths
| where not(Image has "known_legitimate_vendor_log.dll") 
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, LoadedImage=Image, LoadedPath=FolderPath, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```
Concluding Remarks: The Masquerade

DLL Sideloading is one of the most effective and frustrating defense evasion techniques. The execution chain looks entirely benign: TrustedApp.exe is running, therefore everything is fine. But the code running inside that trusted process is the attacker's payload.

It’s a Three-Part Crime: Always look for the trusted host, the malicious DLL, and the suspicious path. If you have all three, you have a confirmed sideloading attack.

The Vulnerability is the Target: The attacker didn't hack the system; they hacked the software's configuration (its DLL search path). Containment is temporary; remediation requires fixing the configuration or the vulnerability in the software itself.

Don't Delete the Host: Be extremely careful not to delete the Trusted Host Binary (svchost.exe, etc.). You must only remove the malicious, sideloaded DLL.
