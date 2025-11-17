# Incident Response Playbook – Browser → LOLBIN Execution Chain

This playbook is designed for L2/L3 analysts responding to high-priority alerts where a web browser (the initial access vector) initiates the execution of a Living Off the Land Binary (LOLBIN) or Script Host.

**MITRE ATT&CK Tactic:** Initial Access (TA0001), Execution (TA0002), Defense Evasion (TA0005)
**Technique:** T1189 (Drive-by Compromise), T1566 (Phishing), T1218 (Signed Binary Proxy Execution)
**Critical Link:** Browser Process (`chrome.exe`, `msedge.exe`, `firefox.exe`) as the Parent of a Suspicious Child Process (e.g., `certutil.exe`, `powershell.exe`, `mshta.exe`).

---

## 1. L2 Analyst Actions (Initial Triage & Validation)

The goal is to confirm the malicious parent-child relationship and immediately collect context about the initial compromise.

### 1.1 Triage and Validation Steps

1.  **Parent-Child Review:** Confirm the parent process is a web browser and the child process is an unexpected system utility (`powershell.exe`, `cmd.exe`, `mshta.exe`, `regsvr32.exe`, `certutil.exe`, etc.).
2.  **Initial Access Context:** Immediately query network logs/browser history for the **full URL and IP address** accessed by the browser immediately preceding the execution. Check if the URL is known malicious or highly suspicious (e.g., suspicious file extension, shortened URL).
3.  **Command Line Analysis:** Scrutinize the LOLBIN's full command line for telltale signs:
    * **Obfuscation:** Base64 or heavy encoding arguments.
    * **Network Activity:** Usage of commands like `certutil -urlcache -f` or `Invoke-WebRequest` for downloading additional payloads.
    * **Execution Path:** The LOLBIN is executing from a user-writable path (e.g., `\AppData`, `\Temp`, `\Downloads`).

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for documentation and L3 handover:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (User Principal Name)
* **Time Range:** Collect all logs and alerts within a forensic window of **$\pm24$ hours** around the detection time.
* **Initial Access Artifacts:** The full source URL/IP that triggered the download/execution.
* **LOLBIN Artifacts:** The full command line and hash (SHA256) of any file downloaded or created in the temporary directory.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* `Severity` is **Medium or High** (Default for successful LOLBIN execution).
* The command line shows evidence of **payload download** or **encoding/obfuscation**.
* The host/user is **sensitive** (e.g., Domain Controller, Tier-0 Server, privileged account).
* The execution chain involves a **multi-stage script** (Browser -> WScript/CScript -> PowerShell -> LOLBIN).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Scoping)

The L3 analyst reconstructs the full attack narrative, determines the payload, and establishes the incident scope.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Payload Analysis:** Identify the exact file downloaded by the browser or the LOLBIN. Reverse engineer the script/command line to determine the malware family or objective (e.g., information stealer, remote access trojan).
2.  **Execution Path:** Trace the full sequence: Browser -> Script/LOLBIN -> Memory Injection/Persistence. Note all file paths, especially those in temporary folders.
3.  **Subsequent Activity:** Trace forward from the successful execution. Look for signs of:
    * **Persistence:** New scheduled tasks, registry run keys, or startup folder entries created by the LOLBIN's payload.
    * **Discovery:** Execution of system enumeration tools (`whoami`, `quser`, `ipconfig`).
    * **Staging/Exfiltration:** Data staging (T1560) or network connections to known Command and Control (C2) infrastructure.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Benign/FP:** (Rare) Confirmed update mechanisms or specific company-approved tool initialization.
    * **Malicious Intrusion (T1218 Confirmed):** Execution chain matches known threat actor TTPs (e.g., QakBot dropper, IcedID download).
2.  **Scoping:**
    * Determine the full extent of compromise on the **affected host**.
    * Check if the compromised **identity** was used to access sensitive data or perform **lateral movement**.

---

## 3. Containment – Recommended Actions

Containment aims to stop the threat actor's activity and preserve forensic integrity.

1.  **Endpoint Isolation:** **MANDATORY** isolate affected endpoints immediately.
2.  **Forensic Snapshot:** Initiate a live memory dump and disk image acquisition *before* any major remediation action is taken.
3.  **Credential Revocation:** Reset/revoke affected user credentials and **immediately enforce MFA**, as the host may contain token or credential artifacts.
4.  **Network Blocking:** Block the C2 IP addresses and file download URLs/domains identified during the reconstruction phase at the firewall/proxy layer.
5.  **Binary Constraint:** Block the specific LOLBIN and command line signature (e.g., `certutil.exe` with `-urlcache`) using application control policies (WDAC, AppLocker, EDR policy).

---

## 4. Remediation & Hardening – Strategic Improvements

Focus on eliminating the root cause and strategic hardening to prevent recurrence.

1.  **Root Cause Analysis:** Determine which security control failed (Web Proxy, Email Filter, EDR Detection, Application Control) and why.
2.  **Propose and Track Improvements:**
    * **Detection Logic:** Implement new, refined **detection logic** to alert on suspicious browser parent-child relationships (see KQL below) and execution from high-risk paths (`\Temp`, `\Downloads`).
    * **Hardening Baselines:** Implement **Attack Surface Reduction (ASR) rules** to block credential theft and execution of potentially obfuscated scripts.
    * **Web/Email Filter:** Update web proxy and email filters to block newly identified malicious domains/files.
3.  **Documentation and Knowledge Transfer:** Update this playbook, SOPs, Threat Models, and the Knowledge Base with newly observed TTPs.

---

## 5. Threat Hunting Queries (KQL Focus)

These KQL fragments target the suspicious parent-child process relationship central to this attack.

### 5.1 Hunting Query Example (KQL Only)

This query searches for common browser processes acting as a parent to known LOLBINs, excluding obvious false positives (FPs).

```kql
// KQL Query for Browser Spawning LOLBINs
let Browsers = dynamic(['chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe']);
let HighRiskLOLBINs = dynamic(['powershell.exe', 'cmd.exe', 'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe', 'msbuild.exe']);
DeviceProcessEvents
| where InitiatingProcessFileName has_any (Browsers) // Parent is a web browser
| where FileName has_any (HighRiskLOLBINs) // Child is a high-risk system utility
// Filter out common benign browser FPs
| where not(ProcessCommandLine has_any ("--type=renderer", "--type=gpu", "/C timeout", "/c start", "update.exe", "install.exe"))
// Look for common malicious flags
| where ProcessCommandLine has_any ("-e ncoded", "IEX", "Invoke-WebRequest", "urlcache", "downloadfile", ".dll")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ChildProcessName=FileName,
    ChildProcessCommandLine=ProcessCommandLine,
    FolderPath
| order by Timestamp desc
