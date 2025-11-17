# Incident Response Playbook – Suspicious PowerShell Script Abuse

This playbook addresses the highly versatile execution and defense evasion technique where an attacker uses **PowerShell** to execute malicious code, often filelessly (T1059.001) or using highly encoded commands (T1027.004). Detection focuses on unusual execution parameters, unauthorized network calls, or suspicious script content revealed through **PowerShell Script Block Logging**.

**MITRE ATT&CK Tactic:** Execution (TA0002), Defense Evasion (TA0005)
**Technique:** PowerShell (T1059.001), Obfuscated Files or Information (T1027), Scripting (T1059)
**Critical Threat:** PowerShell abuse often leads directly to in-memory payload delivery, credential theft (LSASS access), and persistence establishment, making it a critical initial foothold.

---

## 1. L2 Analyst Actions (Initial Triage & Execution Decoding)

The L2 analyst must confirm the malicious nature of the script and extract the true, decoded command to understand the attacker's intent.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the execution is tied to any expected, signed, or whitelisted administrative automation, particularly for patch management or configuration deployment. **Reject executions originating from user-owned scripts or unusual directories.**
2.  **Parent Process Check:** Identify the Parent Process. Suspicious parents include: `cmd.exe`, `explorer.exe` (after macro execution), or web browsers (after a drive-by download). The parent-child chain often reveals the initial access method.
3.  **Command Line Review (MDE/Sentinel):** Inspect the full command line within **`DeviceProcessEvents`**. Look for:
    * **`–EncodedCommand`** or **`-e`**: Indicates Base64 obfuscation (MANDATORY L3 step).
    * **`IEX`** or **`Invoke-Expression`**: Indicates fileless, in-memory execution.
    * **Network Calls:** Use of `Invoke-WebRequest` (`IWR`) or `Invoke-RestMethod` (`IRM`) to external IPs or suspicious domains.
4.  **User Privilege Check:** Note the user's privilege level when the script ran. If it was a local or domain administrator, the risk is immediately elevated.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`**
* **Time Range:** The $\pm1$ hour surrounding the PowerShell launch.
* **Full Process Chain:** The parent process, the `powershell.exe` execution, and any subsequent child processes (e.g., `whoami`, network connections).
* **Decoded Script Block:** The raw, decoded script content captured by PowerShell Script Block Logging (this is the most critical piece of evidence).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **Successful network connection** by PowerShell to an external C2 infrastructure (T1071). **Severity is High.**
* The decoded script block contains functions for **Credential Harvesting** (e.g., reading LSASS memory) or **Persistence** (e.g., creating Scheduled Tasks).
* The script execution is followed immediately by **file write operations** to temporary or startup directories.
* **Similar activity** is observed on a second endpoint, suggesting lateral movement or a widespread campaign.

---

## 2. L3 Analyst Actions (Technical Deep Dive & TTP Analysis)

The L3 analyst focuses on the intent of the decoded script, reversing the obfuscation, and mapping the entire threat sequence.

### 2.1 Full Attack Chain Reconstruction

1.  **Script Decoding and Intent:** Take the Base64/encoded command and decode it. Use Sentinel's built-in decoding functions or external tools to reveal the plaintext script. Categorize the script's functions:
    * **Discovery (e.g., `Get-NetUser`, `Invoke-ACLScanner`)**
    * **Credential Theft (e.g., `Invoke-Mimikatz`, memory reading functions)**
    * **Payload Delivery (e.g., `DownloadFile`, `BITSAdmin`)**
2.  **Telemetry Review:** Review **`DeviceProcessEvents`** and **`DeviceProcessProcessEvents`** to find any evidence of the malicious script attempting to access **`lsass.exe`** memory or injecting code into other processes (T1055).
3.  **Persistence Analysis:** If the script ran, check for immediate persistence: Was a new `.ps1` script dropped in a startup folder? Was a Registry Run Key or WMI Event Consumer established?
4.  **Lateral Movement Check:** Audit network logs for subsequent authentication attempts from the source machine to other systems, using the credentials likely harvested by the script.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (Confirmed):** PowerShell is the primary tool for post-exploitation by threat actors and should be treated as a hands-on-keyboard intrusion.
2.  **Scope the Incident:** Determine the scope of access—what resources did the compromised account have access to? Which systems were contacted for C2 or staging?

---

## 3. Containment – Recommended Actions (Execution & Network Block)

Containment requires immediate host isolation and breaking the communication channel the script was using.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE immediately.
2.  **Block IOCs:** Block the **Destination IP/URL** used for C2 or payload download across the firewall and MDE Custom Indicators list.
3.  **Credential Revocation:** Reset/revoke the affected user's credentials (`AccountName / UPN`), as PowerShell is often used for dumping credentials before network activity is detected.
4.  **Memory Flush:** Force a system logoff or reboot to flush the PowerShell runspace, which often holds the malicious script and any in-memory payload.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must reduce the surface area for fileless execution and ensure complete visibility into the PowerShell environment.

1.  **Control Failure Analysis:** Identify which control failed: **Endpoint Detection** (missing the initial file drop), or **PowerShell Logging** (failing to capture the script block content).
2.  **Propose and Track Improvements:**
    * **Script Block Logging (Sentinel Requirement):** Ensure **PowerShell Script Block Logging** and **Module Logging** are enabled and actively sending logs to Sentinel/MDE on *all* endpoints, as this is the only way to capture the decoded command.
    * **Constrained Language Mode (CLM):** Implement a policy (WDAC) to enforce **Constrained Language Mode** on all user and non-administrative endpoints. This significantly limits the malicious capabilities of PowerShell.
    * **ASR Deployment:** Deploy the **"Block execution of potentially obfuscated scripts"** ASR rule in Enforce Mode.
    * **JIT/Just-Enough-Admin:** Restrict the use of high-privilege credentials on endpoints, limiting the attack surface for credential theft via PowerShell.
3.  **Documentation and Knowledge Transfer:** Update playbooks and train analysts on common Base64 encoding patterns and known PowerShell post-exploitation modules.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query focuses on finding common obfuscation methods, specifically Base64 encoding (`-enc` or `-encodedcommand`) used with PowerShell, which is a near-certain indicator of malicious intent.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Suspicious Encoded PowerShell Execution (T1027.004)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-e", "-EncodedCommand")
| where InitiatingProcessFileName !in ("IntuneManagementExtension.exe", "ConfigurationManagerClient.exe") // Exclude known admin tooling
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
Concluding Remarks: Unmasking the Fileless Threat:

PowerShell is the modern adversary's tool of choice because it's built-in, trusted, and often executed filelessly. This means you can't rely on simple hash or file name detection—you must rely entirely on its behavior and command line syntax.

The Decoder Ring: If you see -EncodedCommand, your first action must be to decode it. The Base64 string is the payload; the rest is just the wrapper. You cannot understand the attack until you have the plaintext script block.

Logging is Your Lifeline: Without PowerShell Script Block Logging enabled and flowing to Sentinel, you are blind to 90% of modern execution attacks. Every incident where the decoded script is missing is a critical gap in your logging policy that must be closed immediately.

Enforce Constraint: Your long-term defense against this attack is not better detection, but prevention via Constrained Language Mode. This is the only way to neuter PowerShell and force the attacker to use noisier, less effective methods.
