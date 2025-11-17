# Incident Response Playbook – WinRM-based Lateral Execution

This playbook addresses **Lateral Movement (TA0008)** and **Execution (TA0002)** using **Windows Remote Management (WinRM)**, specifically the command-line tools `winrm.cmd` or, more commonly, **PowerShell Remoting (PSRP)** via `Invoke-Command` or `Enter-PSSession` (T1021.006). WinRM is a trusted native protocol often used by administrators for remote management and automation. Attackers leverage compromised credentials to execute commands (often base64-encoded PowerShell) on remote hosts, blending in with legitimate administrative traffic.

**MITRE ATT&CK Tactic:** Lateral Movement (TA0008), Execution (TA0002)
**Technique:** Remote Services: Windows Remote Management (T1021.006)
**Critical Threat:** Confirmed credential compromise and successful command execution on a remote, often high-value, target, indicating hands-on-keyboard activity.

---

## 1. L2 Analyst Actions (Initial Triage & Traffic Validation)

The L2 analyst must confirm that the WinRM session was unauthorized and was used to deliver a malicious payload.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the remote command execution is tied to any documented, scheduled, or emergency administrative script, patching activity, or deployment. **Reject any execution of commands that involve downloading code, base64 encoding, or known malicious hashes.**
2.  **Network and Protocol Check:** Verify the network traffic:
    * **Protocol/Port:** Confirm communication over **HTTP Port 5985** or **HTTPS Port 5986** (WinRM/PSRP).
    * **Source/Destination:** Identify the **Source Host** (the attacker's pivot point) and the **Destination Host** (the victim).
3.  **Command Execution Vetting (Destination Host):** Review the process creation logs on the **Destination Host**. Look for the `wsmprovhost.exe` process (the host for the remote session) spawning suspicious child processes, typically:
    * **`powershell.exe`:** Often with long, base64-encoded or obfuscated command lines.
    * **`cmd.exe`:** Executing reconnaissance or staging commands.
4.  **Credential Check:** Identify the **Account Name** used for the remote session. Is this a privileged service account, a legitimate administrator, or a compromised standard user?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId` (Both Source and Destination Hosts).
* `AccountName` / **`UPN`** (The compromised identity used for WinRM).
* **Time Range:** The $\pm1$ hour surrounding the remote session establishment.
* **Artifacts:** The **Source Host IP**, the **Full Command Line** executed on the destination by `wsmprovhost.exe`, and the **Execution Hash** of any dropped payload.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed unauthorized command execution over WinRM/PSRP. **Severity is Critical.**
* The command execution involves **base64 encoding** or known **payload delivery utilities** (`certutil`, `IEX`, `Invoke-WebRequest`).
* The source or destination host is a **Domain Controller** or a **Critical Server** (Tier 0 asset).
* The compromised identity is a **Domain Administrator** or highly privileged service account.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Initial Access Link)

The L3 analyst must assume the attacker has achieved domain dominance and is using WinRM as a primary lateral movement utility.

### 2.1 Full Attack Chain Reconstruction

1.  **Credential Source (Source Host Focus):** Trace the activity on the **Source Host** backward. How was the credential for the WinRM session obtained? (e.g., Lsass dump via `procdump.exe`, brute force, or a successful phishing attempt). This identifies the true point of ingress.
2.  **Payload Analysis:** Decode the base64-encoded command line executed on the destination host. Determine the payload's intent:
    * **Persistence:** Was a Scheduled Task (T1053.005) or Service (T1543.003) created?
    * **Credential Access:** Was `Invoke-Mimikatz` or similar executed to dump credentials from the new victim machine?
    * **Discovery:** Execution of detailed domain discovery commands (`Invoke-ShareFinder`, `Net user /domain`).
3.  **WMI vs. PSRP:** Confirm if the attacker used WMI (port 135/RPC, followed by dynamic ports) or PSRP (WinRM ports). Both are common lateral movement techniques, but the process trace differs (`wsmprovhost.exe` for PSRP, `wmiprvse.exe` for WMI).
4.  **Scope the Domain:** Review WinRM logs across the entire domain for other successful or failed connections using the **compromised account**. This determines the full scope of lateral movement.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1021.006 Confirmed):** Hands-on-keyboard lateral movement using compromised credentials.
2.  **Scope the Incident:** The scope includes the **initial compromised host**, the **final victim host**, all **intermediate pivot hosts** the attacker may have touched via WinRM, and the **compromised credential**.

---

## 3. Containment – Recommended Actions (Credential Kill & Execution Vector Block)

Containment must focus on invalidating the compromised credentials immediately, as they are the key to the attacker's continued movement.

1.  **Isolate Endpoint:** **MANDATORY** isolate the **Destination Host** where the malicious payload was executed.
2.  **Credential Revocation:** **IMMEDIATELY** reset/revoke the password for the **compromised identity**. If the account is a service account, suspend the account before resetting the password to prevent application failure, then update all services using it.
3.  **Block Lateral Movement:**
    * **Firewall Rule:** On all critical endpoints, configure the firewall to **deny inbound WinRM (5985/5986)** connections from all but a defined list of administrative hosts.
    * **Session Kill:** If the attacker is still in an active PSSession, use the management tooling to disconnect and kill the session.
4.  **Remove Persistence:** Search for and **remove all persistence mechanisms** (Scheduled Tasks, Run keys, services) created by the executed remote command.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must enforce a least-privilege identity model and restrict remote execution.

1.  **Control Failure Analysis:** Identify which control failed: **Identity Management** (credential theft/weak credentials), or **Network Access** (WinRM/PSRP allowed from unapproved hosts).
2.  **Propose and Track Improvements:**
    * **Credential Hardening:** Enforce **Just-in-Time (JIT)** administrative access and use **Privileged Access Workstations (PAW)** for all remote management. Implement MFA for all administrative accounts.
    * **Network Segmentation:** Use the host firewall (GPO or Intune) to enforce that **WinRM/PSRP traffic is only allowed from administrative subnets or PAW systems**.
    * **PowerShell Logging:** Enforce **full PowerShell Script Block Logging and Module Logging** across all endpoints to ensure all remote commands (including decoded base64) are captured.
    * **Detection Tuning:** Implement a high-fidelity detection rule that flags any instance of `wsmprovhost.exe` or `wmiprvse.exe` spawning a child process that has a **base64-encoded command line**.
3.  **Documentation and Knowledge Transfer:** Update the Identity Governance policy and the Threat Model, emphasizing that WinRM/PSRP is the primary post-compromise lateral movement tool and must be heavily restricted.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for the signature of a malicious PSRP session: the `wsmprovhost.exe` process spawning a shell with suspicious command-line arguments.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for WinRM/PSRP Lateral Execution (T1021.006)
DeviceProcessEvents
| where Timestamp > ago(7d)
// 1. Target the host process for remote management sessions
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
// 2. Identify suspicious child processes spawned by the remote session
| where FileName in ("powershell.exe", "cmd.exe")
// 3. Look for strong indicators of malicious payload delivery/execution
| where ProcessCommandLine has_any (
    "-EncodedCommand", // Base64 encoding
    "Invoke-Expression", // IEX
    "Invoke-Command",
    "certutil", "bitsadmin", // Native download utilities
    "lsass", // Credential access attempts
    "New-Service" // Persistence attempts
)
| extend RemoteUser = InitiatingProcessAccountName
| extend AttackerCommand = ProcessCommandLine
| project Timestamp, DeviceName, RemoteUser, FileName, AttackerCommand, InitiatingProcessCommandLine
| order by Timestamp desc

```
Concluding Remarks: The Administrator's Tool

WinRM is the ultimate administrator's tool, and that's precisely why attackers love it. By using a valid protocol with a compromised, valid credential, the attacker achieves "safe passage" onto the remote host.

It's a Credential Problem: The network connection is legitimate; the credential is the hack. Focus 80% of your energy on invalidating that credential (password reset/session kill) and hardening your overall identity posture.

Decode the Command: If you find a base64-encoded command line, decode it immediately. That decoded payload will tell you the attacker's exact intent (persistence, dumping, or C2).

Source Matters: Lateral movement means there is a Source Host and a Destination Host. Never clean the destination without first investigating the source, which is where the attacker initially obtained the credentials.
