# Incident Response Playbook – Pass-the-Hash Pattern (NTLM)

This playbook addresses the highly dangerous post-exploitation technique known as **Pass-the-Hash (PtH)**. This attack leverages stolen NTLM hashes (password equivalents) from memory (LSASS) or the registry and reuses them to authenticate to other systems without ever knowing the plaintext password. This is a primary method for lateral movement (T1550.002).

**MITRE ATT&CK Tactic:** Lateral Movement (TA0008), Credential Access (TA0006)
**Technique:** Use Alternate Authentication Material (T1550.002), OS Credential Dumping (T1003)
**Critical Threat:** Rapid, covert lateral movement across the network using valid domain credentials, bypassing two-factor authentication (MFA) on older, legacy services.

---

## 1. L2 Analyst Actions (Initial Triage & Lateral Movement Confirmation)

The L2 analyst must confirm two key indicators: the source of the hash theft and the first successful lateral authentication attempt using that stolen hash.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the authentication is tied to any documented, expected administrative scripts or legacy tooling that still utilizes NTLM without Kerberos. **Reject non-standard NTLM authentications.**
2.  **Authentication Anomaly:** Identify an authentication event where the user logs in to a new host **without a prior interactive login** on that system. Look for NTLM authentication coming from a process that shouldn't be initiating it (e.g., a standard application launching a network service request).
3.  **Precursor Check (Hash Theft):** Immediately check the source machine (`DeviceName`) for precursor alerts indicating **Credential Dumping (T1003)**, such as access to `lsass.exe` memory or registry key exports.
4.  **Source Process Identification:** Identify the process on the source machine that is initiating the NTLM authentication attempt. Tools like `Mimikatz`, `PowerSploit`, or native tools like `Invoke-Command` will be the common vectors.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic documentation:

* `SourceDeviceName` / `SourceDeviceId` (Where the hash was stolen).
* `TargetDeviceName` (Where the hash was used for lateral authentication).
* `AccountName` / **`UPN`** (The compromised user whose hash was used).
* **Time Range:** The $\pm1$ hour window spanning the credential dump and the first successful PtH authentication.
* **Authentication Logs:** The raw Security Event Logs (ID 4624/4648) showing the **Network Logon Type (3)** authentication on the target machine.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **Successful NTLM authentication** from an unexpected source to a high-value target (Domain Controller, Exchange Server). **Severity is High.**
* The compromised account (`AccountName`) is a **privileged administrator** or service account.
* **Multiple failed and/or successful PtH attempts** are observed across different target servers within minutes (rapid lateral movement).
* Confirmed **`lsass.exe` memory access** on the source machine precedes the NTLM network authentication.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Hash Invalidation)

The L3 analyst focuses on confirming the credential theft mechanism and stopping the lateral movement chain by invalidating the stolen hash.

### 2.1 Full Attack Chain Reconstruction

1.  **Theft Mechanism:** Confirm the tool or method used for credential dumping (e.g., specific parameters used with `procdump`, `sekurlsa::logonpasswords` command line string).
2.  **Lateral Path Mapping:** Map the full path of movement: Which servers were accessed using the stolen hash? This reveals the full scope of the compromise.
3.  **Persistence Review:** Check all machines in the lateral movement chain for persistence artifacts (new user accounts, scheduled tasks, WMI events) created by the attacker using the compromised account.
4.  **Target Impact:** Determine the attacker's actions on the target machine (`TargetDeviceName`): Did they drop new tooling, escalate privileges further, or attempt to steal *more* hashes?

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1550.002 Confirmed):** Rapid, covert lateral movement using harvested credentials.
    * **Risky Operational Pattern:** (Low Probability) Misconfigured internal vulnerability scanner using NTLM credential relay (requires immediate policy change).
2.  **Scope the Incident:** The scope includes the **source machine (theft)**, the **identity (compromised account)**, and **all target machines** accessed via the stolen hash.

---

## 3. Containment – Recommended Actions (Credential & Protocol Break)

Containment must focus on invalidating the stolen credential across the network and blocking the ability to reuse NTLM hashes.

1.  **Isolate Source and Targets:** **MANDATORY** isolate the source machine (where the hash was stolen) and all highly sensitive target machines immediately.
2.  **Credential Invalidation:** Force an immediate **password reset** for the compromised `AccountName / UPN`. This invalidates the stolen hash for future use. **NOTE:** The password reset *must* be done to secure storage, assuming the attacker may still be able to monitor the network.
3.  **Protocol Restriction (Temporary):** Temporarily disable NTLM authentication on high-value targets (Domain Controllers, critical databases) via registry settings or GPO to block the PtH vector entirely during containment.
4.  **Session Kill:** Force a system reboot on the source machine to flush any credentials from `lsass.exe` memory.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must eliminate the source of the hash theft (memory exposure) and the protocol weakness (NTLM).

1.  **Control Failure Analysis:** Identify which control failed: **Credential Protection** (lack of LSA protection/Credential Guard), or **Protocol Governance** (allowing NTLM to persist).
2.  **Propose and Track Improvements:**
    * **Credential Guard Deployment:** Implement **Windows Defender Credential Guard** across all endpoints and servers to isolate `LSASS` from the kernel, physically preventing tools like Mimikatz from reading plaintext or hashed credentials.
    * **LSA Protection:** Implement **Local Security Authority (LSA) protection** via the registry to restrict unauthorized code injection into `lsass.exe`.
    * **NTLM Audit and Restriction:** Conduct an audit to identify all remaining NTLM authentication usage. Implement a phased plan to **disable NTLM** in favor of Kerberos across the domain.
    * **Tiered Access:** Ensure all privileged accounts are protected by an administrative tiering model, reducing their exposure to lower-tier, compromised endpoints.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that PtH attacks exploit a core weakness in the Windows authentication protocol. Train analysts on identifying the combination of **memory access + network logon type 3** as the definitive PtH signature.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query targets the combined evidence of credential theft (LSASS access) followed immediately by network logon events, which is the definitive signature of a Pass-the-Hash attack.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Pass-the-Hash (PtH) Activity Chain
let LSAccess = DeviceProcessEvents
| where ActionType == "ProcessAccessed" and TargetFileName =~ "lsass.exe"
| where InitiatingProcessFileName has_any ('procdump.exe', 'powershell.exe', 'dumpert.exe')
| project DumpTime=Timestamp, SourceDevice=DeviceName, SourceProcess=InitiatingProcessFileName, AccountName;
LSAccess
| join kind=inner (
    DeviceLogonEvents
    | where LogonType == "Network" and isnotempty(TargetDeviceName)
    | project LogonTime=Timestamp, TargetDevice=DeviceName, TargetIP=RemoteIP, AccountName
) on AccountName
| where LogonTime between (DumpTime .. DumpTime + 1h)
| project DumpTime, LogonTime, AccountName, SourceDevice, TargetDevice, TargetIP, SourceProcess | order by DumpTime asc
```
Concluding Remarks: Ending the Era of Password Equivalents:

The Pass-the-Hash attack is a living testament to the fact that your network is only as secure as its weakest authentication protocol. When you see this pattern, understand that the attacker has successfully bypassed the initial "password hurdle" and is now moving as a trusted, authenticated user.

Hashes Are Not Passwords, But They Are Keys: Remember that the NTLM hash is a password equivalent. Once it's stolen, changing the password is the only way to invalidate the stolen key. Never delay that step.

The Forensics Focus: Your priority in an L3 investigation is to find the precursor event (T1003). Knowing how the hash was stolen (which process accessed LSASS) is crucial for developing a permanent remediation control.

Kerberos is the Goal: Every successful PtH incident should lead to a concrete project plan to retire NTLM entirely in your environment. NTLM permits this weakness; Kerberos does not. You are fighting a war against a legacy protocol, and your remediation strategy must reflect that long-term goal.
