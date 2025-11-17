# Incident Response Playbook – RDP Lateral Movement

This playbook addresses the use of **Remote Desktop Protocol (RDP)** for **Lateral Movement (T1021.001)**. After compromising an initial host, attackers often use existing RDP sessions and stolen credentials (or Pass-the-Hash) to jump to other systems, especially servers and high-value targets. This technique often appears as legitimate administrative activity but exhibits abnormal behavioral characteristics.

**MITRE ATT&CK Tactic:** Lateral Movement (TA0008)
**Technique:** Remote Services: RDP (T1021.001)
**Critical Threat:** Rapid, interactive, and often covert movement across the network, leading to hands-on-keyboard access of critical infrastructure.

---

## 1. L2 Analyst Actions (Initial Triage & Session Analysis)

The L2 analyst must confirm that the RDP session is anomalous by checking the source, time, and user context.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the RDP activity is tied to any documented, scheduled, or approved administrative access (e.g., jump-box use, vendor support session, known privileged access workflow). **Reject RDP sessions originating from unexpected user endpoints or servers.**
2.  **Source Host Anomaly:** Identify the RDP **source machine (`RemoteIP`)** using **`DeviceLogonEvents`**. This machine is likely the initial foothold and must be immediately triaged for credential theft or initial access vectors (Phishing, Exploit).
3.  **Authentication Pattern:** Analyze the user's RDP login history:
    * **Time:** Is the RDP session occurring outside the user's normal working hours or in an unusual time zone?
    * **Sequence:** Has the user established RDP sessions to systems they **never access** (e.g., from a laptop to a finance server)?
    * **Failures:** Look for a high volume of failed RDP logins immediately preceding the success (indicates brute-forcing or credential spray).
4.  **Local RDP Logs:** Check the Windows Event Logs on the target host (Security Event ID 4624/4647, and TerminalServices-LocalSessionManager 21/24/25) for evidence of the session start, source, and successful logon type.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId` (The RDP target/victim server).
* `RemoteIP` / `SourceDeviceName` (The machine initiating the RDP session).
* `AccountName` / **`UPN`** (The compromised user account used for RDP).
* **Time Range:** The $\pm24$ hours surrounding the RDP session start.
* **Session Details:** The full logon event details showing the `LogonType` (usually Type 10 - RemoteInteractive).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** successful RDP session using an **Administrator/Tier 0** account from a non-privileged user workstation. **Severity is Critical.**
* The RDP session **originates from a system confirmed to be compromised** (Source Device is already flagged).
* The RDP session is followed immediately by **file transfers** (using shared drives/clipboard) or **malicious execution** on the target.
* The source machine is geographically **unexpected** (e.g., external IP or unusual country).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Movement Mapping)

The L3 analyst must assume the RDP session is a hands-on-keyboard intrusion and map the full path of compromise.

### 2.1 Full Attack Chain Reconstruction

1.  **Movement Map:** Use the RDP session logs to map the full path of lateral movement (the "server-hopping" sequence). Example: `UserLaptop -> ServerA -> ServerB (DC)`. Every system in the chain is compromised.
2.  **Session Activity Review:** Audit the target machine's process logs (`DeviceProcessEvents`) **during the RDP session** (Logon Time to Logoff Time):
    * **File Execution:** What executables were run? Look for utilities like `cmd.exe`, `powershell.exe`, or dropped payloads.
    * **Discovery:** Execution of commands like `whoami /all`, `ipconfig`, `net user /domain`.
    * **Tunnelling/Exfiltration:** Evidence of communication channels being established (e.g., SSH tunnels, data compression and transfer).
3.  **Initial Access Corroboration:** Trace the credentials used for RDP back to the original host where they were likely stolen (PtH, Credential Dumping, Phishing).

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (Confirmed):** RDP lateral movement is a strong indicator of a hands-on-keyboard adversary.
    * **Misconfiguration / Risky Pattern:** (Low Probability) Unrestricted administrative access between tiers.
2.  **Scope the Incident:** The scope includes **all hosts** involved in the RDP chain, the **compromised identity**, and any **data accessed** during the interactive session.

---

## 3. Containment – Recommended Actions (Session & Identity Kill)

Containment must break the adversary's interactive session and invalidate the stolen credentials.

1.  **Isolate Source & Target:** **MANDATORY** isolate the initial source machine (where the credentials were stolen) and the immediate RDP target machine (`DeviceName`) using MDE.
2.  **Kill Session:** Forcibly **terminate the suspicious RDP session** on the target machine. This stops the attacker's interactive control instantly.
3.  **Credential Revocation:** Force an immediate **password reset** for the compromised user account (`AccountName / UPN`), and enforce a logoff/token revocation across all endpoints.
4.  **Network Blocking:** If the source IP is external or unexpected, block that IP at the network perimeter (firewall/WAF).

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must enforce stricter controls over which accounts can access which systems via RDP.

1.  **Control Failure Analysis:** Identify which control failed: **Network Segmentation** (allowing RDP between sensitive and non-sensitive networks), or **Identity Governance** (permitting RDP for highly privileged accounts).
2.  **Propose and Track Improvements:**
    * **Tiered Access/GPO:** Implement **Group Policy Objects (GPO)** or **Intune Settings** to strictly limit RDP access: Only privileged **Jump Hosts** should be able to RDP into servers, and user workstations should **never** RDP directly to domain infrastructure.
    * **Network Level Authentication (NLA):** Ensure NLA is mandatory on all systems to prevent pre-authentication exploits and credential brute-forcing.
    * **Conditional Access / MFA:** For any RDP gateway or VDI solution, enforce **MFA** for the connection setup. Implement a **Conditional Access Policy** to block access from suspicious geographies or IPs.
    * **RDP Monitoring:** Deploy a refined detection rule to monitor for any **non-administrative RDP session duration** (e.g., sessions lasting longer than 4 hours) or multiple consecutive sessions.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that RDP is often the final stage before data exfiltration or mass disruption (e.g., deploying ransomware).

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for RDP sessions that originate from unexpected or potentially compromised user devices into sensitive infrastructure, indicating unauthorized lateral movement.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for RDP Lateral Movement (User Workstation -> Server)
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "RemoteInteractive" // RDP sessions
| where Protocol == "RDP"
| extend RemoteIP = coalesce(RemoteIP, InitiatingProcessCommandLine) // Extract source IP from command line if necessary
| where isnotempty(RemoteIP) and RemoteIP !startswith "127." // Exclude local RDP loopbacks
| join kind=leftouter (
    DeviceInfo // Identify device type for better filtering
    | distinct DeviceName, DeviceType
) on DeviceName
| extend TargetDeviceType = DeviceType
| extend SourceIP = RemoteIP
| join kind=leftouter (
    DeviceInfo
    | distinct DeviceName, DeviceType
) on $left.SourceIP == $right.IPAddress
| extend SourceDeviceType = DeviceType
// Filter: Look for a standard client machine logging into a server/DC/critical asset
| where TargetDeviceType in ('Server', 'Domain Controller')
| where SourceDeviceType !in ('Server', 'Domain Controller', 'Jump Host') // Source is an unexpected device type
| summarize by Timestamp, DeviceName, TargetDeviceType, AccountName, RemoteIP, SourceDeviceType, Protocol
| order by Timestamp desc
```
Concluding Remarks: RDP – The Attacker’s Favorite Back Door

RDP is the attacker’s gold standard for hands-on-keyboard time. When you see suspicious RDP activity, you are no longer dealing with an automated script or malware; you have a human adversary inside your network, actively exploring and escalating.

It’s not the Protocol, it’s the Path: The RDP session itself is benign. What matters is the unusual path—a user jumping from their normal workstation to a core financial server they shouldn't manage. Focus on the source-target pair.

Act Fast, Log Off: Your primary containment action is to terminate the session. Every second the session remains active is a second the attacker has to steal more credentials, stage data, or establish a more resilient persistence mechanism.

Segmentation is Key: The only way to stop this is to break the path. Implement a strong tiered model where RDP access is strictly regulated. If a user is compromised, they should only be able to RDP to systems in their current, lower-security tier, not jump straight to your Domain Controllers.
