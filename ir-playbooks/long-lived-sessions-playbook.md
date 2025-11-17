# Incident Response Playbook – Long-Lived External Sessions (C2 Implant)

This playbook is designed for high-severity alerts related to **long-duration, low-volume, and highly recurrent outbound network sessions**. This is a classic indicator of a successful Command and Control (C2) implant, where the attacker maintains persistent access (T1071 / T1105) often using common protocols like HTTPS or DNS.

**MITRE ATT&CK Tactic:** Command and Control (TA0011), Persistence (TA0003)
**Technique:** Application Layer Protocol (T1071), Standard Application Layer Protocol (T1071.001), Remote Access Software (T1021)
**Critical Threat:** A permanent backdoor or implant is established on an endpoint, facilitating continuous monitoring, lateral movement, or future exfiltration.

---

## 1. L2 Analyst Actions (Initial Triage & Persistence Validation)

The L2 analyst must confirm the abnormal session duration and identify the specific executable responsible for maintaining the persistence.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the session aligns with any expected long-lived internal service (e.g., VPN tunnel, specific cloud file sync service, or authenticated backup client). **Reject generic synchronization excuses.**
2.  **Duration Anomaly:** Validate that the connection duration significantly exceeds the **organizational baseline** for that protocol/port (e.g., a 12-hour HTTPS connection is abnormal; a 5-minute connection is normal).
3.  **Process Identification:** Identify the **Initiating Process Name** and its **Process ID (PID)**. Suspicious processes often masquerade as system files but run from unusual directories (e.g., `svchost.exe` from `\Users\Public`).
4.  **Destination Context:** Resolve the **Remote IP/FQDN**. Determine if the destination is a known high-risk provider (e.g., free dynamic DNS, cloud development/hosting providers often used for C2) or a newly registered domain (under 90 days).

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`**
* **Time Range:** The full duration of the suspicious session and the $\pm24$ hours before the session started (to capture the delivery/installation).
* **Network Flow:** Total **Duration** (Time Span), **Total Bytes** exchanged, and the **Protocol/Port** used.
* **Process Snapshot:** Full path, hash, and command line of the C2 process.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **Session Duration** exceeds 4 hours to an external, non-corporate endpoint.
* The initiating process is a **LOLBIN** (`powershell.exe`, `wscript.exe`, `certutil.exe`) or an unknown binary running from a user's `Temp` or `AppData` directory.
* The suspicious connection is accompanied by **process injection alerts** (T1055) or **failed logon attempts** (lateral movement precursors).
* The destination IP/Domain is flagged as a known C2 endpoint.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Implant Removal)

The L3 analyst focuses on dismantling the persistence mechanisms and recovering the protocol used for communication.

### 2.1 Full Attack Chain Reconstruction

1.  **Persistence Analysis:** Determine the mechanism used to ensure the session restarts after a reboot or failure. Look for:
    * **Registry Run Keys (T1547.001)**
    * **Startup Folders/Files**
    * **Scheduled Tasks (T1053.005)** — especially those disguised as maintenance.
    * **Service Creation (T1543.003)** — running under a local system or network service account.
2.  **C2 Protocol Analysis:** Analyze the network traffic for **beaconing patterns** (e.g., highly predictable, fixed-interval packets). Attempt to classify the C2 framework (e.g., Cobalt Strike, Metasploit, custom framework) based on TLS fingerprinting or unique header characteristics.
3.  **Decryption & Recovery:**
    * If the C2 used an **encrypted tunnel (HTTPS/TLS)**, attempt to leverage gateway logs for decryption or use the memory dump to identify the key.
    * If the C2 used **DNS (T1071.004)**, analyze DNS query logs for unusual payload encoding in the subdomains.
4.  **Internal Impact:** Determine what the attacker did *during* the long session (e.g., ran enumeration commands, performed file access, staged data for exfiltration).

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1071/T1105 Confirmed):** Established C2 implant.
    * **Misconfiguration:** (Extremely Low Probability) Misconfigured third-party monitoring agent or poorly written in-house application with excessive keep-alive settings.
2.  **Scope the Incident:** Identify all **hosts and identities** associated with the lateral movement activity that preceded the implant deployment. The scope includes the compromised host and all hosts accessed during the session.

---

## 3. Containment – Recommended Actions (Network Disruption & System Reset)

Containment must stop the C2 access and ensure all memory-resident components are flushed.

1.  **Network Disruption:** **MANDATORY** isolate the affected endpoint immediately. Simultaneously, **block the C2 destination IP/Domain** at the perimeter firewall/proxy to prevent beaconing from any other, undiscovered implants.
2.  **Memory Clearing:** **Force a system reboot** of the affected machine. Many implants and C2 processes rely on memory injection or scheduled tasks that are broken or cleared upon system restart.
3.  **Persistence Removal:** Delete all identified persistence artifacts (Registry keys, Scheduled Tasks, or malicious Service entries).
4.  **Credential Revocation:** Reset/revoke affected user credentials immediately, as the attacker may have already scraped passwords or session cookies during the long-lived session.

---

## 4. Remediation & Hardening – Strategic Improvements

Focus on reducing the attack surface for persistence and enhancing visibility into C2 protocols.

1.  **Control Failure Analysis:** Identify which control failed: **Endpoint Detection** (missing the initial implant drop), **Identity Management** (allowing persistence creation), or **Network Visibility** (failing to inspect or baseline the C2 traffic).
2.  **Propose and Track Improvements:**
    * **Execution Restriction:** Implement **WDAC/AppLocker** policies to prevent execution of processes from user-writable directories (Temp, AppData).
    * **Session Monitoring:** Deploy advanced network monitoring to calculate and flag the **Mean Time Between Beaconing Intervals** and alert on statistical outliers.
    * **Protocol Hardening:** For DNS-based C2, enforce **Internal DNS Resolvers Only** and deploy a DNS sinkhole or filter to block known high-risk dynamic DNS services.
    * **Hardening Baselines:** Implement GPO/Intune to disable unused legacy persistence vectors (e.g., WMI Event Consumers).
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that **initial access (T1071/T1105)** must be addressed by hardening client-side execution policies.

---

## 5. Threat Hunting Queries (KQL Focus)

These KQL fragments target the core behavioral indicator: persistent, long-duration network activity to external IPs.

### 5.1 Hunting Query Example (KQL Only)

This query calculates the total duration and volume of external connections per process over a 7-day period, flagging any connection active for more than 8 hours, indicating a strong likelihood of C2 beaconing.

```kql
// KQL Query for Persistent C2 Implants (Long-Lived External Sessions)
let TargetDuration = 8h;
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteIPType == "Public" and RemotePort in (80, 443, 53)
| summarize Start=min(Timestamp), End=max(Timestamp), Pkts=count(), Bytes=sum(RemoteBytes) by DeviceName, InitiatingProcessFileName, RemoteIP
| extend Duration = End - Start
| where Duration > TargetDuration and Pkts > 50 
| project DeviceName, Process=InitiatingProcessFileName, RemoteIP, ConnStart=Start, ConnEnd=End, Duration, Pkts, Bytes
| order by Duration desc
```
Concluding Remarks: Strategic Defense Against Covert Implants:
This playbook demonstrates an understanding that an attacker's goal is often to establish a permanent, low-profile presence. 

From "Alert Fatigue" to "Duration Analysis": Emphasize that you're pivoting away from noise (individual connection attempts) toward session duration and regularity. Detecting long-lived sessions proves an ability to analyze network behavior rather than just signatures.

Decoupling C2 and Implant: Stress that a successful response requires identifying both the C2 protocol (network) and the persistence mechanism (endpoint). You must find the reg key or scheduled task that ensures the implant survives the reboot you will execute.

Targeting the Protocol Evasion: Point out that C2 often abuses standard protocols (HTTPS/DNS). Your strategy to use TLS fingerprinting (L3 action) and DNS sinkholing (Remediation) shows expertise in advanced network counter-measures, not just basic firewalling.
