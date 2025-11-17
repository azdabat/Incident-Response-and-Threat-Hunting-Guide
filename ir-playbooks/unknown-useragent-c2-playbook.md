# Incident Response Playbook – Unknown or Rare User-Agent C2

This playbook addresses the detection of **Command and Control (C2)** communication where the malicious traffic attempts to blend in with legitimate web traffic by using an HTTP or HTTPS connection, but utilizes a **custom, rarely seen, or non-standard User-Agent (UA) string (T1071.001)**. Threat actors use unique UAs to evade network defenses that rely on whitelisting common browser UAs, and to easily filter their own traffic from legitimate noise on their C2 server.

**MITRE ATT&CK Tactic:** Command and Control (TA0011), Defense Evasion (TA0005)
**Technique:** Application Layer Protocol: Web Protocols (T1071.001), Custom/Non-Standard Protocol
**Critical Threat:** A covert communications channel is operational, proving the attacker has successfully executed a payload capable of establishing its own network connection, often for receiving commands or staging data exfiltration.

---

## 1. L2 Analyst Actions (Initial Triage & User-Agent Vetting)

The L2 analyst must focus on validating the legitimacy of the User-Agent string against the known organizational baseline and correlating it with the initiating process.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Check if the host recently deployed any new custom software, internal tool, or monitoring agent that might use a unique, non-browser User-Agent (e.g., custom telemetry, internal API calls). **Reject UAs that are garbled, contain random characters, or mimic known malware signatures.**
2.  **User-Agent Analysis:**
    * **Frequency/Rarity:** Confirm that the UA string is indeed rare or unknown across the enterprise. If the UA is seen on only one or a handful of hosts, it is highly suspicious.
    * **Spoofing Check:** Does the UA claim to be a standard browser but contain abnormal parameters (e.g., "Mozilla/5.0 (Windows NT 10.0; Win64; x64; **CustomPayload**) AppleWebKit/537.36")?
3.  **Source Process Correlation:** Identify the process that initiated the connection (`DeviceNetworkEvents`).
    * **Suspicious:** If the UA is rare but the process is **`chrome.exe`** or **`msedge.exe`**, this might indicate an infected browser extension or proxy. If the process is **`powershell.exe`**, **`wscript.exe`**, or an unknown executable, it is a high-confidence threat.
4.  **Destination Check:** Review the destination domain/IP (FQDN) associated with the UA. Is the domain known, trusted, or newly registered?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The user context of the running process).
* **Time Range:** The $\pm12$ hours surrounding the first detected connection.
* **Network Artifacts:** The **Full User-Agent String**, the **Source Process Path and Hash**, the **Destination IP and FQDN**, and the **Connection Count/Timing**.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed connection using a custom, **unique, or known malicious** User-Agent. **Severity is Critical.**
* The source process is an **unknown or unsigned executable** operating in the user's or a temporary directory.
* The connection shows a **periodic beaconing pattern** (e.g., check-ins every 300 seconds).
* Similar activity appears on **multiple hosts**, suggesting a widespread, automated campaign.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Payload Identification)

The L3 analyst must identify the specific malicious payload or script that is hardcoding the suspicious User-Agent string.

### 2.1 Full Attack Chain Reconstruction

1.  **Payload Location:** Determine the exact location, file name, and hash of the initiating process. This file is the primary infection source.
2.  **Persistence Analysis:** Review the host for persistence mechanisms associated with the payload (T1543.003, T1053.005). Does the payload run automatically via a **Registry Run key, Scheduled Task, or a malicious Service**?
3.  **Code Analysis (If Possible):** If the payload is a script (e.g., PowerShell, VBScript), analyze the code for the hardcoded User-Agent string and the C2 logic (e.g., base64 encoding, custom encryption).
4.  **Subsequent Activity:** Trace all activities immediately following the C2 connection. Look for evidence of:
    * **Secondary Payload Download:** The C2 channel may download a Stage 2 binary.
    * **Discovery:** Execution of system commands (`whoami`, `netstat`, `ipconfig`).
    * **Data Staging:** Creation of compressed archives (.zip, .rar) containing sensitive user data.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1071.001 Confirmed):** Established C2 channel using a stealthy, custom fingerprint.
2.  **Scope the Incident:** The scope includes the **host** that initiated the connection, the **compromised user account**, the **persistence mechanism**, and all **IOCs** associated with the custom User-Agent.

---

## 3. Containment – Recommended Actions (Fingerprint and Network Kill)

Containment must focus on eliminating the persistence and immediately blocking the unique C2 fingerprint.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Network Kill (UA/IP):** **IMMEDIATELY** block the **Destination IP and FQDN** at the network perimeter. Additionally, configure proxy/web filtering rules to **block any traffic containing the specific, malicious User-Agent string** discovered during triage.
3.  **Process Termination & Removal:** Terminate the initiating process and delete the malicious file and all associated persistence mechanisms (Registry keys, Scheduled Tasks, files).
4.  **Credential Revocation:** Reset/revoke affected credentials if the process was run with elevated privileges or if credential access was suspected.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must enforce stricter controls over custom network communication.

1.  **Control Failure Analysis:** Identify which control failed: **Network Filtering** (failing to inspect and block based on header data), or **Application Control** (allowing the execution of the unknown payload).
2.  **Propose and Track Improvements:**
    * **User-Agent Baseline:** Implement a SIEM/EDR rule to track and alert on any User-Agent string that has not been observed in the last 90 days, or any UA with an occurrence count of less than 5 across the environment.
    * **Proxy/Gateway Hardening:** Configure the web proxy to **deny requests** that contain User-Agents matching specific criteria (e.g., UAs containing a low entropy score or common C2 strings).
    * **Process-to-Network Correlation:** Enforce policies that audit or restrict non-browser, non-system executables (like executables in `%TEMP%` or user folders) from making direct outbound HTTP/S connections.
3.  **Documentation and Knowledge Transfer:** Update playbooks and threat models, emphasizing that attackers frequently bypass reputation checks by using custom User-Agents, making **network metadata analysis** a key defensive layer.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for User-Agent strings associated with network connections that are **rare** (low count) and originated from suspicious processes, thereby filtering out the noise of standard browser traffic.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Unknown or Rare User-Agent C2 (T1071.001)
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort in (80, 443) // Targeting standard web ports for blending
// Exclude common browsers and known system tools (e.g., update clients)
| where InitiatingProcessFileName !in ("chrome.exe", "msedge.exe", "iexplore.exe", "svchost.exe", "powershell.exe") 
| extend UserAgent = extract(@"(User-Agent:\s+)(.*?)(?:\r?\n|$)", 2, AdditionalFields) // Adjust extraction based on logging format
// 1. Summarize to find rare User-Agents
| summarize UA_Count = count() by UserAgent, InitiatingProcessFileName, DeviceName, RemoteIP, RemoteUrl
| where UA_Count < 5 // Focus on User-Agents seen less than 5 times in the last 14 days
| project Timestamp=now(), DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, UserAgent, UA_Count
| order by UA_Count asc, DeviceName asc

```
Concluding Remarks: The Fingerprint of the Attacker

The User-Agent is the attacker's fingerprint. By using a rare or custom UA, the attacker trades stealth for reliability—they know their unique traffic will reach their C2 server easily.

It’s Hardcoded: Unlike dynamic IP addresses, the custom User-Agent is often hardcoded into the malicious binary. This means the UA is a robust, high-fidelity Indicator of Compromise (IOC) that can be easily blocked network-wide.

The Process Context: Never stop at the UA. The critical piece of evidence is the InitiatingProcessFileName. Finding out which file is using the weird UA will lead you directly to the malware.

Proactive Hunting: Use the KQL query above to regularly hunt for UAs with a low occurrence count. This is a very effective way to surface new, customized malware strains before they are widely known.
