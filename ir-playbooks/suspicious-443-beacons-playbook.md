# Incident Response Playbook – Suspicious 443 Beacon Patterns

This playbook addresses the detection of highly suspicious **Command and Control (C2)** communication masquerading as legitimate HTTPS traffic on **Port 443**. Attackers utilize HTTPS (TLS) to encrypt their beaconing traffic, enabling it to bypass basic network monitoring and blend in with normal web browsing activity. Detections rely on timing, frequency, and anomalies in the process, certificate, or HTTP header data.

**MITRE ATT&CK Tactic:** Command and Control (TA0011), Defense Evasion (TA0005)
**Technique:** Application Layer Protocol: Web Protocols (T1071.001), Encrypted Channel (T1573)
**Critical Threat:** A covert and resilient communications channel has been established, allowing the attacker to receive commands, deliver secondary payloads, and exfiltrate data without immediate detection.

---

## 1. L2 Analyst Actions (Initial Triage & Traffic Validation)

The L2 analyst must verify that the network traffic is genuinely malicious and not a benign application update or licensing check.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the process or destination domain is associated with any recent software installation, patch, or legitimate maintenance. **Reject any connections going to known, reputable, and necessary cloud/vendor infrastructure (e.g., Microsoft, Google, antivirus vendors).**
2.  **Beaconing Pattern Analysis:** Immediately check the EDR network logs for the connection pattern:
    * **Frequency:** Is the connection **periodic** (e.g., every 60s, 300s, 10 minutes)? Consistent timing is a strong C2 indicator.
    * **Volume:** Is the data transfer **low volume** (small bytes sent/received), indicative of a beacon or check-in?
3.  **Source Process Inspection:** Identify the executable initiating the connection.
    * **Suspicious:** Processes like `powershell.exe`, `cmd.exe`, `svchost.exe` (when not for system services), or legitimate but abused binaries (LOLBINs) making external calls.
    * **Benign:** Standard browsers (`chrome.exe`, `msedge.exe`) or dedicated, known update agents.
4.  **Destination Artifacts (TLS/DNS):** Check the destination domain/IP:
    * **Reputation:** Is the destination a known C2 domain, newly registered, or using a suspicious **Dynamic DNS** service?
    * **Certificate:** Is the SSL certificate generic, self-signed, or issued very recently? Threat actors often use disposable or custom certificates.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The user context under which the suspicious process is running).
* **Time Range:** The $\pm24$ hours surrounding the first beacon detection.
* **Network Artifacts:** The **Source Process Path and Hash**, the **Destination IP and FQDN**, the **Protocol/Port** (443), and the recorded **Connection Timings/Intervals**.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** connection to a **known malicious domain/IP** or a **Dynamic DNS** service. **Severity is Critical.**
* The source process is **not a browser** and the beaconing pattern is **consistent** (low-volume, high-frequency).
* The C2 connection is followed immediately by a **new file drop** or **process injection** activity.
* The activity is observed on a **critical server** or a **privileged user's host**.

---

## 2. L3 Analyst Actions (Technical Deep Dive & C2 Framework Identification)

The L3 analyst must assume the host is compromised and focus on decrypting the attacker's communication channel and identifying the C2 framework.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access and Persistence:** Trace the process execution chain backward from the beaconing process. How was the executable dropped or launched? (e.g., Phishing attachment, vulnerability exploitation, or a malicious Scheduled Task). This is the true root cause.
2.  **Traffic Analysis (If Decryption Possible):** If network decryption (e.g., SSL inspection) is available, analyze the actual HTTP payloads inside the TLS tunnel. Look for:
    * **Unique User-Agents:** Malicious C2 frameworks (like Cobalt Strike, Sliver) often use distinct, non-standard, or spoofed User-Agent strings.
    * **Jitter and Malleability:** Try to identify the C2 framework based on connection metadata (timings, URL structure).
3.  **Targeted Discovery:** Review endpoint logs for any **command execution** (`DeviceProcessEvents` from the beaconing process) that occurred *after* the beacon, indicating the attacker received a command (e.g., discovery, enumeration, or lateral movement preparation).
4.  **Data Staging:** Check for file read/write events (`DeviceFileEvents`) on sensitive directories (e.g., user documents, configuration files) just before a beacon, suggesting data exfiltration preparation.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1071.001 Confirmed):** Established, stealthy command and control.
2.  **Scope the Incident:** The scope includes the **beaconing host**, the **initial access vector**, and potentially **other hosts** if the C2 command was to stage lateral movement.

---

## 3. Containment – Recommended Actions (Hard Kill & Channel Blockade)

Containment must focus on immediately terminating the malicious process and surgically eliminating the C2 communications channel.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE or network quarantine.
2.  **Hard Network Kill:** **IMMEDIATELY** block the **Destination IP and FQDN** at the network perimeter (firewall, proxy). Add a rule to the EDR network containment policy to ensure the block is host-specific as well.
3.  **Process Termination:** Identify the specific PID of the beaconing process and **terminate it immediately**.
4.  **Remove Persistence:** Search for and **remove the malicious file and all persistence mechanisms** (Registry Run keys, Scheduled Tasks, or malicious Services) that launch the beaconing process.
5.  **Credential Revocation:** If the compromised host was a server or the user was privileged, enforce a password reset for the associated user/service account, as the attacker may have already executed credential dumping commands.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must harden the network and endpoints against stealthy encrypted communications.

1.  **Control Failure Analysis:** Identify which control failed: **Network Defense** (failing to inspect or profile 443 traffic), or **Endpoint Protection** (failing to prevent the initial payload execution).
2.  **Propose and Track Improvements:**
    * **TLS/SSL Inspection:** For perimeter security, evaluate implementing **TLS inspection** (SSL man-in-the-middle) to inspect 443 traffic on non-standard processes or connections to untrusted categories.
    * **Network Flow Baselines:** Implement monitoring for **non-browser processes** initiating external 443 connections and enforce baselines. (E.g., `cmd.exe` should never talk outbound on 443).
    * **Certificate Trust Policy:** Deploy EDR rules to specifically alert on processes connecting to destinations using **self-signed or newly created TLS certificates**.
    * **LOLBIN Hardening:** Use **ASR** or **WDAC** rules to severely restrict which trusted binaries (like `powershell.exe`, `msbuild.exe`) are allowed to make outbound network connections.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, focusing on the danger of encrypted C2 and the need to analyze **behavior** (timing, process) rather than relying on signature checks for highly trusted ports.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query is designed to find processes initiating recurring, external connections on the highly trusted TCP port 443, a prime indicator of C2 beaconing.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Suspicious 443 Beaconing Patterns (T1071.001)
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 443
| where ActionType == "ConnectionSuccess"
// Filter out internal connections
| where RemoteIP !startswith "10." and RemoteIP !startswith "172.16." and RemoteIP !startswith "192.168."
| summarize
    ConnectionCount = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    FirstConnection = min(Timestamp),
    LastConnection = max(Timestamp),
    RemoteUrls = make_set(RemoteUrl, 10)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP, RemotePort
// Filter for consistent, frequent connections from a single process to a single external IP
| where ConnectionCount > 5 and UniqueRemoteIPs == 1
| extend TimeSpan = LastConnection - FirstConnection
// Calculate average interval, looking for consistency (e.g., beaconing every 5 minutes)
| extend AverageIntervalSeconds = iff(ConnectionCount > 1, total_seconds(TimeSpan) / (ConnectionCount - 1), 0)
// Filter out high-volume browsers and low-frequency connections, focus on periodic/low-and-slow
| where InitiatingProcessFileName !in ("chrome.exe", "msedge.exe", "firefox.exe") and AverageIntervalSeconds between (60 .. 1800) // 1 minute to 30 minutes

```
Concluding Remarks: The Blended Threat

Beaconing on Port 443 is the C2 gold standard for threat actors. It’s highly effective because it relies on the simple fact that almost all organizations trust HTTPS traffic.

Trust Nothing: Your analysis must pivot from "Is the port trusted?" to "Is the behavior trusted?" If a PowerShell process is calling a weird domain every five minutes, the answer is no, regardless of the port.

Decryption is the Key: If this pattern repeats, push your Network Engineering team to implement SSL/TLS decryption and inspection on the proxy for non-standard application traffic. You cannot fight C2 effectively if you can't see the data.

The Hunt: Use the KQL query above to proactively hunt for other hosts with similar periodic connection patterns. Where there is one beacon, there are often more.
| project DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, ConnectionCount, AverageIntervalSeconds, RemoteIP, RemoteUrls
| order by ConnectionCount desc
