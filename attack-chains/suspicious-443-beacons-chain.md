# SOC Investigation Spine: Suspicious 443 Beacon Patterns – T1071.002

**Explanation:** This playbook analyzes Command and Control (C2) communication using **HTTPS (TCP/443)**, often referred to as "beacons." Attackers leverage legitimate encryption (SSL/TLS) and common web ports to mask their traffic as benign activity. The "beacon pattern" is defined by repetitive, low-volume communication at fixed intervals (e.g., every 60 seconds) between a compromised internal host and an external, suspicious IP/domain. Advanced techniques involve **Jitter** (randomized timing), **Domain Fronting**, and custom **TLS fingerprints** to evade detection. The most reliable **Anchor Point** is the **detection of high-entropy, repetitive, fixed-interval HTTPS traffic** to an unknown external endpoint.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1059 (Execution) | **Endpoint:** User executes a dropper/loader that contains the C2 agent. | **Process Event:** Execution of a malicious file or obfuscated script (e.g., `powershell.exe -enc ...`). |
| **Execution / Foothold** | T1055 (Process Injection) | **Process/Memory:** The beaconing payload is injected into a legitimate process (e.g., `explorer.exe`, `svchost.exe`). | **Memory Anomaly:** EDR alert on cross-process memory writing or suspicious DLL injection into a core system binary. |
| **Beaconing (ANCHOR)**| **T1071.002 (Encrypted Channel)** | **Network/Process:** A compromised process initiates repetitive, fixed-interval HTTPS connections to a suspicious external domain/IP. | **Network Flow IOC:** Repetitive connections on TCP/443 with low request/response volume and high entropy in TLS SNI/JARM hash. |
| **Lateral Movement / Command** | T1021 (Remote Services) | **Network/Identity:** C2 channel receives a command, causing the compromised host to initiate internal access (e.g., PtH, RDP) to a peer host. | **Identity Log:** Authentication attempt to an internal server immediately following a beacon check-in. |
| **Impact / Data Staging** | T1041 (Exfiltration Over C2 Channel) | **Network/File:** C2 receives command to stage files or exfiltrate data back through the established 443 channel. | **Network Flow IOC:** A sudden, massive increase in **outbound data volume** over the existing 443 session. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Network & Protocol IOCs

1.  **Fixed Interval/Repetition:** The most fundamental IOC is the **pattern of communication**. Analyze network flow logs (NetFlow, firewall, proxy) for an internal host initiating an HTTPS connection to the same external IP/domain at **regular, short intervals** (e.g., 30s, 60s, 300s). Be aware of **Jitter** (randomized timing) intended to break this pattern.
2.  **TLS Metadata/Fingerprinting:** Since the traffic is encrypted, focus on the metadata visible before encryption:
    * **SNI (Server Name Indication):** Is the SNI hostname associated with a known **C2 domain** or a **Domain Fronting** service (e.g., Google or Amazon CDN)?
    * **JARM/Ja3 Hash:** Use network security monitors to calculate the **TLS Client Fingerprint (e.g., JARM or Ja3)**. A suspicious or unique fingerprint not matching a common browser or OS binary is a high-fidelity IOC for C2 frameworks like Cobalt Strike.
3.  **Traffic Volume Anomaly:** The initial beacon requests and responses are typically **low volume** (e.g., <5KB total). A sudden, massive increase in **outbound bytes** over that specific session strongly indicates **data exfiltration** is occurring.
4.  **Domain Age/Reputation:** The destination domain should be checked against external threat intelligence sources. C2 domains are often **newly registered** (Domain Age < 60 days) or have low reputation scores.

### Process, Memory, and File IOCs

1.  **Beaconing Process Anomaly:** Identify the process that initiated the outbound connection. If a legitimate process (like `svchost.exe`, `explorer.exe`) initiates network traffic to a suspicious external IP, it points to **Process Injection/Hollowing**. The EDR should alert on the **`PROCESS_VM_WRITE`** or **`CreateRemoteThread`** API calls that led to the injection.
2.  **Parent-Child Chain:** Walk backward from the compromised process to find the initial loader/dropper that injected the C2 agent. This will often be an obfuscated script (`powershell.exe -enc`) or a temporarily dropped executable.
3.  **Memory Artifacts:** Use forensic analysis on the compromised process's memory dump (from EDR) to look for high-entropy regions, strings associated with C2 frameworks (e.g., "Malleable C2 profile strings"), or the presence of known payload code.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Sever the C2 communication channel and contain the execution. | **Blackhole the C2 Destination IP/Domain** at the firewall/proxy. **Isolate the host** immediately to prevent further internal movement. **Terminate the compromised process** that is initiating the beacon. |
| **Network Visibility** | **TLS Interception/Inspection:** Decrypt and inspect encrypted traffic where legally and functionally possible (especially egress traffic). | Implement a **Proxy/Next-Gen Firewall** to perform **SSL/TLS deep packet inspection** to analyze the actual content of the 443 beacon traffic. |
| **Process Control** | **Monitor and Restrict Network Access:** Limit the network access of core system processes to known good destinations. | Configure EDR rules to alert on system processes (`svchost.exe`, `lsass.exe`) initiating **outbound network connections** to external IP addresses. |
| **Protocol Fingerprinting** | **Baseline JARM/Ja3:** Establish a baseline of known, expected TLS client fingerprints and alert on any traffic using new, unrecognized, or known malicious (e.g., Cobalt Strike) fingerprints. | Deploy network security sensors capable of **TLS fingerprinting** (JARM/Ja3) and integrate alerts into the SIEM. |
