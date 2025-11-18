# SOC Investigation Spine: Unknown or Rare User-Agent C2 – T1071.001

**Explanation:** This playbook analyzes Command and Control (C2) communication using **HTTP/HTTPS** where the malware agent utilizes a highly **unusual, unknown, or rare User-Agent (UA) string** (e.g., "Mozilla/5.0 (Windows; Zombieware) payload/1.337"). This technique is a simple but effective way for attackers to distinguish their C2 traffic from legitimate web browsing. The malicious UA string serves as a clear fingerprint for the malware on the network. The most reliable **Anchor Point** is the **Proxy/Firewall log detection of a connection to an external endpoint using a statistically rare or invalid User-Agent string.**

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1059 (Execution) | **Endpoint:** User executes a dropper/loader that contains the C2 agent. | **Process Event:** Execution of a malicious file or obfuscated script that loads the C2 component. |
| **Execution / Foothold** | T1055 (Process Injection) / T1059 (Scripting) | **Process/Memory:** The beaconing payload is executed, either filelessly or by a dropped binary. | **Process Anomaly:** A non-browser process (e.g., `svchost.exe`, `powershell.exe`) initiates external network activity. |
| **C2 Beaconing (ANCHOR)**| **T1071.001 (Web Protocols)** | **Network/Proxy Logs:** A statistically rare or unknown User-Agent string is used in a request to an external IP/domain. | **Proxy Log IOC:** HTTP request containing UA: `RareMalwareClient/v1.0` or a short, base64-encoded string. |
| **Lateral Movement / Command** | T1021 (Remote Services) | **Network/Identity:** C2 channel receives a command, causing the compromised host to initiate internal access (e.g., PtH, RDP) to a peer host. | **Identity Log:** Authentication attempt to an internal server immediately following a beacon check-in. |
| **Impact / Exfiltration** | T1041 (Exfiltration Over C2 Channel) | **Network:** C2 directs the payload to stage and exfiltrate data back through the established channel. | **Network Flow IOC:** Sudden, massive increase in **outbound data volume** over the identified C2 session. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Network & Protocol IOCs

1.  **User-Agent Anomaly (The C2 Tell):** The most critical IOC is the **User-Agent header** captured in proxy, firewall, or web application logs. L3 analysts must compare the UA string against a statistical baseline:
    * **Rarity:** The UA string appears in less than 0.01% of all organization traffic.
    * **Structure:** The UA string is short, contains non-standard keywords (e.g., product names like `Sliver`, `Meterpreter`), or is a known **C2 Framework UA** (e.g., UAs used by PoshC2, Empire, or custom Go/Python malware).
    * **Invalid Format:** The UA does not conform to the standard HTTP specification (e.g., missing parenthesis, incorrect platform names).
2.  **Process-to-Network Mismatch:** Correlate the network connection event with the corresponding **process execution** log on the source host. If the UA string suggests Chrome but the process initiating the connection is `powershell.exe` or a non-browser executable, this is a strong indicator of spoofing or malicious activity.
3.  **Domain/IP Reputation:** Analyze the destination URL/IP associated with the suspicious UA. C2 domains are often **newly registered** (Domain Age < 60 days) or have low reputation scores, confirmed via threat intelligence lookup.

### Process, Memory, and File IOCs

1.  **Network Initiating Process:** Identify the exact executable path that initiated the connection using the malicious UA. If it's a script host (`powershell.exe`), investigate the **decoded command-line arguments** (Event ID 4104) for the use of networking cmdlets like `Invoke-WebRequest` or `System.Net.WebClient`.
2.  **Injected Code:** If the process initiating the traffic is a core system binary (e.g., `svchost.exe`), perform memory analysis to detect **code injection** (T1055). EDR logs should be reviewed for preceding API calls like `WriteProcessMemory` or `CreateRemoteThread`.
3.  **File Staging:** Look for any **newly created files** (executables, scripts, compressed archives) in temporary or public directories that may have been downloaded or staged by the C2 agent following the initial beacon.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Sever the C2 channel and contain the execution. | **Block the Destination IP/Domain** at the proxy/firewall level. **Isolate the host** immediately. **Kill the compromised process** that is initiating the C2 beacon. |
| **Network Filtering** | **User-Agent Whitelisting/Blacklisting:** Filter traffic based on UA string rarity and known malicious patterns. | Configure **Web Proxies/Firewalls** to **block requests containing User-Agent strings** that are not statistically present in a pre-approved baseline or that match known malicious UA patterns. |
| **Process-Network Correlation** | **Mandate EDR/Proxy Integration:** Ensure network flow logs can be directly correlated with process execution logs on the endpoint. | Implement a security tool correlation rule that alerts when a **non-browser executable** (Parent Process) initiates a web connection (Network Log) using a **standard browser User-Agent** (UA Spoofing). |
| **Endpoint Logging** | **Enhanced Script Logging:** Capture the full execution context of scripting engines. | Mandate **PowerShell Event ID 4104 (Script Block Logging)** to fully capture the code that is using networking cmdlets to perform C2 communication. |
