# Incident Response Playbook – Data Exfiltration over HTTPS (Volume Anomaly)

This playbook is designed for L2/L3 analysts responding to high-severity alerts related to **volumetric anomalies** in outbound encrypted network traffic (HTTPS/TLS). This indicates a high probability of data exfiltration (T1041 / T1567) bypassing static security controls.

**MITRE ATT&CK Tactic:** Exfiltration (TA0010), Command and Control (TA0011)
**Technique:** Exfiltration Over Encrypted Channel (T1041), Data Staging (T1560)
**Critical Threat:** Large volumes of sensitive data are leaving the network, often disguised as legitimate HTTPS traffic (e.g., uploads to cloud services, C2 using TLS).

---

## 1. L2 Analyst Actions (Initial Triage & Volume Validation)

The L2 analyst must validate the anomaly against organizational baselines, identify the source process, and pinpoint the destination endpoint.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Determine if the massive traffic volume can be explained by a recent, approved event (e.g., OS update push, large internal migration, cloud backup job). **Reject default explanations.**
2.  **Process Identification:** Identify the specific process and executable (`ProcessName`) initiating the high-volume outbound connection on port 443. This is the **most critical piece of evidence**.
3.  **Destination Analysis:** Identify the destination **FQDN/Domain** and **IP Address** for the traffic flow. Classify the destination:
    * **Cloud Storage:** (e.g., OneDrive, Dropbox, S3 bucket) — High probability of user-initiated file upload.
    * **Unknown/Suspicious IP:** (e.g., no known ASN, high-risk geo-location) — High probability of C2 or attacker-controlled endpoint.
4.  **Precursor Check (Staging):** Immediately check the host for alerts related to **Archive Creation (T1560)** or large file aggregation (e.g., creation of a `.zip`, `.rar`, or `.tar.gz` file) minutes or hours before the traffic spike.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for documentation and L3 handover:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`**
* **Time Range:** The $\pm24$ hours surrounding the connection anomaly.
* **Network Flow:** Total **Bytes Sent** and **Duration** of the suspicious connection.
* **Process Path:** Full path and hash of the initiating process.
* **Destination:** The full destination URL/Domain and its associated geolocation.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* `Severity` is **Medium or High**. (Any confirmed exfiltration volume is Medium/High.)
* The traffic destination is an **unknown or foreign-registered domain/IP**.
* The initiating process is a **non-standard utility** (e.g., `cmd.exe`, `powershell.exe`, or a recently dropped binary).
* Precursor alerts confirm **staging of sensitive data** (T1560) on the host prior to the connection.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Exfiltration Recovery)

The L3 analyst confirms the malicious nature of the traffic, attempts to identify the specific files exfiltrated, and determines the full chain of compromise.

### 2.1 Full Attack Chain Reconstruction

1.  **Staging-Exfiltration Link:** Trace the process execution. If an archive file was created (T1560), confirm that the initiating process of the HTTPS traffic was responsible for the archive upload.
2.  **Traffic Decryption (Where Possible):** Engage the Network Security team to review **SSL Visibility (TLS Decryption)** or **DLP Logs** at the proxy/gateway level for the *specific session* and *destination*. This is the only way to confirm the file names or content sent over HTTPS.
3.  **Initial Access Vector:** Trace backward to the initial compromise (e.g., phishing link, vulnerable service) that allowed the attacker to gain access and stage the data.
4.  **Lateral Movement/Credential Check:** Determine if the compromised host/identity accessed or enumerated sensitive file shares **before** staging the data.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1041 Confirmed):** Unauthorized process executing high-volume, covert uploads to an attacker-controlled endpoint.
    * **Policy Violation/Misconfiguration:** Legitimate user uploading sensitive company data to a personal, unauthorized cloud storage account (requires DLP review, not full intrusion response).
2.  **Scope the Incident:** Determine the **Classification and Volume** of the exfiltrated data (e.g., 5GB of customer PII, 20GB of source code). Identify all **hosts and identities** involved in the staging and upload.

---

## 3. Containment – Recommended Actions (Network & Identity)

Containment must focus on cutting off the data flow immediately and preserving the forensic state of the source host.

1.  **Network Disruption:** **MANDATORY** isolate the affected endpoint immediately. Simultaneously, **block the destination domain/IP** at the network perimeter (firewall/proxy) to prevent any potential subsequent connections from other compromised hosts.
2.  **Credential Revocation:** Reset/revoke affected user credentials (local, domain, cloud) as the attacker likely accessed data using the victim's authenticated identity.
3.  **DLP Constraint:** Update Data Loss Prevention (DLP) policies to block uploads of *any* content type to the malicious destination domain/IP, or restrict uploads to specific, approved cloud storage tenants only.
4.  **Forensic Capture:** Initiate a live memory dump and disk image acquisition of the source host for deep forensic analysis, as encrypted exfiltration often precedes further internal access.

---

## 4. Remediation & Hardening – Strategic Improvements

Focus on reinforcing the "last line of defense" (DLP) and improving visibility into encrypted traffic flow.

1.  **Control Failure Analysis:** Identify which control failed: **DLP** (didn't block the file content), **Proxy/Gateway** (lacked necessary TLS decryption/visibility), or **Behavioral Engine** (failed to establish a baseline for normal upload volume).
2.  **Propose and Track Improvements:**
    * **Behavioral Baselines:** Refine detection logic to alert on **Bytes Sent** exceeding the 99th percentile of normal traffic for *any* process or user identity over a sliding time window (see KQL below).
    * **TLS Inspection Deployment:** Strategically deploy or expand **TLS/SSL Inspection (Man-in-the-Middle)** capabilities on the perimeter gateway to enable content analysis for high-risk destinations.
    * **DLP Policy Enhancement:** Implement granular DLP policies targeting high-value content (e.g., credit card numbers, confidential document formats) and explicitly restrict upload to any domains outside of corporate control.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model and Knowledge Base entries, emphasizing that **high-volume encrypted traffic** is often the final phase of an intrusion, and precursors (T1560) must be prioritized.

---

## 5. Threat Hunting Queries (KQL Focus)

These KQL fragments hunt for connections that demonstrate significant deviations from normal network volume, focusing on HTTPS traffic.

### 5.1 Hunting Query Example (KQL Only)

This KQL query identifies devices that have sent an extremely high volume of data (Bytes Sent) over the standard HTTPS port (443) to external domains within a short window, filtering out common Microsoft/OS updates.

```kql
// KQL Query for Outbound HTTPS Volume Anomaly (Potential Exfiltration)
let TimeRange = 1d; // Look back over the last 24 hours
DeviceNetworkEvents
| where Timestamp > ago(TimeRange)
| where RemotePort == 443 // Focus on encrypted web traffic
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Internal"
// Filter out common high-volume benign FPs (e.g., Microsoft/OS updates)
| where not(RemoteUrl has_any ("microsoft.com", "windowsupdate.com", "azure.com"))
| summarize
    TotalBytesSent = sum(RemoteBytes),
    UniqueDestinations = dcount(RemoteUrl),
    FirstConnection = min(Timestamp),
    LastConnection = max(Timestamp),
    TopDestination = arg_max(RemoteBytes, RemoteUrl)
    by DeviceId, DeviceName, AccountName, InitiatingProcessFileName
// Set a threshold for review (e.g., > 500 MB sent in 24 hours, adjust based on baseline)
| where TotalBytesSent > 500000000
| project
    FirstConnection,
    LastConnection,
    DeviceName,
    AccountName,
    TotalBytesSent_GB = round(TotalBytesSent / 1000000000, 2),
    InitiatiConcluding Remarks: Mastering the Encrypted Channel Challenge
```
This playbook is highly valued because it addresses the single most critical challenge in modern network security: the blind spot created by ubiquitous encryption.

Behavioral Defense is Key: Emphasize that in the absence of content visibility, the only reliable defense is behavioral baselining. Your ability to establish a "normal" upload volume per user/process and alert on deviations is paramount.

The Power of the Precursor: Stress the strategic importance of the T1560 link. Linking a successful file staging event (archive creation) with a subsequent volume anomaly confirms the entire kill chain, transforming a noisy network alert into a confirmed intrusion.

Decryption is a Business Decision: Explain that while full SSL inspection is challenging, the IR process must include an attempt to utilize any existing decryption tools (like those in a forward proxy or DLP engine) to recover the payload.ngProcessFileName,
    UniqueDestinations,
    TopDestination
| order by TotalBytesSent desc
```

