# Incident Response Playbook – Signed Installer Post-Install C2 Behaviour

This playbook addresses a sophisticated attack pattern where the initial access mechanism is a file with a **valid digital signature** (e.g., a legitimate third-party installer, a supply-chain compromised binary, or a signed application that has been abused). The detection fires when this trusted executable, after installation or execution, initiates **Command and Control (C2)** communication (T1102.001) or other suspicious activity, typically leading to the download of a final payload.

**MITRE ATT&CK Tactic:** Command and Control (TA0011), Initial Access (TA0001), Defense Evasion (TA0005)
**Technique:** Trusted Relationship (T1199), Signed Binary Proxy Execution (T1218), Web Service (T1102.001)
**Critical Threat:** A trusted application’s security context and file signature have been abused, allowing the initial infection to bypass standard signature-based controls and application whitelisting, leading to immediate external communication.

---

## 1. L2 Analyst Actions (Initial Triage & Trust Verification)

The L2 analyst must immediately verify the status of the digital signature and the legitimacy of the network traffic.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the application is a newly deployed tool or recent update that requires external communication (e.g., activation, licensing checks). **Reject any communication going to a non-standard port or IP range not documented for the vendor.**
2.  **Signature Verification:** Review the file's digital signature in the EDR or forensics tool.
    * Is the signature **Valid and Trusted** (e.g., Microsoft, Google, known vendors)?
    * Does the file name, version, and location **match** what is expected for that vendor's product? (Watch for path hijacking or DLL side-loading where the main file is signed but supporting files are malicious).
3.  **Network Activity Analysis (MDE Focus):** Examine the suspicious network connection (`DeviceNetworkEvents`):
    * **Destination:** Is the target IP/domain known as a C2 infrastructure or newly registered? Is the destination geographically unexpected?
    * **Port/Protocol:** Is it using common beaconing ports (80/443) but with unusual byte patterns or HTTP headers (low, sporadic traffic)? Or is it using an unexpected protocol?
4.  **Process Context:** Identify the parent process that launched the signed binary. Was it launched from an unusual location (e.g., email attachment download folder, temp directory)?

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `DeviceName` / `DeviceId`
* `AccountName` / **`UPN`** (The user account running the signed application).
* **Time Range:** The $\pm1$ hour surrounding the C2 connection attempt.
* **Network Artifacts:** The **Signed Binary Path**, its **Digital Signature Details**, the **Destination IP/URL**, and the **Port/Protocol** used.
* **File Integrity:** The full path and hash of the signed binary.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **Signature is Valid, but the communication is to a known malicious C2 domain.** **Severity is Critical.**
* The communication is followed immediately by the **download and execution of an unsigned, unknown binary** (Stage 2 payload).
* The signed binary's execution leads to **process injection** or **credential dumping** attempts.
* The application is identified as part of a **supply-chain compromise** affecting multiple systems.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Trust Degradation)

The L3 analyst must determine if the signature is legitimate (compromised vendor) or if the file is simply being abused (LOLBIN). The focus is on the Stage 2 payload.

### 2.1 Full Attack Chain Reconstruction

1.  **Stage 2 Payload Recovery:** Identify and recover the file downloaded/executed immediately following the C2 connection. This file is typically the primary malware (RAT, ransomware, or loader).
2.  **Abuse Vector Analysis:** Determine the specific technique used:
    * **LOLBIN Abuse (T1218):** Was the signed binary a living-off-the-land tool (e.g., `Mshta.exe`, `Rundll32.exe`) used to execute a remote script?
    * **Supply Chain/Compromise:** Was the legitimate vendor's signing key stolen, or was their update mechanism poisoned?
3.  **Endpoint Activity Audit:** Review all activities on the host following the initial C2 beacon. Look for evidence of:
    * **Persistence:** Creation of Scheduled Tasks or Registry Run keys (Section 1.1, 1.2, 1.3 of those playbooks).
    * **Discovery:** Internal scanning, file enumeration, or credential access.
4.  **Lateral Movement Audit:** Check if the host was used to send phishing emails or deliver the compromised installer to other internal systems.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (Confirmed):** The signed binary acted as the Stage 1 loader for a malicious campaign.
    * **Misconfiguration / Risky Pattern (Low Probability):** An application trying to call home to a revoked or decommissioned domain.
2.  **Scope the Incident:** The scope includes **all hosts** that executed the suspicious signed binary, the **compromised application vendor** (if applicable), and all **Stage 2 IOCs** downloaded.

---

## 3. Containment – Recommended Actions (Targeted Isolation & Network Kill)

Containment must break the C2 channel and remove the malicious application and its payload.

1.  **Isolate Endpoint:** **MANDATORY** isolate the affected endpoint (`DeviceName`) using MDE.
2.  **Network Blockade:** **MANDATORY** Block the identified **Destination IP/URL** at the network perimeter (firewall, web proxy) and via **EDR Network Containment** policy to prevent any other compromised hosts from connecting.
3.  **Application Removal:** If the signed binary was an application installer, **uninstall the application** completely from the host.
4.  **Payload Quarantine:** Quarantine the **Stage 2 payload** (the file downloaded after the C2 connection) and block its hash organization-wide.
5.  **Prevent Future Execution:** Block the **hash of the malicious signed installer** itself. While the signature is valid, blocking the specific hash prevents future execution of this specific malicious instance.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must enforce stricter controls over network communication and trust policies for signed code.

1.  **Control Failure Analysis:** Identify which control failed: **Network Filtering** (failing to block beaconing traffic/suspicious domains), or **Application Control** (failing to enforce trust boundaries for signed binaries).
2.  **Propose and Track Improvements:**
    * **Signature Revocation Check:** Ensure all application whitelisting and EDR solutions perform **real-time Certificate Revocation List (CRL) checks** to identify signatures that have been revoked by the vendor/CA.
    * **ASR Deployment:** Implement **Attack Surface Reduction (ASR) rules** to block common abuse vectors, such as:
        * Block process creation originating from PSExec and WMI commands.
        * Block executable content from email client and webmail.
    * **Network Behavior Policy:** Deploy a security policy that alerts on or blocks any application from making network connections to domains or IPs that are not part of an approved baseline, even if the application is signed.
    * **Software Inventory:** Conduct a full inventory to identify the scope of the affected signed application across the environment, prioritize patching, or outright removal if the vendor cannot remediate the compromise.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, placing higher risk on software updates and third-party installers, and update playbooks to emphasize network flow analysis over simple file signature checks.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query hunts for execution of signed binaries followed immediately by an external network connection to a suspicious or unknown destination, a strong indicator of C2 beaconing.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Signed Binary Post-Install C2 Beaconing
DeviceProcessEvents
| where Timestamp > ago(7d)
// Look for processes that executed a file with a valid signature
| where IsSigned == true and IsExecutable == true
| project CreationTime=Timestamp, DeviceName, InitiatingProcessId=ProcessId, SignedFileName=FileName, Signature=InitiatingProcessSignature
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIP !in ("127.0.0.1", "::1") // Exclude localhost
    | where RemoteIP startswith "10." or RemoteIP startswith "172.16." or RemoteIP startswith "192.168." // Filter for external connections (assuming private IP ranges are internal)
    | project ConnectionTime=Timestamp, InitiatingProcessId, RemoteUrl, RemoteIP, Protocol, DestinationPort
) on InitiatingProcessId
| where ConnectionTime between (CreationTime .. CreationTime + 30s) // Connection must happen shortly after execution
| project CreationTime, ConnectionTime, DeviceName, SignedFileName, Signature, RemoteUrl, RemoteIP, Protocol, DestinationPort
| order by CreationTime desc

```
Concluding Remarks: The Blurring Line of Trust

This attack represents the highest level of trust abuse. The attacker is weaponizing your security tools' reliance on code signing. When a file is signed, your EDR is essentially saying, "I trust this." The moment that file starts beaconing C2 traffic, that trust is immediately invalidated.

Behavior Over Signature: Your primary detection mechanism must shift from simply checking the signature status to analyzing the behavior of the signed code. The what (C2 connection) overrides the who (trusted vendor).

The Stage 2 Pivot: The signed file is just the delivery mechanism. The immediate focus must be on recovering and analyzing the Stage 2 payload downloaded via the C2 channel, as this is the actual malicious tool the attacker intends to use for their final objective.

Collaboration with IT: If the vendor is genuinely compromised (supply chain attack), you must coordinate immediately with your IT team to pull the application from all endpoints and with your threat intel team to notify the vendor or the relevant CERT/security authority.
