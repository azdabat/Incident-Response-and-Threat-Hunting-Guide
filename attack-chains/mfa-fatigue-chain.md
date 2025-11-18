# 🛡️ SOC Investigation Spine: MFA Fatigue / Push Spamming

**Objective:** Anchor the investigation on the detection event (MFA Fatigue) and trace the activity backwards (Initial Access) and forwards (Impact) using security telemetry.

## 🚨 Phase 1: Detection Anchor (MFA Fatigue / Push Spamming)

This phase identifies the direct evidence of the attack itself.

| Data Source | Investigation Artifacts | Analyst Action / Query |
| :--- | :--- | :--- |
| **Identity/MFA Logs** | Excessive **failed/denied** MFA push notifications (e.g., >5 attempts in 3 minutes). | Filter by user ID and time window for high-frequency failures. |
| **Authentication Logs** | A **successful MFA approval** immediately following the high-frequency failure/denial pattern. | Correlate the successful MFA event with the source IP and sign-in location. |
| **Network/VPN Logs** | Successful login from a **new, suspicious, or geo-unusual** IP address. | Compare the source IP address against the user's historical login data. |

---

## 🔍 Phase 2: Walking Backwards (Initial Access / Execution)

This phase determines how the attacker obtained the initial credential.

| Data Source | Investigation Artifacts | Analyst Action / Query |
| :--- | :--- | :--- |
| **Email/Phishing Logs** | Evidence of a **successful credential harvesting link click** or **malicious attachment download**. | Search user's email history for known phishing email subjects or sender addresses leading up to the attack. |
| **EDR/Endpoint Logs** | Execution of **credential dumping tools** (e.g., Mimikatz) or registry queries for stored credentials. | Search for process execution events for suspicious command-line strings or file writes in temporary folders. |
| **Security Awareness** | **User Interview:** Confirm the user was receiving unexpected pushes and if they approved any of them. | Document the user's experience and timeline of events. |

---

## 🏃 Phase 3: Walking Forwards (Lateral Movement / Persistence / Staging)

This phase determines what the attacker did *after* gaining unauthorized access.

| Data Source | Investigation Artifacts | Analyst Action / Query |
| :--- | :--- | :--- |
| **Identity/Directory Logs** | Creation of **new user accounts** or **unauthorized changes** to the compromised account (e.g., adding a secondary MFA method, role assignment). | Review audit logs for *Add-MfaMethod* or *Set-UserPrincipalName* events by the compromised user. |
| **File Access Logs (Cloud/Share)** | **Mass downloads**, synchronization, or access of highly sensitive files (e.g., finance, HR data). | Track API calls for *DownloadFile* or *SyncOperation* to identify staging for exfiltration. |
| **Network Traffic** | Large, **outbound data transfers** (exceeding baseline) to untrusted cloud storage or VPN/proxy connections. | Analyze firewall logs for high-volume traffic to known malicious or suspicious destinations. |

---

## 💥 Phase 4: Impact and Containment

This is the final result of the attack and the immediate response required.

| Impact Category | Artifacts | Containment and Remediation |
| :--- | :--- | :--- |
| **Impact (Account Takeover)** | Successful sign-in from the malicious IP; high-risk actions performed by the compromised user. | **Immediate Password Reset** and **Revoke All Sessions/Tokens**. Block the malicious source IP. |
| **Impact (Exfiltration)** | Presence of data staged for transfer or evidence of successful outbound data transfer. | **Quarantine** the affected endpoint; **restore** files from a clean backup; inform legal/data protection teams. |
| **Mitigation** | Weak MFA policy (e.g., push only). | **Enforce MFA Number Matching**, conditional access policies (Geo-blocking), and stronger authentication methods (e.g., FIDO2 keys). |
