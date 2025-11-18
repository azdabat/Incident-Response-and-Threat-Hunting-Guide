#  SOC Investigation Spine: NTDS.dit Replication / DCSync-like Attack

**Objective:** Anchor the investigation on the detection event (DCSync activity) and trace the activity backwards (Initial Access) and forwards (Impact) using security telemetry, focusing on the NTDS.dit theft.

##  Phase 1: Detection Anchor (NTDS.dit Replication / DCSync)

This phase identifies the key event where credentials for the entire domain were compromised.

| Data Source | Investigation Artifacts (IOC Type) | Analyst Action / Query |
| :--- | :--- | :--- |
| **Domain Controller (DC) Event Logs** | **Event ID 4662** (Access to an object), specifically querying the **Directory Replication Service (DRS) APIs**. | Filter for `Replicating Changes` or `Get Changes All` operations (`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`) initiated by a **non-DC machine or account**. |
| **Identity/Account Logs** | The use of an account with **Replicating Directory Changes** permissions (e.g., Administrator, or a service account) from an **unusual source IP**. | Check access requests from non-DC servers for the **NTDS object** using protocols like **RPC** (TCP/135 or 49152-65535). |
| **Network Logs** | **Outbound RPC calls** from a non-DC machine to a Domain Controller on ports like **TCP/135** or high dynamic ports, followed by a large data transfer. | Look for an unexpected high volume of data flowing between a client and a DC, indicative of the NTDS.dit being replicated. |

---

## 🔍 Phase 2: Walking Backwards (Initial Access / Execution)

This phase determines how the attacker obtained the privileges needed to execute the DCSync.

| Data Source | Investigation Artifacts (IOC Type) | Analyst Action / Query |
| :--- | :--- | :--- |
| **Initial Access / Endpoint Logs** | Evidence of **Local Administrator credential harvesting** (e.g., use of tools like **Mimikatz** or **LaZagne**). | Search for process execution events for known hacking tools, especially those dumping credentials from memory (`lsass.exe` access). |
| **Lateral Movement (Pre-DCSync)** | The initial **compromise of a privileged account** (e.g., a tier 1 or tier 0 administrator). | Trace the login history of the account used for the DCSync back to its first successful login from an unexpected source. |
| **Network Data (C2)** | Connection from the compromised machine to an **external C2 IP address/domain** (e.g., `generic_c2_domain[.]com`). | Review DNS/Proxy logs for connection attempts to non-sanctioned domains right before the DCSync execution. |

---

## 🏃 Phase 3: Walking Forwards (Lateral Movement / Persistence / Staging)

This phase tracks the use of the stolen NTLM hashes (from NTDS.dit) for post-compromise activity.

| Data Source | Investigation Artifacts (IOC Type) | Analyst Action / Query |
| :--- | :--- | :--- |
| **Identity/Authentication Logs** | **Pass-the-Hash (PtH)** or **Golden Ticket** attacks using the stolen credentials. | Look for login events where the **authentication method is NTLM/Kerberos** but no preceding password attempt was made (PtH). Search for abnormal **Kerberos Ticket Granting Ticket (TGT)** requests (Golden Ticket). |
| **Persistence Mechanisms** | Creation of **new service
