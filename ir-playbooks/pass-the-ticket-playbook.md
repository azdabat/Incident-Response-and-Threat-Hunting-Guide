# Incident Response Playbook – Pass-the-Ticket / Kerberos Ticket Abuse (PtT)

This playbook addresses the compromise of identity via the **Pass-the-Ticket (PtT)** attack. This technique involves stealing or forging valid Kerberos tickets (Ticket Granting Tickets (TGTs) or Service Tickets (TGSs)) from memory (`lsass.exe`) and replaying them on the network to authenticate to services, often bypassing traditional password and MFA checks.

**MITRE ATT&CK Tactic:** Lateral Movement (TA0008), Credential Access (TA0006)
**Technique:** Use Alternate Authentication Material (T1550.003), OS Credential Dumping (T1003)
**Critical Threat:** Covert lateral movement and privilege escalation by impersonating an authenticated user session without needing the plaintext password or hash.

---

## 1. L2 Analyst Actions (Initial Triage & Ticket Anomaly Check)

The L2 analyst must validate the authentication chain, looking for evidence of ticket reuse originating from an unapproved process or host.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether any scheduled system maintenance, specific administrative scripts, or monitoring agents could explain the unexpected Kerberos service ticket (TGS) requests from the source machine.
2.  **Ticket Reuse Anomaly:** Identify an authentication event where the user is granted access to a resource (e.g., file share, remote desktop) using a **TGS that did not originate from a TGT recently requested by the user's current session**. The session is established without a recent interactive logon.
3.  **Precursor Check (Ticket Theft):** Immediately check the source machine (`DeviceName`) for events indicating **Credential Dumping (T1003)**, specifically memory read access to the `lsass.exe` process (often via `Mimikatz`, `Rubeus`, or similar tools).
4.  **Process and Cache Check:** Identify the process initiating the ticket replay. Check the local system's Kerberos ticket cache for unusual or expired tickets present on the filesystem or in memory.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for forensic preservation:

* `SourceDeviceName` / `SourceDeviceId` (Where the ticket was stolen).
* `TargetDeviceName` (Where the ticket was successfully replayed).
* `AccountName` / **`UPN`** (The compromised user whose ticket was used).
* **Time Range:** The $\pm1$ hour window spanning the ticket theft and the first successful PtT authentication.
* **Authentication Logs:** Raw Kerberos authentication logs showing the **Target Service Principal Name (SPN)** and the **ticket encryption type** (often unusual or weak encryption is used by forged tickets).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **Successful Kerberos authentication** using a ticket on a host where the user had no prior interactive logon. **Severity is High.**
* The compromised account (`AccountName`) is a **Tier 0/Administrator account** or a critical service account.
* The ticket allows access to a **Domain Controller** or other security-sensitive infrastructure (indicating a possible Golden/Silver Ticket scenario).
* Confirmed **`lsass.exe` memory access** on the source machine precedes the Kerberos authentication.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Ticket Invalidation)

The L3 analyst must pivot from detection to forensic confirmation of ticket forgery/theft and determine the necessary password reset scope.

### 2.1 Full Attack Chain Reconstruction

1.  **Theft Mechanism & Tooling:** Confirm the exact tool used (e.g., `Mimikatz` command line arguments, `Rubeus` arguments) and the mechanism of memory access to `lsass.exe`.
2.  **Ticket Type Analysis:** Determine which ticket was abused:
    * **Stolen TGS/TGT (Standard PtT):** Requires resetting the password for the **compromised user account**.
    * **Forged Silver Ticket:** Requires resetting the password for the **Service Account** associated with the target resource (SPN).
    * **Forged Golden Ticket:** Requires **double-resetting the `krbtgt` account password**, as this compromises the entire domain's key material.
3.  **Lateral Path Mapping:** Map the full sequence of servers and services accessed by replaying the ticket. This determines the full scope of resource compromise.
4.  **Persistence Review:** Check all machines in the lateral movement chain for evidence of **WMI persistence (T1546.003)** or **Service Creation (T1543.003)**, which can be created using the replayed ticket.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1550.003 Confirmed):** Unauthorized reuse or forging of authentication material.
2.  **Scope the Incident:** The scope includes the **source machine, all target services accessed**, and, in the case of a Golden Ticket, the **entire identity domain**.

---

## 3. Containment – Recommended Actions (Ticket Expiration & Credential Reset)

Containment must focus on breaking the attacker's ability to reuse the stolen or forged ticket, which requires specific Kerberos commands.

1.  **Isolate Source:** **MANDATORY** isolate the source machine (where the ticket was stolen) immediately.
2.  **Ticket Purge:** Run the **`klist purge`** command on the compromised user's session and the source machine to forcibly clear any live tickets from the cache.
3.  **Credential Invalidation:** **Force an immediate, complex password reset** for the compromised account (`AccountName / UPN`). If Golden Ticket is suspected, **double-reset the `krbtgt` password** (see DCSync playbook).
4.  **Service Ticket Reset:** If a Silver Ticket is suspected, reset the password for the specific service account associated with the forged Service Principal Name (SPN).
5.  **Session Kill:** Force a logoff or reboot on the source machine to ensure all in-memory tickets are flushed.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must secure the Kerberos key distribution system and limit the capability to steal tickets.

1.  **Control Failure Analysis:** Identify which control failed: **Credential Protection** (lack of Credential Guard/LSA protection), or **Kerberos Audit** (failing to track the TGT/TGS request chain).
2.  **Propose and Track Improvements:**
    * **Credential Guard Deployment:** Implement **Windows Defender Credential Guard** across all endpoints and servers to isolate the Kerberos key material stored in `LSASS`.
    * **LSA Protection:** Implement **Local Security Authority (LSA) protection** to prevent unauthorized processes from accessing `lsass.exe`.
    * **Tiered Access Enforcement:** Enforce the principle of **clean source** and **separate administrator accounts** to ensure privileged accounts are never used on lower-tier endpoints where they can be compromised.
    * **Group Managed Service Accounts (gMSA):** Migrate all traditional Service Accounts to gMSA to automatically manage complex passwords and reduce the risk of Silver Ticket attacks.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that PtT attacks are often used **after** PtH failed or to achieve greater stealth by abusing the Kerberos trusted framework.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query links the primary event (LSASS access) with the evidence of successful Kerberos authentication on the network (TGS or TGT replay).

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for Pass-the-Ticket (PtT) Activity Chain
let LSAccess = DeviceProcessEvents
| where ActionType == "ProcessAccessed" and TargetFileName =~ "lsass.exe"
| where InitiatingProcessFileName has_any ('mimikatz.exe', 'rubeus.exe', 'kekeo.exe', 'powershell.exe')
| project DumpTime=Timestamp, SourceDevice=DeviceName, AccountName=InitiatingProcessAccountName;
LSAccess
| join kind=inner (
    DeviceLogonEvents
    | where Protocol == "Kerberos" and LogonType == "Network"
    | project LogonTime=Timestamp, TargetDevice=DeviceName, TargetIP=RemoteIP, AccountName
) on AccountName
| where LogonTime between (DumpTime .. DumpTime + 30m)
| project DumpTime, LogonTime, AccountName, SourceDevice, TargetDevice, TargetIP | order by DumpTime asc

```
Concluding Remarks: The Ultimate Identity Stealth Attack:

The Pass-the-Ticket attack is the ultimate stealth attack in an Active Directory environment. By reusing a valid ticket, the attacker generates zero password failures and often bypasses MFA entirely, appearing to all systems as a legitimate, already authenticated user.

Tickets are Gold: Treat every Kerberos ticket stored in memory, especially TGTs, as if it were the user's plaintext password. The fact that the attacker could steal it is the security failure.

The krbtgt Question: If the compromised user is high-value, you must immediately pivot to the Golden Ticket assumption. This forces the double-password reset on krbtgt, which is the only reliable way to break the trust chain an attacker has forged.

Defense by Sealing Memory: Your remediation focus should be on denying the theft (Credential Guard), not just detecting the replay. A successful PtT incident means the detection controls have already failed, and the attacker is moving freely.
