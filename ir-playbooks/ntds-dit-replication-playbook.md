# Incident Response Playbook – NTDS.dit Replication / DCSync-like (T1003.006)

This playbook addresses the most severe identity-based attack against Active Directory: the abuse of the **Directory Replication Service (DRS) Remote Protocol** (DCSync) to steal the `NTDS.dit` database contents, including all password hashes. This indicates the attacker has successfully compromised an account with high-level replication privileges.

**MITRE ATT&CK Tactic:** Credential Access (TA0006), Discovery (TA0007)
**Technique:** OS Credential Dumping (T1003.006), Domain Replication Service (T1003.006)
**Critical Threat:** Complete compromise of all domain user and service account credentials, leading to immediate Golden Ticket creation and full domain control.

---

## 1. L2 Analyst Actions (Initial Triage & Privilege Check)

The L2 analyst must immediately confirm the process and the account privileges, as this alert signals a critical security breach of the Identity Layer.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Strictly verify if the activity correlates with any scheduled, approved *Domain Controller (DC) synchronization* or AD maintenance jobs. **Reject non-DC sources.**
2.  **Source/Destination Validation:** Confirm the source device (`DeviceName`) is **NOT** a Domain Controller, but the destination device (`RemoteIP`) **IS** a Domain Controller.
3.  **Process Context:** Identify the process initiating the request. **Suspicious indicators:** `powershell.exe`, `cmd.exe`, or any non-system process communicating on the DRS ports (RPC 135, 5722, or high ports 49152-65535).
4.  **Account Privilege Check:** Immediately identify the **`AccountName / UPN`** used. Check if this account possesses the necessary permissions for DCSync (e.g., *Replicating Directory Changes* or *Replicating Directory Changes All*).

### 1.2 Minimal Triage Data Collection (Criticality: Extreme)

Since all credentials may be compromised, priority must be placed on external log capture and immediate account lockdown.

* `DeviceName` / `DeviceId` (The attacking source machine).
* `AccountName` / **`UPN`** (The compromised identity used for replication).
* **Time Range:** The $\pm1$ hour surrounding the detection.
* **Network Flow:** The total volume of data transferred (NTDS.dit is large, often 100MB+).
* **Process Snapshot:** Hash and full command line of the process initiating the request.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** confirmed non-DC device communicating with a DC on the DRS ports using a non-standard process. **Severity is Critical/Highest.**
* The compromised account is a **Service Account** or a **Tier 0/Administrator account**.
* A large volume of data was transferred from the DC (confirming hash extraction success).
* Precursor alerts confirm **privilege escalation** on the source machine.

---

## 2. L3 Analyst Actions (Technical Deep Dive & Domain Integrity)

The L3 analyst must assume a full domain compromise and focus on credential invalidation and persistence identification.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Vector:** Determine how the attacker compromised the initial endpoint and gained the necessary privileges to impersonate an account capable of DCSync.
2.  **Post-DCSync Persistence:** Assume the attacker now has the `krbtgt` hash (Golden Ticket capability). Check for evidence of:
    * **New Administrative Account Creation (T1136):** A new, obscure administrator account created immediately after the DCSync event.
    * **Service Ticket Abuse (T1558):** Signs of forged or replayed Kerberos tickets.
3.  **Compromise Validation:** Verify the contents of the stolen hashes by analyzing the data volume transferred. Check if the compromised user account was immediately disabled or removed by the attacker to conceal their initial foothold.
4.  **Lateral Movement Check:** Audit the source machine for evidence of post-DCSync activity, such as connection attempts to other domain controllers or high-value servers using the newly stolen credentials.

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1003.006 Confirmed):** Full Domain Credential Compromise.
2.  **Scope the Incident:** The scope is effectively the **entire identity domain**. Any account that has not changed its password since the DCSync event is compromised.

---

## 3. Containment – Recommended Actions (Maximum Domain Lockdown)

Containment must be immediate and severe, focusing on breaking the attacker's ability to use the stolen hashes.

1.  **Isolate Source:** **MANDATORY** isolate the source endpoint (`DeviceName`) immediately.
2.  **Compromised Account Lockdown:** **Immediately disable or force the complex password reset** on the compromised `AccountName / UPN`.
3.  **Krbtgt Key Reset (Critical):** This is the highest priority containment step. The **`krbtgt` account password must be reset twice** (allowing time for one replication cycle between resets) to invalidate any potential Golden Tickets created by the attacker.
4.  **Tier 0 Service Review:** Audit all accounts with *Replicating Directory Changes* permission and temporarily suspend any unnecessary Service Accounts in that Tier 0 group.
5.  **Firewall Hardening:** Temporarily block all non-DC traffic on RPC ports (135, 5722, 49152-65535) destined for Domain Controllers until the threat is confirmed mitigated.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must focus on eliminating the attack vector by strictly enforcing the Principle of Least Privilege in the Active Directory structure.

1.  **Control Failure Analysis:** Identify which control failed: **Identity Governance** (granting excessive replication permissions to a low-tier account), **Endpoint Security** (allowing initial compromise), or **Network Filtering** (failing to block non-DC traffic on high-value ports).
2.  **Propose and Track Improvements:**
    * **Tiered Access Model Enforcement:** Implement a rigorous **Tier 0, Tier 1, Tier 2** access model, ensuring only **dedicated, secure Domain Administrator accounts** have the necessary replication permissions.
    * **Audit and Remove Permissions:** Conduct a domain-wide audit to remove the `Replicating Directory Changes` permission from all user and service accounts that do not strictly require it (this includes default administrator groups).
    * **Advanced Endpoint Hardening:** Deploy EDR capabilities to hook or explicitly block `lsass.exe` and related processes from making unauthorized DRS API calls.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that the focus must shift from *detecting* the DCSync to *preventing* the initial compromise and privilege escalation that enables it.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query is designed to flag non-DC machines attempting to communicate on the Domain Replication Service ports (RPC endpoint mapper and RPC high ports).

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for DCSync-like Behavior (DRSR Protocol Abuse)
DeviceNetworkEvents
| where RemotePort in (135, 5722) or (RemotePort > 49151 and RemotePort < 65536)
| where InitiatingProcessFileName has_any ('powershell.exe', 'cmd.exe', 'ntdsutil.exe', 'kekeo.exe') or (InitiatingProcessFileName == 'lsass.exe' and RemoteBytes > 100000000)
| where RemoteUrl has_any ('ldap', 'drs')
| summarize Start=min(Timestamp), End=max(Timestamp), Volume=sum(RemoteBytes) by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| project Start, DeviceName, SourceProcess=InitiatingProcessFileName, RemoteIP, RemotePort, Volume_MB=round(Volume/1048576, 2), Duration=End-Start | order by Start asc
```
Concluding Remarks: Mission Criticality for SOC AnalystsL

You are responding to a Category 5 Identity Hurricane. This is not a drill. A successful DCSync attack means the adversary has bypassed all your perimeter and endpoint defenses and now holds the keys to the kingdom.

Your Time is the Only Constraint: Forget about saving logs on the local host. Your only priority is containment. You must act within minutes, not hours.

The Krbtgt Double Reset is Non-Negotiable: Do not skip the step of resetting the krbtgt password twice. This is the only way to invalidate a Golden Ticket, which is the ultimate persistence mechanism of this attack. If you only reset it once, the attacker can still forge tickets using the old key for one replication cycle.

Tier 0 is Compromised: Assume any administrative account or service account that had replication permissions has been compromised, even if the logs don't show it. The attacker is likely using the stolen hashes to forge Kerberos tickets silently. Your subsequent investigation must pivot to Tiered Access Model enforcement to ensure this vulnerability never exists again.
