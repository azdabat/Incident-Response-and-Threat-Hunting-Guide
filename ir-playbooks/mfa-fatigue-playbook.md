# Incident Response Playbook – MFA Fatigue / Push Spamming (T1621)

This playbook addresses the highly effective Identity-based attack known as **MFA Fatigue** (T1621), where an attacker, having already stolen primary credentials, repeatedly spam the victim's device with MFA push notifications until the victim accepts out of annoyance or confusion. This indicates a successful initial password compromise and active exploitation of the human factor.

**MITRE ATT&CK Tactic:** Credential Access (TA0006), Initial Access (TA0001)
**Technique:** Multi-factor Authentication Request Generation (T1621)
**Critical Threat:** Bypassing the primary security control (MFA) to gain verified access to cloud or network resources, leading to immediate post-access activity.

---

## 1. L2 Analyst Actions (Initial Triage & User Confirmation)

The L2 analyst must immediately validate the alert with the user and halt the authentication attempts to prevent accidental access.

### 1.1 Triage and Validation Steps

1.  **Immediate User Contact:** Contact the user (`AccountName / UPN`) via a secure, out-of-band channel (e.g., internal chat, direct phone call) to confirm if they are currently initiating any sign-in requests.
2.  **Anomaly Confirmation:** Validate the detection is triggering on a high frequency of failed/denied MFA push requests (e.g., 5-10 requests within a 5-minute window).
3.  **Source IP Analysis:** Identify the source external IP address attempting the sign-in. Perform a quick geolocation and WHOIS lookup. Is the IP associated with a known VPN, proxy, or high-risk geo-location?
4.  **Credential Health Check:** Check the user's account for precursor alerts: Phishing link clicks, credential dumping on their endpoint, or password change failures, which would explain the password compromise.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for documentation and L3 handover:

* `DeviceName` / `DeviceId` (If the user's primary endpoint is involved).
* `AccountName` / **`UPN`**
* **Time Range:** The $\pm1$ hour surrounding the MFA spamming activity.
* **Authentication Logs:** The raw log entries showing the time, source IP, application requested, and the status of each MFA attempt (e.g., `MFA_Push_Denied`, `MFA_Challenge`).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** instance where the user confirmed they were *not* initiating the login requests. **Severity is High.**
* The spamming activity results in a single, successful MFA approval (T1621 success). **This is an active intrusion.**
* The source IP address is geographically distant from the user's typical login location or is associated with a known malicious infrastructure.
* The target application is a sensitive cloud service (e.g., Email, SharePoint Admin, or ERP).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Access Interruption)

The L3 analyst focuses on dismantling the attacker's access vector, confirming the extent of credential compromise, and establishing if post-access activity occurred.

### 2.1 Full Attack Chain Reconstruction

1.  **Precursor Analysis:** Confirm the method used to obtain the initial password:
    * **Phishing/Vishing:** Did the user interact with a credential harvesting page or divulge the password over the phone?
    * **Endpoint Compromise:** Was the password scraped via a keylogger or memory dump on the endpoint?
2.  **Source IP Patterning:** Analyze the attacker's source IP(s) and User Agent strings. Are they rapidly changing IPs (typical of residential proxy services) or are they consistent?
3.  **Post-Access Audit (If successful):** If the MFA was approved, immediately audit the entire authenticated session for:
    * **Session Token Theft (T1539):** Did the attacker immediately attempt to export or persist the session token?
    * **Email Exfiltration (T1041):** Was the first action creating forwarding rules or accessing sensitive files?
    * **New Persistence:** Did the attacker register a new MFA device or create a new service principal?

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1621 Confirmed):** Successful MFA bypass (if approved) or high-risk attempt (if denied/failed).
2.  **Scope the Incident:** Determine the **total number of identities** whose passwords were stolen, even if MFA attempts were not initiated. Confirm if the attack was targeted or part of a wider campaign against the organization.

---

## 3. Containment – Recommended Actions (Identity Lockdown)

Containment must focus on immediate revocation of the stolen password and halting the MFA attack vector.

1.  **Stop Attack and Lock Account:** Immediately **lock the user's account** in the identity provider (e.g., Azure AD) to prevent further attempts.
2.  **Mandatory Password Reset:** Force a **password reset** for the compromised user, ensuring the new password adheres to modern complexity standards.
3.  **MFA Hardening:** For the affected user, temporarily **disable the Push/Approve notification method** and enforce the use of **TOTP (Time-based One-Time Password) codes** or **Security Keys (FIDO2)** only.
4.  **Credential Revocation:** **Revoke all existing refresh tokens and session cookies** for the affected user to terminate any currently active attacker session.
5.  **Source Blocking:** Block the attacker's source IP(s) and associated User Agents at the network perimeter and the identity provider's Conditional Access policies.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must shift the organizational MFA strategy from simple push notifications to more robust, less vulnerable methods.

1.  **Control Failure Analysis:** Identify which control failed: **Email/Phishing Filter** (allowing the password theft), or **MFA Configuration** (allowing push notifications without number matching).
2.  **Propose and Track Improvements:**
    * **MFA Method Upgrade:** Implement a global policy requiring **MFA Number Matching** or **Contextual Data** display for all push notifications to defeat simple approvals.
    * **Conditional Access:** Implement or refine risk-based Conditional Access policies to automatically **block sign-ins** originating from high-risk countries or proxy services.
    * **Automated Remediation:** Implement security automation to automatically **suspend or block** an account after a threshold of failed/denied MFA attempts (e.g., 5 attempts in 5 minutes).
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that MFA Push Spamming is a social engineering technique that bypasses technical controls. Launch immediate, targeted training for all employees on this specific attack vector.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query is designed to flag the specific volumetric anomaly of failed/denied MFA push requests from a single user or IP address, which is the signature of a fatigue attack.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for MFA Fatigue Spike (T1621)
IdentityLogs
| where EventType in ('MFA_Push_Denied', 'MFA_Push_Challenge')
| summarize Attempts=count(), First=min(Timestamp), Last=max(Timestamp) by AccountUpn, SourceIp
| where Attempts > 10 and Last - First < 10m
| project Time=Last, AccountUpn, SourceIp, Attempts, Duration=Last-First
| order by Attempts desc
```

Concluding Remarks: Countering Human-Centric Identity Attacks:

This playbook is highly critical because it deals with a sophisticated attack that targets the human element rather than a system vulnerability. Successful containment relies heavily on the SOC's speed and ability to execute out-of-band communication with the victim.

The Race Against Fatigue: Every second the attacker is spamming the user increases the risk of an accidental approval. The SOC's primary goal is to lock the account and kill the attacker's login flow before the user is worn down.

Engineering Out the Weakness:  permanent remediation requires implementing Number Matching. Simple push/approve notifications are now considered legacy and highly vulnerable to this exact attack pattern.

Validation is Key: focus as L2 Analyst's secure, out-of-band contact with the user is the single most important step. Without user confirmation, the entire incident response is conducted blind, wasting critical time.
