# Incident Response Playbook – OAuth Consent Abuse (Native Logs)

This playbook addresses the compromise of identity by leveraging the OAuth authorization framework. An attacker registers a malicious third-party application and convinces a user to click a phishing link, granting the app broad permissions (e.g., `Mail.Read`, `Files.ReadWrite`). This bypasses session limits and MFA, enabling data exfiltration via API calls.

**MITRE ATT&CK Tactic:** Persistence (TA0003), Defense Evasion (TA0005)
**Technique:** Cloud Service Dashboards (T1526), Account Manipulation (T1098), Access Token Manipulation (T1539)
**Critical Threat:** A persistent, non-session-based backdoor that grants the attacker continuous, direct API access to cloud resources (e.g., Exchange Online, SharePoint, OneDrive).

---

## 1. L2 Analyst Actions (Initial Triage & Permission Review)

The L2 analyst must immediately identify the malicious application and the permissions it was granted, recognizing that the user's password is often already compromised.

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether the application registration (`AppId`) is a known, approved, or internal corporate application. **Reject generic utility applications.**
2.  **Consent Source:** Check the authentication logs to confirm the **user consented** to the application. Note the **Source IP** and **User Agent** used during the consent event (this may indicate the phishing vector).
3.  **Permission Scope Check:** Identify the **exact permissions** granted. The highest severity includes read/write permissions to sensitive services:
    * `Mail.ReadWrite`, `Mail.Send` (Email access)
    * `Files.ReadWrite.All` (Cloud storage access)
    * `Directory.ReadWrite.All` (Identity manipulation)
4.  **User Contact:** Contact the user (`AccountName / UPN`) via a secure, out-of-band channel. Ask if they recently authorized a new cloud application or clicked a link to log into a non-standard site.

### 1.2 Minimal Triage Data Collection

Collect the following minimal set of data for documentation and L3 handover:

* `AccountName` / **`UPN`** (The compromised user).
* **Application Details:** The malicious **`App ID`**, **`App Name`**, and the **`Publisher`** (if available).
* **Permissions Granted:** The full list of OAuth scopes granted by the user.
* **Time Range:** The $\pm24$ hours surrounding the consent event and any subsequent application activity.

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* **ANY** user consent granting **ReadWrite** access to high-value resources (Email, Files, Directory). **Severity is High.**
* The compromised user is **sensitive** (privileged administrator, executive, or finance staff).
* Application activity logs show **API calls** immediately following consent (e.g., reading mail, creating forwarding rules).
* The **Publisher name** is suspicious, newly created, or mimics a legitimate brand.

---

## 2. L3 Analyst Actions (Technical Deep Dive & API Activity Audit)

The L3 analyst must assume the attacker has full programmatic access to the user's data and prioritize access token revocation and activity auditing.

### 2.1 Full Attack Chain Reconstruction

1.  **Token Usage Audit:** Audit the **Cloud Service Provider (CSP) Logs** (e.g., Exchange Audit, SharePoint Audit) filtering by the **malicious `App ID`** to determine what data was accessed, read, or modified *after* the consent event.
    * **Email:** Did the application create email forwarding rules (T1114.003)? Did it search for specific keywords (e.g., "password," "invoice")?
    * **Files:** Did the application read files from OneDrive or SharePoint? Were files aggregated or staged (T1560)?
2.  **Persistence Analysis:** Confirm if the attacker attempted to use the access to create **secondary persistence**, such as adding a new administrator to an Office 365 group or modifying a Conditional Access policy.
3.  **Initial Access Vector:** Determine the exact phishing method used (e.g., a "Sign in with Google" pop-up clone, Vishing, or a malicious link in a chat).

### 2.2 Classification and Scoping

1.  **Activity Classification:**
    * **Malicious Intrusion (T1526 Confirmed):** Unauthorized, persistent access token granted to a malicious application.
2.  **Scope the Incident:** The scope includes the **compromised user's entire cloud environment**. Determine the sensitivity and volume of data accessed by the malicious application.

---

## 3. Containment – Recommended Actions (Application and Token Revocation)

Containment must focus on breaking the App-to-API connection immediately. Endpoint isolation is secondary, as the attack is identity-based, not host-based.

1.  **Application Revocation (Primary):** **Immediately revoke the OAuth token** by removing the malicious application's service principal consent from the compromised user's account.
2.  **App Blocking (Secondary):** In the cloud identity provider, set up a **Conditional Access Policy** to prevent **all future access** by that specific **`App ID`**, or delete the malicious Enterprise Application/Service Principal entirely.
3.  **Credential Health:** Force a **password reset** and **revoke all existing sessions/tokens** for the compromised user, as the password was likely stolen as part of the initial attack.
4.  **User Education:** Brief the user on the malicious application and the risks of granting third-party consent.

---

## 4. Remediation & Hardening – Strategic Improvements

Remediation must shift governance to prevent users from granting risky permissions to untrusted applications.

1.  **Control Failure Analysis:** Identify which control failed: **Email Filtering** (allowing the phishing link), **User Training** (leading to consent), or **App Governance** (allowing non-approved third-party consent).
2.  **Propose and Track Improvements:**
    * **User Consent Restriction:** Implement a global policy restricting **all non-admin users** from consenting to any application that requires **high-risk permissions** (e.g., ReadWrite on mail/files). Require administrative approval for these scopes.
    * **Automated Governance:** Implement an automated workflow to alert and review **newly created application registrations** and those requesting broad permissions.
    * **App Visibility:** Use cloud governance tools to maintain an inventory of all existing, high-privilege applications and audit their activity regularly.
    * **FIDO Keys:** Ensure **FIDO2 security keys** are used for all company devices and privileged accounts. These tokens are resistant to most phishing and session token theft attacks.
3.  **Documentation and Knowledge Transfer:** Update the Threat Model, emphasizing that OAuth Abuse is a form of persistent, API-level access that bypasses traditional network defense and requires cloud-native log analysis.

---

## 5. Threat Hunting Queries (KQL Focus)

This KQL query targets the log events that capture user consent for new applications, specifically filtering for applications with a low usage history or those requesting high-risk scopes.

### 5.1 Hunting Query Example (KQL Only)

```kql
// KQL Query for OAuth Consent to New or High-Risk Apps (T1526)
AuditLogs
| where OperationName == 'Consent to application' and Result == 'Success'
| extend GrantedScopes=tostring(InitiatedBy.AdditionalDetails)
| where GrantedScopes has_any ('ReadWrite', 'Directory.Read.All', 'Mail.Send')
| summarize Count=count() by InitiatingUser=AadResource.ResourceName, AppId=TargetResources[0].Id, AppName=TargetResources[0].DisplayName, GrantedScopes
| project Time=datetime_add('hour', 0, now()), InitiatingUser, AppId, AppName, GrantedScopes, Count
| order by Time desc
```
Concluding Remarks: Mastering the Cloud Identity Backdoor:

You're dealing with a modern persistence vector that is often more dangerous than a simple malware implant. Why? Because the attacker gains direct API access, completely bypassing your host-based EDR, your network firewalls, and any session timeouts.

It’s Not a Password Problem: The password may be compromised, but the true failure is the lack of strict Application Governance. The attacker is using an entirely separate pathway into your data—the OAuth token—that is often overlooked.

Focus on the App ID: The malicious application's unique ID is your only truly reliable Indicator of Compromise. Once you have it, you can audit all its past actions and implement a permanent block.

The New Normal: Accept that users will occasionally click phishing links. Your job is to ensure that when they do, your Conditional Access and Consent Policies prevent them from handing over the keys to the entire organization. The only way to win this fight is to restrict default user consent permissions.
