# 🔑 OAuth Consent Abuse (Native Logs) – T1527: Compromise Infrastructure

**Explanation:** This playbook analyzes a cloud-native attack where an adversary tricks a user into granting high-privilege permissions (Consent) to an attacker-controlled OAuth application. This technique creates a long-lasting, off-network persistence mechanism, allowing the attacker to access resources (Mail, Files) via an Access Token without ever needing the user's password again. The most reliable **Anchor Point** is the security event log showing the **malicious application consent** and the **high-risk permissions** granted.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Command / Key Event in Logs |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.002 (Spearphishing Link) | **Email/Network:** User receives and clicks a link directing them to the malicious authorization URI. | *(User receives email link:)* `https://generic-attack-url[.]com/authorize` |
| **Execution/Redirection** | T1547.014 (OAuth Token) | **Network:** The attacker's server successfully redirects the user to the legitimate identity provider (IDP) consent page. | *(IDP Log Event:)* `ApplicationAccessRequest` from Suspicious URI. |
| **Consent Abuse (ANCHOR)**| **T1527 (Consent Compromise)** | **Identity/App Audit:** A user successfully grants consent to an application with a suspicious `App ID` or `Publisher` and requesting excessive scopes. | **Event: `Add application access`** or **`Consent to application`** (Success). |
| **Staging/Persistence** | T1098.006 (Account Access Addition) | **App Audit/Mail Logs:** The attacker uses the token to set up persistence, such as creating an external forwarding rule in the mailbox. | *(API Call by App ID:)* `New-MailboxTransportRule -ForwardTo external-email[.]com` |
| **Impact / Exfiltration** | T1041 (Exfiltration Over C2 Channel) | **Cloud API:** The malicious application makes rapid, high-volume calls to file read/download APIs, then transfers data off-network. | *(API Call by App ID:)* `Files.ReadWrite.All - Get-File /data/Sensitive_Files` |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Identity & Application IOCs

1.  **Consent Event Flag:** The highest-fidelity IOC is the **`Consent to application`** or **`Add application access`** event in the cloud audit logs. Investigate this event for the following red flags:
    * **Application ID:** Is it a known/approved application? If not, the ID is a critical IOC.
    * **Publisher:** Is the publisher unknown, generic (e.g., "Dev"), or a random string?
    * **Requested Scopes:** Did the user grant high-risk permissions like `Mail.ReadWrite.All`, `Files.Read.All`, or any scope with `.All`?
2.  **App Token Usage:** Immediately after the consent event, check the audit logs for API calls initiated by the **Application ID** (not the User ID). Look for rapid, high-volume activity inconsistent with normal use (e.g., 100+ file listings in 5 minutes).
3.  **Authentication Anomaly:** The OAuth token may be used by the attacker from a geographically unusual or suspicious IP address without any corresponding password attempt.

### File, Network, and Remediation IOCs

1.  **Mail Artifacts (Persistence):** After consent, check the victim's mailbox for **newly created Inbox Rules** that auto-forward emails to an external attacker-controlled address. This is a common post-consent persistence mechanism.
2.  **File Staging/Archive:** Look for the App ID creating **compressed files** (e.g., ZIP/RAR) within the user's cloud drive, indicating staging for mass exfiltration.
3.  **Remediation (Critical Action):** The critical containment step is to **Revoke the Access Token** and **Disable/Block the Malicious Application ID** globally within the tenant. The successful revocation of the token is a remediation IOC.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Consent Policy** | **Restrict User Consent:** Limit user ability to grant consent only to applications from **verified publishers** or apps explicitly configured by the organization. | Change global policy to **"Do not allow user consent."** Manually vet and approve all third-party apps. |
| **Vetting** | **Application Block List:** Proactively identify and block applications that request excessive (over-privileged) permissions. | Immediately add the malicious `App ID` to the tenant's **Block List** to prevent future consent. |
| **Detection** | **Conditional Access Policy:** Require **Multi-Factor Authentication** even for low-privileged apps or block access from high-risk locations. | Configure alerts for *any* application requesting **`.All` scopes** (e.g., `User.Read.All`). |
