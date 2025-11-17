# Incident Response Playbook – Cloud Admin Role Drift / Escalation (T1098, T1078)

This playbook addresses high-priority alerts signaling unauthorized changes to cloud roles, privilege escalation, or lateral movement within the Identity and Access Management (IAM) plane. This often involves abuse of valid accounts or compromised keys.

**MITRE ATT&CK Tactic:** Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005)
**Technique:** Account Manipulation (T1098), Valid Accounts (T1078), Modify Cloud Compute Infrastructure (T1578.004)
**Cloud Focus:** Abuse of IAM Roles, Service Principals, or Conditional Access Policies (CAPs).

---

## 1. L2 Analyst Actions (Initial Triage & Role Scoping)

The L2 analyst must validate the alert and determine the nature of the privilege manipulation (Role Assignment, Policy Modification, or Session Hijack).

### 1.1 Triage and Validation Steps

1.  **Change Validation:** Confirm whether a documented, approved change request (CR) or automated process (e.g., CI/CD pipeline, PIM/JIT activation) explains the role modification or sensitive API call.
2.  **Identity Context:** Determine the **source identity** (`AccountName` / `UPN` / `ServicePrincipalName`) and the **identity type** (Human User, Service Account, or Federated Identity).
3.  **Role/Action Review:** Identify the exact **role name** that was assigned/modified (e.g., `Owner`, `Global Administrator`, `Storage Blob Data Contributor`) and the **sensitive API action** performed (e.g., `iam:CreateUser`, `iam:AttachPolicy`, `Compute:CreateSnapshot`).
4.  **Source Analysis:** Note the **source IP address** and **user agent** of the request. Look for activity from rare/geographically unusual IPs or legacy user agents.

### 1.2 Minimal Triage Data Collection (Cloud-Native Artifacts)

Collect the following minimal set of data from the **Cloud Audit Log** (e.g., Azure Activity Log, AWS CloudTrail):

* **Identity & Session:** `AccountName` / `UPN`, `Session ID`, and the duration of the suspicious session.
* **Time Range:** The **exact time** of the role change/sensitive action, plus a forensic window of **$\pm72$ hours** for preceding login attempts and enumeration.
* **Target Artifacts:** The **target resource ID** and the **new policy document** or **role assignment ID**.
* **Geolocation & Client:** Source IP address, country, and client type (e.g., browser vs. CLI).

### 1.3 Escalation Criteria

Escalate immediately to the L3 Analyst/Technical Lead when any of the following are true:

* The change is **unapproved** and grants **administrative rights** to a non-privileged user or a non-standard Service Principal.
* The activity originates from an **impossible travel location** or a **TOR/VPN exit node**.
* The compromised identity is a **Tier-0 Service Account** or a **Security Administrator**.
* The suspicious activity is followed by **key/secret generation** or the **creation of new users** (T1098.001).

---

## 2. L3 Analyst Actions (Technical Deep Dive & Impact Assessment)

The L3 analyst focuses on confirming the initial vector, removing the persistence, and determining the full blast radius of the compromised role.

### 2.1 Full Attack Chain Reconstruction

1.  **Initial Access Vector:** Determine *how* the identity was compromised:
    * **Credential Theft:** Was there suspicious login activity or a breach notification?
    * **Access Key Abuse:** Was a valid API key used outside of its normal context (e.g., used by an external IP)?
    * **Lateral Movement:** Was the identity obtained from a compromised VM (e.g., using Instance Metadata Service to steal an attached role)?
2.  **Persistence Analysis:** Confirm all persistence mechanisms established by the attacker:
    * **New Roles/Users:** Are there any newly created, redundant admin roles or users?
    * **Trust Relationships:** Were trust relationships modified to grant access to an external tenant/account?
    * **Backdoor Keys:** Were new SSH keys added to critical VMs or were new access keys generated for the compromised account?
3.  **Impact and Access Scope:** Review the audit logs to identify *every* sensitive operation the elevated role performed (e.g., data dumps from storage, creation of shadow infrastructure, security policy changes).

### 2.2 Classification and Scoping (Focus on Cloud Risk)

1.  **Activity Classification:**
    * **Malicious Intrusion (T1098 Confirmed):** Unauthorized, irreversible privilege granting followed by resource manipulation.
    * **Misconfiguration / Role Drift:** Unintentional over-permissioning by a trusted administrator (requires hardening, not full incident response).
2.  **Scope the Incident:** Define the **criticality** of the data/resources accessed, and the **full list of compromised identities and resources** the attacker attempted to modify or destroy.

---

## 3. Containment – Recommended Actions (Identity First)

Containment must focus on revoking the compromised session and removing the unauthorized role access.

1.  **Identity Revocation (Immediate):**
    * **Revoke Sessions:** Immediately terminate all active sessions for the compromised user account/Service Principal.
    * **Remove Credentials:** Rotate or revoke all associated access keys, API tokens, and secrets.
    * **Geoblock/Conditional Access:** Update Conditional Access Policies (CAPs) to temporarily block access from the identified suspicious source IPs/countries.
2.  **Role Removal:** **MANDATORY** remove the unauthorized high-privilege role assignment and delete any newly created **"shadow" users** or Service Principals.
3.  **Infrastructure Containment:** If the attacker created new resources (e.g., a rogue VM or database), isolate those resources via network security groups (NSGs) or delete them only after forensic data is preserved.

---

## 4. Remediation & Hardening – Strategic Improvements

Focus on strengthening IAM controls and establishing a Just-in-Time (JIT) security culture.

1.  **Control Failure Analysis:** Identify which control failed (e.g., lack of MFA on admin role, overly permissive service principal policy, lack of alerting on `iam:AttachPolicy`).
2.  **Propose and Track Improvements:**
    * **Detection Logic:** Implement new, refined **detection logic** to alert on IAM operations originating from non-federated identities or unusual user agents (see KQL below).
    * **IAM Hardening:** Enforce **PIM/JIT access** for all high-privilege roles, requiring manual justification and time boxing.
    * **Preventative Policy:** Implement **Service Control Policies (SCPs)** or **Cloud Policy Guardrails** to restrict the creation of new high-privilege roles or changes to critical IAM policies.
3.  **Documentation and Knowledge Transfer:** Update this playbook, SOPs, and the Knowledge Base, emphasizing the importance of securing IAM access keys.

---

## 5. Threat Hunting Queries (KQL Focus)

These KQL fragments target unauthorized role modifications and sensitive persistence attempts in the cloud environment.

### 5.1 Hunting Query Example (KQL Only)

This KQL query hunts for unauthorized role assignments (a classic T1098 event) where the source is not a recognized administrator or automation process, which may signal a compromised identity.

```kql
// KQL Query for Cloud Role Assignment/Escalation Detection (Azure Example)
// Note: This requires relevant Azure Activity or Defender for Cloud logs ingested.
let SensitiveActions = dynamic(['Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleDefinitions/write']);
let AdminRoles = dynamic(['Owner', 'Global Administrator', 'User Access Administrator', 'Security Administrator']);
let ApprovedSources = dynamic(['Azure-PIM-Service', 'Terraform-CI-Service-Principal', 'Approved_JIT_Admin_Group']);
AzureActivity
| where OperationNameValue in (SensitiveActions)
| extend RoleDefinition = tostring(parse_json(Properties).roleDefinitionId)
| extend RolePrincipal = tostring(parse_json(Properties).principalId)
| where RoleDefinition has_any (AdminRoles) // Targets admin roles
| where not(Caller in (ApprovedSources)) // Excludes known automation/JIT processes
| summarize
    AttemptCount = count(),
    UniqueSources = dcount(Caller),
    SourceIPs = make_set(SourceIPAddress),
    TargetRoles = make_set(RoleDefinition)
    by Caller, ActivityStatus
| where AttemptCount > 1 // Look for repeated or widespread attempts
| extend Action = "Cloud Role Escalation Attempt"
| project Action, Caller, UniqueSources, AttemptCount, SourceIPs, TargetRoles, ActivityStatus
| order by Timestamp desc
```

Concluding Remarks: A Strategic Perspective
This playbook demonstrates a mature, identity-centric approach to cloud security. When engaging with employers, highlight that this is not just a reactive response—it is a comprehensive strategy for managing the most common and dangerous cloud intrusion scenarios.

Focus on the "Why": Explain that this addresses the shift from endpoint security to Identity as the new Perimeter. Cloud incidents almost always begin with a compromised key or session.

Emphasize JIT and Automation: Stress the importance of Just-in-Time (JIT) access policies to minimize standing permissions, transforming the entire organization's security posture from static defense to proactive governance.

Show Adaptability: Point out that the steps and KQL can be mapped seamlessly between major cloud providers (Azure, AWS, GCP) because the underlying threats (T1098, T1078) remain the same, proving your ability to manage multi-cloud environments.
