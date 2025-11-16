# Incident Response Playbook – MFA Fatigue / Push Spamming

## 1. L2 Analyst Actions

- Confirm whether any documented change/maintenance could explain this behaviour.
- Collect a minimal triage set:
  - DeviceName, DeviceId
  - AccountName / UPN
  - Time range (±24h) around the detection
  - All hits from this rule and any related alerts on the same host/user
- Escalate to L3 when:
  - `Severity` is Medium or High
  - the host/user is sensitive (privileged, server, critical asset)
  - similar activity appears on multiple hosts.

## 2. L3 Analyst Actions (Technical Lead)

- Reconstruct the full chain around this detection:
  - Preceding execution: parent processes, initial access vector.
  - Subsequent activity: persistence, lateral movement, staging, exfiltration.
- Classify the activity as:
  - Benign admin / expected tooling
  - Misconfiguration / risky operational pattern
  - Malicious intrusion (hands-on-keyboard)
- Scope the incident:
  - Number of affected hosts
  - Number of affected identities
  - Any evidence of data access or exfiltration.

## 3. Containment – Recommended Actions

- Isolate affected endpoints where Severity is High or where hands-on-keyboard is suspected.
- Reset/revoke affected credentials (local, domain, cloud):
  - Users, service accounts, app registrations where applicable.
- Block or constrain involved tools or binaries using:
  - ASR, AppLocker, WDAC, EDR policy, or equivalent.
- For cloud-related detections:
  - Revoke sessions, enforce MFA / step-up, tighten conditional access.

## 4. Remediation & Hardening – Recommended Actions

- Identify which control layer failed (endpoint, identity, email, network, cloud).
- Propose and track improvements:
  - New or refined detection logic
  - Hardening baselines (GPO, Intune, CIS benchmarks)
  - Identity governance and JIT / just-enough admin rework
- Update:
  - Internal playbooks and SOPs
  - Threat models and risk register entries
  - Knowledge base entries so future analysts can recognise this pattern quickly.
