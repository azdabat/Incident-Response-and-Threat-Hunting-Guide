## Native Hunts vs TI-Powered Hunts (Philosophy)

This repository is explicitly focused on **native behavioural detection**.
It relies purely on:

- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`
- `DeviceImageLoadEvents`
- `DeviceRegistryEvents`
- `IdentityLogonEvents`
- `AuditLogs` / `SecurityEvent`

and **does not require**:

- IP/Domain IOCs
- Hash lists
- MISP feeds
- OpenCTI graphs

### What Native Hunts Can Do

Native hunts are extremely effective at catching:

- LOLBIN abuse
- Credential dumping
- Lateral movement
- Ransomware behaviours
- Data staging and exfiltration
- Cloud privilege escalation
- Anti-forensics and evasion
- Fileless and polymorphic techniques (behaviourally)

### What TI is For (Deliberately Out of Scope Here)

Threat Intelligence is essential for:

- Attribution and clustering (APT / crimeware families)
- Long-term infrastructure tracking
- Malware family naming and variant linkage
- Proactive 0-day/N-day awareness

This project is designed as a **pure detection engineering and L3 hunting artefact**,
to be layered with TI in a separate pipeline if desired.
