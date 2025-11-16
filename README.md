# Native Detection Bible – L3 Behavioural Rulepack

This project is a **pure native KQL detection and hunting pack** for Microsoft 365 Defender
and Microsoft Sentinel. It mirrors the structure and methodology of your LOLBIN Threat Hunter
Bible, but focuses on:

- Execution / foothold
- Credential access
- Lateral movement
- Persistence
- Defense evasion / anti-forensics
- Command & Control
- Data staging / exfiltration
- Cloud abuse
- Supply-chain style behaviours

Each rule includes:

- L3-level behavioural KQL
- `ConfidenceScore` and `Severity`
- `HuntingDirectives` for analysts
- MITRE technique mapping
- Per-attack chain context
- MDE / Sentinel analyst views
- L3 incident response playbooks

See `docs/How-To-Run-Hunts.md` and `docs/Native-vs-TI-Philosophy.md` for
execution guidance and design rationale.
