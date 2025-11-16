# SMB / PsExec-style ADMIN$ Lateral Movement – L3 Native Detection Rule

## Threat Focus

SMB / PsExec-style ADMIN$ Lateral Movement is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: lateral-movement
- MITRE: T1021.002, T1077

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
let lateral_tools = dynamic(["psexec.exe","wmic.exe","powershell.exe","cmd.exe"]);
let admin_ports = dynamic([445,139]);
let smb_connections = DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (admin_ports)
| where InitiatingProcessFileName in (lateral_tools)
| project Timestamp, DeviceId, DeviceName, AccountName,
          RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine;
let admin_writes = DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FolderPath matches regex @"(?i)^\\[^\]+\ADMIN\$"
| project Timestamp, DeviceId, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine;
smb_connections
| join kind=inner (admin_writes) on DeviceId
| extend ConfidenceScore =
    iif(FileName has_any (".exe",".bat",".cmd"), 9, 7)
| extend Reason = strcat("ADMIN$ write from lateral tool ", InitiatingProcessFileName, " dropping ", FileName, " to remote host.")
| project Timestamp=Timestamp1, DeviceId, DeviceName, AccountName,
          RemoteIP, RemotePort, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          ConfidenceScore, Reason

| extend Severity = case(
    ConfidenceScore >= 8, "High",
    ConfidenceScore >= 5, "Medium",
    ConfidenceScore >= 3, "Low",
    "Informational"
)
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", tostring(DeviceName),
    "; User=", tostring(AccountName),
    "; CoreReason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High", "Isolate host, collect full triage (process, file, network, identity), check for lateral movement and credential theft, notify IR lead.",
        Severity == "Medium", "Validate admin/change context, pivot ±24h on the same device/user, correlate with other detections, decide on containment.",
        Severity == "Low", "Baseline this behaviour for this asset/user, treat as a weak hunting signal, consider tuning or elevating if seen with other anomalies.",
        "Use as contextual signal only; combine with higher-confidence rules."
    )
)
| where ConfidenceScore >= 3
| order by Timestamp desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
