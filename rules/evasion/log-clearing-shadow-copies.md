# Log Clearing and Shadow Copy Deletion – L3 Native Detection Rule

## Threat Focus

Log Clearing and Shadow Copy Deletion is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1070, T1489

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
let tools = dynamic(["wevtutil.exe","vssadmin.exe","powershell.exe","cmd.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (tools)
| extend Cmd = tostring(ProcessCommandLine)
| extend IsLogClear = iif(Cmd has "wevtutil" and Cmd has_any ("cl","clear-log","/c"), 1, 0)
| extend IsShadowDelete = iif(Cmd has "vssadmin" and Cmd has_any ("delete","shadows","/all"), 1, 0)
| extend ConfidenceScore =
    iif(IsLogClear == 1 and IsShadowDelete == 1, 9,
    iif(IsShadowDelete == 1, 8,
    iif(IsLogClear == 1, 7, 4)))
| extend Reason = case(
    IsLogClear == 1 and IsShadowDelete == 1, "Log clearing and shadow copy deletion on same host; strong anti-forensics indicator.",
    IsShadowDelete == 1, "Shadow copies deleted; often precursor to ransomware.",
    IsLogClear == 1, "Event logs cleared; anti-forensics behaviour.",
    "Potential anti-forensics tooling."
)
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, Cmd,
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
