# File Timestomping Behaviour – L3 Native Detection Rule

## Threat Focus

File Timestomping Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1070.006

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| extend Cmd = tostring(ProcessCommandLine)
| extend ConfidenceScore = 4
| extend Reason = "timestomping – baseline native behavioural detection; tune conditions to match your environment."
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
