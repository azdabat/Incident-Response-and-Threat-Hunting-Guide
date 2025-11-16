# Modern LOLBIN – Winget Package Abuse – L3 Native Detection Rule

## Threat Focus

Modern LOLBIN – Winget Package Abuse is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: execution
- MITRE: T1218, T1059

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "winget.exe"
| extend Cmd = tostring(ProcessCommandLine)
| extend IsCustomSource = iif(Cmd has_any ("--source","-s") and Cmd has_any ("http://","https://") and Cmd !has "microsoft", 1, 0)
| extend IsSilentInstall = iif(Cmd has_any ("--silent","--accept-package-agreements","--accept-source-agreements"), 1, 0)
| extend ConfidenceScore =
    iif(IsCustomSource == 1 and IsSilentInstall == 1, 9,
    iif(IsCustomSource == 1, 7,
    iif(IsSilentInstall == 1, 5, 3)))
| extend Reason = strcat("Winget invocation: ", Cmd,
                         iif(IsCustomSource == 1, " using custom/non-Microsoft source.", ""),
                         iif(IsSilentInstall == 1, " with silent/auto-accept flags.", ""))
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
