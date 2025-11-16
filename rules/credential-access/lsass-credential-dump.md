# LSASS Credential Dumping Behaviour – L3 Native Detection Rule

## Threat Focus

LSASS Credential Dumping Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1003.001, T1055

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
let dump_tools = dynamic(["procdump.exe","rundll32.exe","wmic.exe","nanodump.exe","lsassy.exe","comsvcs.dll","procdump64.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (dump_tools) or ProcessCommandLine has "lsass"
| extend Cmd = tostring(ProcessCommandLine)
| extend IsDumpSwitch = iif(Cmd has_any ("-ma","-mp","MiniDump","comsvcs.dll","lsass"), 1, 0)
| extend ConfidenceScore =
    iif(IsDumpSwitch == 1 and FileName in (dump_tools), 9,
    iif(IsDumpSwitch == 1, 7, 4))
| extend Reason = case(
    IsDumpSwitch == 1 and FileName in (dump_tools), "Classic LSASS dump tooling with known dump switches.",
    IsDumpSwitch == 1, "Process using LSASS-related dump switches.",
    "Potential LSASS dump or credential theft tooling."
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
