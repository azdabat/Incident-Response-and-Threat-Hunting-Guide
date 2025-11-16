# MFA Fatigue / Push Spamming – L3 Native Detection Rule

## Threat Focus

MFA Fatigue / Push Spamming is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: cloud
- MITRE: Credential abuse

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where AuthenticationRequirement has_any ("multiFactorAuthentication","mfa")
| where ResultType has_any ("Other","Failure")
| summarize Failures=count() by AccountUpn, IPAddress, bin(Timestamp, 10m)
| extend ConfidenceScore =
    iif(Failures >= 20, 9,
    iif(Failures >= 10, 7, 4))
| extend Reason = strcat("Multiple MFA-challenged failures (", tostring(Failures), ") for ", AccountUpn, " from ", IPAddress, " in 10-minute window.")
| project Timestamp, DeviceId="", DeviceName=IPAddress, AccountName=AccountUpn,
          Failures, ConfidenceScore, Reason

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
