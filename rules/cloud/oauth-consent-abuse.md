# OAuth Consent Abuse (Native Logs) – L3 Native Detection Rule

## Threat Focus

OAuth Consent Abuse (Native Logs) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: cloud
- MITRE: T1528, T1098

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName has "Consent to application"
| extend AppDisplayName = tostring(TargetResources[0].displayName),
         User = tostring(InitiatedBy.user.userPrincipalName),
         ConsentType = tostring(AdditionalDetails[0].value)
| extend ConfidenceScore =
    iif(ConsentType =~ "AllPrincipals", 9,
    iif(AppDisplayName has_any ("Management","Backup","Sync","Support"), 7, 5))
| extend Reason = strcat("OAuth consent granted: ", AppDisplayName, " by ", User, " with consent scope ", ConsentType, ".")
| project Timestamp=TimeGenerated, DeviceId="", DeviceName="", AccountName=User,
          AppDisplayName, ConsentType, ConfidenceScore, Reason

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
