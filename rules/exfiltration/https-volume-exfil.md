# Data Exfiltration over HTTPS (Volume Anomaly) – L3 Native Detection Rule

## Threat Focus

Data Exfiltration over HTTPS (Volume Anomaly) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: exfiltration
- MITRE: T1041, T1048.002

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort == 443
| extend Url = tostring(RemoteUrl), OutBytes = tolong(OutboundBytes)
| where OutBytes > 0
| summarize TotalOut = sum(OutBytes), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
  by DeviceId, DeviceName, AccountName, UrlDomain=tostring(Url)
| extend Timestamp = LastSeen
| extend ConfidenceScore =
    iif(TotalOut > 500000000, 9,
    iif(TotalOut > 100000000, 8,
    iif(TotalOut > 20000000, 6, 4)))
| extend Reason = strcat("High outbound HTTPS volume (", tostring(TotalOut), " bytes) to ", UrlDomain, ".")
| project Timestamp, DeviceId, DeviceName, AccountName,
          UrlDomain, TotalOut, ConfidenceScore, Reason

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
