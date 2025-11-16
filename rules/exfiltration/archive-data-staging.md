# Archive-based Data Staging (7z/rar/zip) – L3 Native Detection Rule

## Threat Focus

Archive-based Data Staging (7z/rar/zip) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: exfiltration
- MITRE: T1074, T1560

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
let archivers = dynamic(["7z.exe","7za.exe","7zG.exe","winrar.exe","rar.exe","zip.exe","tar.exe","powershell.exe"]);
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FileName has_any (".7z",".rar",".zip",".tar",".gz")
| extend ArchivePath = FolderPath, ArchiveName = FileName
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName in (archivers)
    | extend Cmd = tostring(ProcessCommandLine)
    | project DeviceId, DeviceName, ProcTime=Timestamp, ProcName=FileName, Cmd, AccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine
) on DeviceId
| extend ConfidenceScore =
    iif(ArchivePath has_any(@"C:\Users\","C:\Windows\Temp","C:\Temp","C:\ProgramData"), 8, 5)
| extend Reason = strcat("Archive ", ArchiveName, " created in ", ArchivePath, " via ", ProcName, "; potential staging of data.")
| project Timestamp=coalesce(ProcTime, Timestamp), DeviceId, DeviceName, AccountName,
          ArchiveName, ArchivePath, ProcName, Cmd,
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
