# File Timestomping Behaviour – L3 Native Detection Rule

## Threat Focus

File Timestomping Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1070.006

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
//  File Timestomping Detection (MDE / Sentinel)
//  MITRE: T1070.006 — Timestamp Manipulation
//  Author: Ala Dabat (Alstrum) — 2025 Native Evasion Pack
// =====================================================================

let lookback = 14d;

DeviceFileEvents
| where Timestamp >= ago(lookback)

// Only evaluate entries where MDE recorded *previous* timestamps
| where isnotempty(PreviousFileCreationTime)
       or isnotempty(PreviousFileModificationTime)

// --- 1. Direct timestamp rollback (backdating)
| extend CreationRollback =
        datetime_diff("minute", FileCreationTime, PreviousFileCreationTime) < -10,
         ModificationRollback =
        datetime_diff("minute", FileModificationTime, PreviousFileModificationTime) < -10

// --- 2. Large timestamp discontinuity (>7 days from event time)
| extend CreationDeltaHours      = abs(datetime_diff("hour", FileCreationTime, Timestamp)),
         ModificationDeltaHours  = abs(datetime_diff("hour", FileModificationTime, Timestamp)),
         SuspiciousDelta         = CreationDeltaHours > 168 or ModificationDeltaHours > 168

// --- 3. Severity mapping (behaviour-based)
| extend Severity = case(
        CreationRollback and ModificationRollback, "High",
        CreationRollback or ModificationRollback,  "Medium",
        SuspiciousDelta,                           "Low",
        "Informational"
)
| where Severity in ("High","Medium","Low")   // reduce noise

// --- 4. L3 analyst guidance
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Indicators=",
        iif(CreationRollback,      "CreationRollback;",      ""),
        iif(ModificationRollback,  "ModificationRollback;",  ""),
        iif(SuspiciousDelta,       "LargeTimestampDelta;",   ""),
    "; NextSteps=",
        case(
            Severity == "High",
                "Strong timestomping signal. Investigate anti-forensics behaviour. Pivot to recent process launches, file renames/deletes, and malware staging activity. Consider containment.",
            Severity == "Medium",
                "Review installer/patch context. Check file ancestry, correlate with process actions and recent writes. Validate expected admin or software update behaviour.",
            "Likely benign but unusual. Baseline if recurring; keep under watch if seen with other suspicious events."
        )
)

// --- 5. Output
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, FolderPath,
          FileCreationTime, PreviousFileCreationTime,
          FileModificationTime, PreviousFileModificationTime,
          CreationRollback, ModificationRollback, SuspiciousDelta,
          Severity, HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
