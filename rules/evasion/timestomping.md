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

// Only files where MDE captured *previous* timestamps
| where isnotempty(PreviousFileCreationTime) 
   or isnotempty(PreviousFileModificationTime)

// -----------------------------------------------------------
//  Detect timestamp **rollback** (backdating)
// -----------------------------------------------------------
| extend CreationRollback = 
    (datetime_diff("minute", FileCreationTime, PreviousFileCreationTime) < -10)

| extend ModificationRollback =
    (datetime_diff("minute", FileModificationTime, PreviousFileModificationTime) < -10)

// -----------------------------------------------------------
//  Detect abnormal timestamp deltas (jump forward/backwards strongly)
// -----------------------------------------------------------
| extend CreationDelta = abs(datetime_diff("hour", FileCreationTime, Timestamp))
| extend ModificationDelta = abs(datetime_diff("hour", FileModificationTime, Timestamp))

| extend SuspiciousDelta = CreationDelta > 168 or ModificationDelta > 168  // > 7 days difference

// -----------------------------------------------------------
//  Score the behaviour
// -----------------------------------------------------------
| extend BehaviourScore =
      (iif(CreationRollback, 4, 0))
    + (iif(ModificationRollback, 4, 0))
    + (iif(SuspiciousDelta, 2, 0))

| where BehaviourScore >= 3   // ignore noise

| extend ConfidenceScore = BehaviourScore
| extend Severity = case(
    ConfidenceScore >= 8, "High",
    ConfidenceScore >= 5, "Medium",
    ConfidenceScore >= 3, "Low",
    "Informational"
)

// -----------------------------------------------------------
//  Hunting Directives (L3 Triage Guidance)
// -----------------------------------------------------------
| extend HuntingDirectives = strcat(
    "[TimestompingDetection] ",
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Indicators=",
        case(CreationRollback, "CreationRollback;", ""),
        case(ModificationRollback, "ModificationRollback;", ""),
        case(SuspiciousDelta, "LargeDelta;", ""),
    " | NextSteps=",
    case(
        Severity == "High",
        "Isolate host, triage for anti-forensics activity, inspect recent process creations, correlate with malware staging, investigate attacker cleanup operations.",

        Severity == "Medium",
        "Validate legitimate installer/patch operations, pivot by hash and filename, check for related file writes or deletes.",

        Severity == "Low",
        "Rare benign scenario (installer rollbacks). Baseline or tune if recurring.",

        "Correlation-only signal."
    )
)

// -----------------------------------------------------------
//  Output
// -----------------------------------------------------------
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, FolderPath,
          FileCreationTime, PreviousFileCreationTime,
          FileModificationTime, PreviousFileModificationTime,
          CreationRollback, ModificationRollback, SuspiciousDelta,
          ConfidenceScore, Severity, HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
