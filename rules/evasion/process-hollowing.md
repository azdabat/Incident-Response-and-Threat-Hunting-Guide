# Process Hollowing / PE-swap – L3 Native Detection Rule

## Threat Focus

Process Hollowing / PE-swap is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1055.012

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
//  Process Hollowing / PE-Swap — L3 Detection (MDE Native)
//  Author: Ala Dabat  – 2025 Memory Evasion Collection
//  MITRE: T1055.012 | T1055 | T1036
// =====================================================================

let lookback = 14d;

// High-risk parent processes (LOLBIN → hollowed target)
let SuspiciousParents = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe","installutil.exe",
    "msbuild.exe","wmic.exe","certutil.exe","curl.exe"
]);

// Common hollowing targets (often used for masking)
let HollowingTargets = dynamic([
    "svchost.exe","dllhost.exe","notepad.exe","explorer.exe","runtimebroker.exe",
    "winlogon.exe","smss.exe","conhost.exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)

// -----------------------------------------------------------
//  1. Memory-Manipulation Signals from AdditionalFields
// -----------------------------------------------------------

// RWX region creation — MDE exposes this as PAGE_EXECUTE_READWRITE
| extend RWX_Memory = AdditionalFields has "PAGE_EXECUTE_READWRITE"

// Remote thread creation → classic hollowing (CreateRemoteThread)
| extend RemoteThreadCreation = AdditionalFields has "RemoteThreadCreated"

// PE anomalies — header tampering or PE-swap indicators
| extend PE_Anomaly = AdditionalFields has "ImageLoadedButSignatureMismatch"
                 or AdditionalFields has "PEHeaderMismatch"
                 or AdditionalFields has "ImageCorruptOrManipulated"

// -----------------------------------------------------------
// 2. Parent > Child Anomaly
// -----------------------------------------------------------
| extend SuspiciousParentChild =
    InitiatingProcessFileName in (SuspiciousParents)
    and FileName in (HollowingTargets)

// -----------------------------------------------------------
//  3. Behavioural Scoring (L3 Analyst Logic)
// -----------------------------------------------------------
| extend BehaviourScore =
      (iif(RWX_Memory, 3, 0))
    + (iif(RemoteThreadCreation, 4, 0))
    + (iif(PE_Anomaly, 3, 0))
    + (iif(SuspiciousParentChild, 2, 0))

| where BehaviourScore >= 3   // avoid low-value noise

// -----------------------------------------------------------
// 4. Confidence + Severity
// -----------------------------------------------------------
| extend ConfidenceScore = BehaviourScore
| extend Severity = case(
      ConfidenceScore >= 8, "High",
      ConfidenceScore >= 5, "Medium",
      ConfidenceScore >= 3, "Low",
      "Informational"
)

// -----------------------------------------------------------
//  5. L3 Hunting Directives — Analyst Instructions
// -----------------------------------------------------------
| extend HuntingDirectives = strcat(
      "[ProcessHollowingDetection] ",
      "Severity=", Severity,
      "; Device=", DeviceName,
      "; User=", AccountName,
      "; Indicators=",
      case(RWX_Memory, "RWX_Memory;", ""),
      case(RemoteThreadCreation, "RemoteThreadInjection;", ""),
      case(PE_Anomaly, "PE_Anomaly;", ""),
      case(SuspiciousParentChild, "Suspicious_ParentChild;", ""),
      " | NextSteps=",
      case(
          Severity == "High",
          "Isolate host immediately. Acquire memory dump. Pull full process tree. Check for credential access (LSASS). Review network traffic for C2. Notify IR lead.",

          Severity == "Medium",
          "Validate context (admin tools, updates). Pivot ±1h across process, file, network. Investigate parent chain. Consider containment if combined with other alerts.",

          Severity == "Low",
          "Low-confidence memory event. Validate if installer/updater activity. Baseline or tune if recurring.",

          "Context-only signal — correlate with other alerts."
      )
)

// -----------------------------------------------------------
//  6. Output
// -----------------------------------------------------------
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RWX_Memory, RemoteThreadCreation, PE_Anomaly, SuspiciousParentChild,
          ConfidenceScore, Severity, HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
