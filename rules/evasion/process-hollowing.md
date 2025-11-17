# Process Hollowing / PE-swap – L3 Native Detection Rule

## Threat Focus

Process Hollowing / PE-swap is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1055.012

## Advanced Hunting Query (MDE / Sentinel)

```kql
// Process Hollowing / PE-Swap — L3 Detection (MDE Native)
// MITRE: T1055.012, T1055, T1036
// Author: Ala Dabat | 2025 Memory Evasion Collection

let lookback = 14d;

let SuspiciousParents = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe","installutil.exe",
    "msbuild.exe","wmic.exe","certutil.exe","curl.exe"
]);

let HollowingTargets = dynamic([
    "svchost.exe","dllhost.exe","notepad.exe","explorer.exe","runtimebroker.exe",
    "winlogon.exe","smss.exe","conhost.exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)

// 1 — Memory manipulation indicators (from AdditionalFields)
| extend RWX_Memory           = AdditionalFields has "PAGE_EXECUTE_READWRITE",
         RemoteThreadCreation = AdditionalFields has "RemoteThreadCreated",
         PE_Anomaly           = AdditionalFields has "ImageLoadedButSignatureMismatch"
                                or AdditionalFields has "PEHeaderMismatch"
                                or AdditionalFields has "ImageCorruptOrManipulated"

// 2 — Suspicious parent → target combination
| extend SuspiciousParentChild =
    InitiatingProcessFileName in (SuspiciousParents)
    and FileName in (HollowingTargets)

// 3 — Behaviour-based severity (no numeric scoring)
| extend Severity = case(
      RWX_Memory and RemoteThreadCreation and (PE_Anomaly or SuspiciousParentChild), "High",
      RemoteThreadCreation and (PE_Anomaly or SuspiciousParentChild),               "Medium",
      RWX_Memory or RemoteThreadCreation,                                           "Low",
      "Informational"
)

// Drop pure noise
| where Severity in ("High","Medium","Low")

// 4 — Analyst guidance
| extend HuntingDirectives = strcat(
      "Severity=", Severity,
      "; Device=", DeviceName,
      "; User=", AccountName,
      "; Indicators=",
         iif(RWX_Memory,           "RWX_Memory;",             ""),
         iif(RemoteThreadCreation, "RemoteThreadInjection;",  ""),
         iif(PE_Anomaly,           "PE_Anomaly;",             ""),
         iif(SuspiciousParentChild,"SuspiciousParentChild;",  ""),
      "; Next=",
      case(
          Severity == "High",
            "Isolate host, capture memory, pull full process tree, check for LSASS access and C2 connections.",
          Severity == "Medium",
            "Validate context (updaters/tools), review process ancestry, correlate with other alerts, consider containment.",
          "Review for installers/updaters; baseline or tune if recurring and benign."
      )
)

// 5 — Output
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RWX_Memory, RemoteThreadCreation, PE_Anomaly, SuspiciousParentChild,

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
