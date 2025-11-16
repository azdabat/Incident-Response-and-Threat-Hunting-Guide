# SAM/SECURITY Hive Export – L3 Native Detection Rule

## Threat Focus

SAM/SECURITY Hive Export is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1003.002

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ==========================================================
// SAM / SECURITY / SYSTEM Hive Extraction – L3 Native Rule
// Author: Ala Dabat 
// MITRE: T1003.002 (Registry Hives), T1003.006, T1059, T1055
// Behaviour-based detection of all modern hive theft vectors
// ==========================================================

let lookback = 14d;

// Known tools and masquerades used for hive extraction
let HiveTools = dynamic([
    "reg.exe","regedit.exe","powershell.exe","cmd.exe","wmic.exe",
    "vssadmin.exe","diskshadow.exe","mimikatz.exe","rubeus.exe",
    "lsassy.exe","secretsdump.py","impacket-secretsdump.exe",
    "dllhost.exe","rundll32.exe"
]);

// Suspicious file extensions attackers use when renaming hive dumps
let SusExt = dynamic([".tmp",".bak",".bin",".dat",".save",".old",".dmp"]);

// Registry hives of interest
let HivePaths = dynamic([
    "\\System32\\config\\sam",
    "\\System32\\config\\system",
    "\\System32\\config\\security"
]);

// Registry export keywords
let ExportKeywords = dynamic([
    "reg save","save hklm","reg export","hklm\\sam","hklm\\system","hklm\\security"
]);

// 1. Process-based hive extraction patterns
let Proc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| extend Cmd = tostring(ProcessCommandLine)
| extend IsHiveTool = iif(FileName in (HiveTools), 1, 0)
| extend ExportCommand = iif(Cmd has_any (ExportKeywords), 1, 0)
| extend SuspiciousParent =
    iif(InitiatingProcessFileName in ("powershell.exe","cmd.exe","rundll32.exe","mshta.exe","cscript.exe"), 1, 0)
| where IsHiveTool == 1 or ExportCommand == 1 or Cmd has_any (HivePaths)
| project Timestamp, DeviceName, DeviceId, AccountName,
          FileName, Cmd, InitiatingProcessFileName,
          IsHiveTool, ExportCommand, SuspiciousParent;

// 2. Raw file access to the actual hive files (even renamed)
let HiveFileAccess =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend LPath = tolower(FolderPath)
| where LPath has @"\system32\config\" 
| where FileName contains_any ("sam","system","security") 
      or FileName endswith_any (SusExt)
| where ActionType in ("FileCopied","FileCreated","FileModified","FileDeleted")
| project HiveTime=Timestamp, DeviceName, DeviceId,
          HiveFileName=FileName, HiveFolder=FolderPath;

// Join process activity to file activity
Proc
| join kind=fullouter HiveFileAccess on DeviceId
| extend HiveActivity = iif(isnotempty(HiveFileName), 1, 0)

// VSS / shadow copy behaviour (shadow copy used for hive extraction)
| extend IsVSS = iif(Cmd has_any ("shadow","vssadmin","shadowcopy","diskshadow"), 1, 0)

// Final scoring
| extend ConfidenceScore =
    0
    + iif(ExportCommand == 1, 6, 0)
    + iif(HiveActivity == 1, 8, 0)
    + iif(IsHiveTool == 1, 4, 0)
    + iif(IsVSS == 1, 4, 0)
    + iif(SuspiciousParent == 1, 3, 0)
    + iif(Cmd has_any (HivePaths), 5, 0)
    + iif(Cmd has "sam" or Cmd has "system" or Cmd has "security", 3, 0)

// Reasoning for analyst
| extend Reason = strcat(
    iif(ExportCommand == 1, "Registry hive export command detected. ", ""),
    iif(HiveActivity == 1, strcat("Raw hive file accessed: ", HiveFileName, ". "), ""),
    iif(IsVSS == 1, "Shadow copy operations detected. ", ""),
    iif(IsHiveTool == 1, "Known hive extraction tool executed. ", ""),
    iif(SuspiciousParent == 1, strcat("Executed from suspicious parent: ", InitiatingProcessFileName, ". "), "")
)

// Severity classification
| extend Severity = case(
    ConfidenceScore >= 12, "High",
    ConfidenceScore >= 7,  "Medium",
    ConfidenceScore >= 3,  "Low",
    "Informational"
)

// Hunter directives
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Treat as probable credential hive extraction. Immediately isolate device. Collect triage: SAM/SYSTEM/SECURITY copies, LSASS access, shadow copies, network lateral movement. Investigate for follow-on credential misuse.",
        Severity == "Medium",
            "Review context of registry modifications. Pivot across ±24h for credential access activity. Validate admin intent.",
        Severity == "Low",
            "Baseline behaviour. Consider tuning for legitimate backup software.",
        "Use as contextual signal only."
    )
)

// Output results
| where ConfidenceScore >= 3
| order by Timestamp desc


```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
