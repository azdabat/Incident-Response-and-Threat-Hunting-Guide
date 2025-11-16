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
          HiveFileName=FileName, H

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
