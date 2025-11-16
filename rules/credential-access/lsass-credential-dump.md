# LSASS Credential Dumping Behaviour – L3 Native Detection Rule

## Threat Focus

LSASS Credential Dumping Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1003.001, T1055

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ===========================================
// LSASS Credential Dumping – L3 Native Detection
// Author: Ala Dabat 
// MITRE: T1003.001, T1055
// ===========================================

let lookback = 14d;

// Known dumping tools, common masquerades, BOF patterns, misc binaries
let DumpTools = dynamic([
    "procdump.exe","procdump64.exe","comsvcs.dll","nanodump.exe","nanodump64.exe",
    "mimikatz.exe","lsassy.exe","taskmgr.exe","wmic.exe","rundll32.exe",
    "handle.exe","pypykatz.exe","procexp.exe","procexp64.exe",
    "dllhost.exe","dmp.exe","dumpert.exe","outflank.dll"
]);

// Suspicious extensions attackers rename dumping tools to
let SuspiciousExt = dynamic([".tmp",".dat",".bin",".dll",".sys"]);

// High-risk LSASS access verbs
let DumpSwitches = dynamic(["-ma","-mp","MiniDump","lsass","getpas","sekurlsa","dump"]);

// Suspicious parent processes for LSASS access attempts
let SuspiciousParents = dynamic([
    "powershell.exe","cmd.exe","cscript.exe","wscript.exe","msbuild.exe",
    "regsvr32.exe","mshta.exe","rundll32.exe"
]);

// 1. Process execution patterns
let ProcEvents =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| extend Cmd = tostring(ProcessCommandLine)
| extend IsDumpTool = iif(FileName in (DumpTools), 1, 0)
| extend HasDumpSwitch = iif(Cmd has_any (DumpSwitches), 1, 0)
| extend SuspiciousExtHit = iif(FileName endswith_any (SuspiciousExt), 1, 0)
| extend SuspiciousParent = iif(InitiatingProcessFileName in (SuspiciousParents), 1, 0)
| where FileName in (DumpTools)
    or SuspiciousExtHit == 1
    or HasDumpSwitch == 1
    or Cmd has "lsass"
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, Cmd, InitiatingProcessFileName, InitiatingProcessCommandLine,
          IsDumpTool, HasDumpSwitch, SuspiciousExtHit, SuspiciousParent;

// 2. Image loads of LSASS-sensitive DLLs (MiniDumpWriteDump, Dbghelp, comsvcs)
let ImageLoads =
DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| where ImageFileName has_any (".dll")
| where InitiatingProcessFileName !in ("lsass.exe","taskmgr.exe","wmiprvse.exe","sdiagnhost.exe")
| where ImageFileName has_any ("dbghelp","comsvcs","minidump","symsrv","dbgcore")
| project LoadTime=Timestamp, DeviceId, DeviceName,
          ProcessName, ImageFileName;

// 3. Combine
ProcEvents
| join kind=leftouter ImageLoads on DeviceId
| extend LoadedDumpDLL = iif(isnotempty(ImageFileName), 1, 0)

// ===== Confidence Scoring =====
| extend ConfidenceScore =
    0
    + iif(IsDumpTool == 1 and HasDumpSwitch == 1, 9, 0)
    + iif(IsDumpTool == 1, 7, 0)
    + iif(HasDumpSwitch == 1, 6, 0)
    + iif(SuspiciousParent == 1, 4, 0)
    + iif(SuspiciousExtHit == 1, 3, 0)
    + iif(LoadedDumpDLL == 1, 5, 0)
    + iif(Cmd has "lsass", 4, 0)

// ===== Reason =====
| extend Reason = strcat(
    iif(IsDumpTool == 1, "Known dumping tool. ", ""),
    iif(HasDumpSwitch == 1, "LSASS dump switches present. ", ""),
    iif(SuspiciousExtHit == 1, "Binary masquerading via suspicious extension. ", ""),
    iif(SuspiciousParent == 1, strcat("Suspicious parent process: ", InitiatingProcessFileName, ". "), ""),
    iif(LoadedDumpDLL == 1, strcat("Loaded dump-related DLL: ", ImageFileName, ". "), ""),
    iif(Cmd has "lsass", "Explicit LSASS reference in command line. ", "")
)

// ===== Severity =====
| extend Severity = case(
    ConfidenceScore >= 12, "High",
    ConfidenceScore >= 8, "Medium",
    ConfidenceScore >= 4, "Low",
    "Informational"
)

// ===== Hunter Directives =====
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Immediately isolate host. Check for credential theft, LSASS handle duplication, memory reads, lateral movement. Collect full triage: process tree, loaded modules, memory, SAM/SECURITY/NTDS access, network.",
        Severity == "Medium",
            "Validate admin use of procdump/backup tools. Pivot ±24h for credential access patterns. Correlate with Kerberos anomalies (4769/4768).",
        Severity == "Low",
            "Baseline admin processes for this host. Watch for escalation.",
            "Use only in combination with other signals."
    )
)

// ===== Output =====
| where ConfidenceScore >= 3
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
