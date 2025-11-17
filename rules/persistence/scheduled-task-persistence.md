# Scheduled Task Persistence – L3 Native Detection Rule

## Threat Focus

Scheduled Task Persistence is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: persistence
- MITRE: T1053.002

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
// Scheduled Task Persistence (High-Fidelity, Low Noise)
// Author: Ala Dabat (Alstrum) – 2025 L3 Persistence Collection
// Platform: MDE / Sentinel
// =====================================================================

let lookback = 14d;

// ---------------------------
// A. Suspicious parents
// ---------------------------
let SuspiciousParents = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe",
    "mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","curl.exe",
    "msbuild.exe","wmic.exe","schtasks.exe" // recursive creation
]);

// ---------------------------
// B. LOLBIN keywords
// ---------------------------
let BadStrings = dynamic([
    "-EncodedCommand"," -enc "," -e ",
    "IEX(","Invoke-Expression","FromBase64String",
    "Invoke-WebRequest","DownloadString","Start-BitsTransfer",
    "rundll32","regsvr32","mshta","certutil","bitsadmin","curl",
    "WriteProcessMemory","VirtualAllocEx","CreateRemoteThread"
]);

// ---------------------------
// C. Suspicious file extensions
// ---------------------------
let SuspExt = dynamic(["exe","dll","js","jse","vbs","vbe","wsf","hta","ps1","psm1","bat","cmd","scr"]);
let SuspExtRx = @"(?i)\.(exe|dll|js|jse|vbs|vbe|wsf|hta|ps1|psm1|bat|cmd|scr)\b";

// ---------------------------
// D. Suspicious paths
// ---------------------------
let UserWritableRx = @"(?i)^[a-z]:\\(users|public|programdata|temp|downloads|appdata)\\";

// ---------------------------
// E. Org-wide prevalence
// ---------------------------
let OrgPrevalence =
DeviceFileEvents
| where Timestamp >= ago(30d)
| summarize DeviceCount=dcount(DeviceId) by SHA256, FileName, FolderPath;

// ---------------------------
// F. Raw scheduled-task creation / modification
// ---------------------------
// Detect task creation via schtasks.exe or through LOLBIN binaries
let Raw =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "schtasks.exe"
  or ProcessCommandLine has "/create"
  or ProcessCommandLine has "/change"
  or ProcessCommandLine has "schtasks "
  or ProcessCommandLine contains "TaskName"
  or ProcessCommandLine contains "/TN"
  or ProcessCommandLine contains "/TR"
| extend Cmd = tostring(ProcessCommandLine);

// ---------------------------
// G. Extract indicators
// ---------------------------
let WithIndicators =
Raw
| extend LowerCL = tolower(Cmd),
         HasBadString = LowerCL has_any (BadStrings),
         HasEncoded   = LowerCL has_any (dynamic(["-encodedcommand"," -enc "," -e "])),
         HasNet       = LowerCL matches regex @"https?://[^\s'\""]+" 
                        or LowerCL matches regex @"\b\d{1,3}(\.\d{1,3}){3}\b",
         SuspFileRef  = LowerCL matches regex SuspExtRx,
         IsUserWritable = LowerCL matches regex UserWritableRx,
         IsSuspiciousParent = InitiatingProcessFileName in~ (SuspiciousParents),
         TaskName     = extract(@"(?i)(/TN\s+\""?([^\""]+)\""?|/TN\s+([^\s]+))", 2, Cmd),
         TaskRun      = extract(@"(?i)(/TR\s+\""?([^\""]+)\""?|/TR\s+([^\s]+))", 2, Cmd);

// ---------------------------
// H. Add signer trust + file hash rarity
// ---------------------------
let Enriched =
WithIndicators
| join kind=leftouter (OrgPrevalence) on $left.InitiatingProcessSHA256 == $right.SHA256
| extend DeviceCount = coalesce(DeviceCount, 0),
         IsRare = iif(DeviceCount <= 2, 1, 0),
         IsTrustedPublisher = iif(InitiatingProcessSigner in~ (
              "Microsoft Windows","Microsoft Windows Publisher",
              "Microsoft Corporation","Microsoft Windows Hardware Compatibility Publisher",
              "Google LLC","Mozilla Corporation"
         ), true, false);

// ---------------------------
// I. Behaviour scoring (stacked)
// ---------------------------
Enriched
| extend SignalCount =
    toint(IsSuspiciousParent)
    + toint(HasBadString)
    + toint(HasNet)
    + toint(HasEncoded)
    + toint(SuspFileRef)
    + toint(IsUserWritable)
    + toint(not(IsTrustedPublisher))
    + toint(IsRare)
| where SignalCount >= 3     // <-- L3 threshold (low noise)

// ---------------------------
// J. Severity (based on signals)
// ---------------------------
| extend Severity = case(
    SignalCount >= 6, "High",
    SignalCount >= 4, "Medium",
    "Low"
)

// ---------------------------
// K. MITRE mappings
// ---------------------------
| extend MITRE_Tactics = "TA0003 Persistence; TA0002 Execution; TA0005 Defense Evasion",
         MITRE_Techniques = strcat_array(
             pack_array(
                 "T1053.005 Scheduled Task",
                 iif(HasEncoded==1,"T1059 Command Execution",""),
                 iif(HasBadString==1,"T1059.001 PowerShell",""),
                 iif(HasNet==1,"T1105 Ingress Tool Transfer",""),
                 iif(SuspFileRef==1,"T1036 Masquerading","")
             ), "; ")

// ---------------------------
// L. Hunting Directives (L3)
// ---------------------------
| extend HuntingDirectives = strcat(
    "[ScheduledTaskPersistence] Severity=", Severity,
    "; TaskName=", coalesce(TaskName,"Unknown"),
    "; TaskAction=", coalesce(TaskRun,"Unknown"),
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Signals=", tostring(SignalCount), "; ",
    "Indicators=",
        iif(IsSuspiciousParent, "SuspiciousParent;", ""),
        iif(HasBadString, "BadStrings;", ""),
        iif(HasEncoded, "Encoded;", ""),
        iif(HasNet, "NetworkIOCs;", ""),
        iif(SuspFileRef, "SuspExtension;", ""),
        iif(IsUserWritable, "UserWritablePath;", ""),
        iif(IsRare, "RareBinary;", ""),
        iif(not(IsTrustedPublisher), "UntrustedSigner;", ""),
    " | NextSteps=",
    case(
        Severity == "High",
           "Confirm whether scheduled task is expected. Extract task XML; inspect Task Action path. Review full process tree, dropped binaries, and outbound connections. Check for persistence chains. Isolate host if malicious.",
        Severity == "Medium",
           "Review task name/action. Validate signer and parent process. Pivot ±24h for file writes, network anomalies and related alerts.",
        "Baseline this behaviour only if tied to legitimate admin tooling; treat as weak signal otherwise."
    )
)

// ---------------------------
// M. Output
// ---------------------------
| project Timestamp, DeviceId, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, Cmd,
          TaskName, TaskRun,
          HasBadString, HasNet, HasEncoded, SuspFileRef,
          IsUserWritable, IsSuspiciousParent, IsRare, IsTrustedPublisher,
          SignalCount, Severity,
          MITRE_Tactics, MITRE_Techniques,
          HuntingDirectives
| order by SignalCount desc, Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
