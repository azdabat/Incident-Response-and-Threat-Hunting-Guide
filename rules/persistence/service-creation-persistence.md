# Malicious Service Creation Persistence – L3 Native Detection Rule

## Threat Focus

Malicious Service Creation Persistence is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: persistence
- MITRE: T1543.003

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
// Service Creation / Modification Persistence (L3 – Low Noise)
// Author: Ala Dabat (Alstrum)
// MITRE: T1543.003 Windows Service; T1059; T1036; T1105
// =====================================================================

let lookback = 14d;

// // Suspicious parent processes
let SuspiciousParents = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe",
    "mshta.exe","rundll32.exe","regsvr32.exe","curl.exe","bitsadmin.exe",
    "wmic.exe","msbuild.exe","installutil.exe"
]);

// // Strings indicative of staged execution, tampering or loaders
let BadStrings = dynamic([
    "-EncodedCommand"," -enc "," IEX(","invoke-expression","frombase64string",
    "invoke-webrequest","downloadstring","start-bitstransfer",
    "rundll32","regsvr32","mshta","certutil","bitsadmin","curl",
    "writeprocessmemory","virtualallocex","createremotethread"
]);

// // Suspicious extensions and user-writable paths
let SuspExtRx = @"(?i)\.(exe|dll|js|ps1|bat|cmd|vbs|hta)\b";
let UserWritableRx = @"(?i)^[a-z]:\\(users|public|programdata|temp|downloads|appdata)\\";

// // File prevalence
let OrgPrevalence =
DeviceFileEvents
| where Timestamp >= ago(30d)
| summarize DeviceCount=dcount(DeviceId) by SHA256, FileName, FolderPath;

// // Detect service creation (multiple sources)
let RawSvc =
union 
(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName =~ "sc.exe" and ProcessCommandLine has_any ("create","config","failure")
    | extend Source="Proc"
),
(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName =~ "powershell.exe" and ProcessCommandLine has "New-Service"
    | extend Source="PowerShell"
),
(
    SecurityEvent
    | where TimeGenerated >= ago(lookback)
    | where EventID == 7045
    | extend Timestamp=TimeGenerated,
             ProcessCommandLine = tostring(EventData),
             FileName="ServiceCreation",
             InitiatingProcessFileName="System",
             InitiatingProcessCommandLine="",
             DeviceName=Computer,
             DeviceId=Computer,
             Source="Sysmon"
);

// // Extract indicators
let WithIndicators =
RawSvc
| extend Cmd = tostring(ProcessCommandLine),
         LowerCL = tolower(Cmd),
         SvcName = extract(@"(?i)(?<=create\s+)[^\s]+", 0, Cmd),
         BinPath = extract(@"(?i)(?<=binPath=)[^\s]+", 0, Cmd),
         HasBadString = LowerCL has_any (BadStrings),
         HasEncoded = LowerCL has_any (dynamic(["-encodedcommand"," -enc "," -e "])),
         HasNet = LowerCL matches regex @"https?://[^\s'\""]+" or LowerCL matches regex @"\b\d{1,3}(\.\d{1,3}){3}\b",
         SuspFileRef = LowerCL matches regex SuspExtRx,
         IsUserWritable = LowerCL matches regex UserWritableRx or LowerCL contains "\\appdata\\";

// // Join prevalence + signer trust
let Enriched =
WithIndicators
| join kind=leftouter (OrgPrevalence) on $left.InitiatingProcessSHA256 == $right.SHA256
| extend DeviceCount = coalesce(DeviceCount, 0),
         IsRare = iif(DeviceCount <= 2, 1, 0),
         IsTrustedPublisher = iif(InitiatingProcessSigner in~ (
             "Microsoft Windows","Microsoft Windows Publisher",
             "Microsoft Corporation","Google LLC","Mozilla Corporation"
         ), true, false),
         IsSuspiciousParent = InitiatingProcessFileName in~ (SuspiciousParents);

// // Behaviour scoring
Enriched
| extend SignalCount =
    toint(IsSuspiciousParent)
    + toint(HasBadString)
    + toint(HasEncoded)
    + toint(HasNet)
    + toint(SuspFileRef)
    + toint(IsUserWritable)
    + toint(not(IsTrustedPublisher))
    + toint(IsRare)
| where SignalCount >= 3   // L3 threshold, low noise

// // Severity
| extend Severity = case(
    SignalCount >= 6, "High",
    SignalCount >= 4, "Medium",
    "Low"
)

// // MITRE
| extend MITRE_Tactics = "TA0003 Persistence; TA0002 Execution; TA0005 Defense Evasion",
         MITRE_Techniques = "T1543.003 Windows Service"

// // Hunting directives
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; ServiceName=", coalesce(SvcName,"Unknown"),
    "; BinPath=", coalesce(BinPath,"Unknown"),
    "; Indicators=",
        iif(IsSuspiciousParent, "SuspiciousParent;", ""),
        iif(HasBadString, "BadStrings;", ""),
        iif(HasEncoded, "Encoded;", ""),
        iif(HasNet, "NetworkIOC;", ""),
        iif(SuspFileRef, "SuspFile;", ""),
        iif(IsUserWritable, "UserWritable;", ""),
        iif(IsRare, "RareBinary;", ""),
        iif(not(IsTrustedPublisher), "UntrustedSigner;", ""),
    "; Next=",
    case(
        Severity == "High",
            "Confirm service legitimacy. Dump service binary. Check for lateral movement. If malicious, isolate host.",
        Severity == "Medium",
            "Validate admin/change ticket. Review process tree and service binary. Pivot ±24h for related alerts.",
        "Low-confidence signal; baseline if expected."
    )
)

// // Output
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, Cmd, InitiatingProcessFileName, InitiatingProcessCommandLine,
          SvcName, BinPath,
          IsSuspiciousParent, HasBadString, HasNet, HasEncoded, SuspFileRef,
          IsUserWritable, IsRare, IsTrustedPublisher,
          SignalCount, Severity, MITRE_Tactics, MITRE_Techniques,
          HuntingDirectives
| order by SignalCount desc, Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
