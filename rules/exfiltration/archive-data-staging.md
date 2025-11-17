# Archive-based Data Staging (7z/rar/zip) – L3 Native Detection Rule

## Threat Focus

Archive-based Data Staging (7z/rar/zip) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: exfiltration
- MITRE: T1074, T1560

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
//  Archive Creation in Suspicious Locations — L3 Exfil/Preparation Hunt
//  MITRE: T1560 (Archive Collected Data), T1020 (Exfiltration Over Network)
//  Author: Ala Dabat (Alstrum) — 2025 Exfil Staging Pack
// =====================================================================

let lookback = 14d;

// Common archivers + LOLBINs used for data staging
let Archivers = dynamic([
    "7z.exe","7za.exe","7zG.exe","winrar.exe","rar.exe","zip.exe","tar.exe",
    "powershell.exe","pwsh.exe","cmd.exe"
]);

// Sensitive directories attackers typically stage from
let SensitiveRoots = dynamic([
    @"C:\Users\", @"C:\Documents and Settings\", @"C:\Windows\Temp\",
    @"C:\Temp\", @"C:\ProgramData\", @"C:\Windows\Tasks\"
]);

// Archive extensions
let ArchiveExt = dynamic([".7z",".zip",".rar",".tar",".gz",".bz2"]);

DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileCreated","FileModified")
| extend LName = tolower(FileName)
| extend Ext = tostring(extract(@"\.(\w+)$", 1, LName))
| where strcat(".", Ext) in (ArchiveExt)
| extend ArchivePath = FolderPath, ArchiveName = FileName

// ----------------------------------------------------------------------
//  Join to the process that created the archive (same device + time proximity)
// ----------------------------------------------------------------------
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName in~ (Archivers)
    | extend Cmd = tostring(ProcessCommandLine)
    | project DeviceId, AccountName,
              ProcTime = Timestamp,
              ProcName = FileName,
              Cmd, InitiatingProcessFileName,
              InitiatingProcessCommandLine
) on DeviceId

| where abs(datetime_diff("minute", Timestamp, ProcTime)) <= 5

// ----------------------------------------------------------------------
//  Behaviour flags
// ----------------------------------------------------------------------

// Archive created in staging/sensitive locations
| extend SuspiciousPath = ArchivePath has_any (SensitiveRoots)

// Large or multi-file archives (exfil pattern)
| extend LargeArchive = FileSize >= 50 * 1024 * 1024  // > 50 MB

// PowerShell-based archiving (common in exfil)
| extend PSArchive = ProcName in ("powershell.exe","pwsh.exe")
                     and Cmd has_any ("Compress-Archive","Add-Type","System.IO.Compression")

// RAR/7z password-protected indicators
| extend PasswordProtect =
       Cmd has_any ("-p","-hp","--password","-y","-mhe","mhe=on")

// Multiple archives created within short time window (mass staging)
let MultiArchive =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FileName has_any (".zip",".7z",".rar",".tar",".gz")
| summarize ArchiveBurst = count() by DeviceId, bin(Timestamp, 15m);

| join kind=leftouter MultiArchive on DeviceId
| extend BurstActivity = iif(ArchiveBurst >= 3, 1, 0)

// Suspicious parents (browser → archiver, script → archiver)
| extend SuspiciousParent =
       InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                      "outlook.exe","winword.exe","excel.exe",
                                      "wscript.exe","cscript.exe","mshta.exe")

// ----------------------------------------------------------------------
//  Severity (behaviour → severity)
// ----------------------------------------------------------------------
| extend Severity = case(
        (SuspiciousPath and LargeArchive)
        or (PasswordProtect and SuspiciousPath)
        or (PSArchive)
        or (BurstActivity == 1)
        or (SuspiciousParent and SuspiciousPath),
            "High",

        SuspiciousPath
        or PasswordProtect
        or LargeArchive
        or SuspiciousParent,
            "Medium",

        true,
            "Low"
    )

| where Severity in ("High","Medium","Low")

// ----------------------------------------------------------------------
//  Reason
// ----------------------------------------------------------------------
| extend Reason = strcat(
      "Archive created: ", ArchiveName, ". ",
      iif(SuspiciousPath,   "Suspicious staging directory. ", ""),
      iif(LargeArchive,     "Large archive (>50MB). ", ""),
      iif(PasswordProtect,  "Password-protected archive. ", ""),
      iif(PSArchive,        "PowerShell-based compression. ", ""),
      iif(SuspiciousParent, "Suspicious parent process. ", ""),
      iif(BurstActivity==1, "Multiple archives created in short window. ", "")
)

// ----------------------------------------------------------------------
//  L3 Hunting Directives
// ----------------------------------------------------------------------
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Reason=", Reason,
    "; NextSteps=",
        case(
            Severity == "High",
                "This resembles exfil staging. Review contents of the archive if possible, check for large file reads, cloud drive uploads, removable media activity, and outbound network flows. Contain host if malicious.",
            Severity == "Medium",
                "Validate business justification. Review user activity, process lineage, and recent file access patterns.",
            "Likely benign, but monitor if repeated. Baseline known archiving tools or software packaging workflows."
        )
)

// ----------------------------------------------------------------------
| project Timestamp, DeviceId, DeviceName, AccountName,
          ArchiveName, ArchivePath, ProcName, Cmd,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileSize, Severity, Reason, HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
