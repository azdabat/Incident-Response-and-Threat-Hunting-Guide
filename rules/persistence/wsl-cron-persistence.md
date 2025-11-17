# WSL Cron-based Persistence – L3 Native Detection Rule

## Threat Focus

WSL Cron-based Persistence is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: persistence
- MITRE: T1053

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
// WSL Cron / WSL-Based Persistence Detection (L3 – Low Noise)
// Author: Ala Dabat (Alstrum)
// Focus: WSL launched with persistence-oriented arguments, suspicious parents,
//        network loaders, encoded payloads, or user-writable cron/script paths.
// MITRE: T1611 (Escape to Host), T1053 (Scheduled Task/Cron), T1059.003 (Unix Shell)
// =====================================================================

let lookback = 14d;

// // WSL binaries
let WSLBins = dynamic(["wsl.exe","wslhost.exe","bash.exe","ubuntu.exe","kali.exe","debian.exe"]);

// // High-risk parents (macro → WSL, lolbin → WSL, browser → WSL)
let SuspiciousParents = dynamic([
    "mshta.exe","wscript.exe","cscript.exe",
    "powershell.exe","pwsh.exe",
    "regsvr32.exe","rundll32.exe",
    "chrome.exe","msedge.exe","firefox.exe"
]);

// // Indicators of persistence or host interaction
let PersistenceIndicators = dynamic([
    "crontab","/etc/cron.","/etc/cron.d","/etc/cron.daily",
    "/etc/rc.local","systemctl","service ",
    "/etc/init.d"
]);

// // Sensitive paths attackers may touch
let SensitiveWSLPaths = dynamic([
    "/etc/shadow","/etc/passwd","/etc/sudoers","/root/.ssh",
    "/var/spool/cron","/var/run/docker.sock"
]);

// // User-writable or staging paths
let UserWritableRx = @"(?i)^/mnt/c/(users|public|programdata|temp|appdata)/";

// // Encoded, download, or loader behaviours
let LoaderStrings = dynamic([
    "-encodedcommand"," -enc ","frombase64string","curl ","wget ",
    "invoke-webrequest","downloadstring","python -c","perl -e"
]);

// // Regex patterns
let NetworkExecRx = @"\b(nc|netcat|curl|wget|python\s+-c|perl\s+-e)\b";
let CronEditRx = @"(?i)(crontab|-l| -e|/etc/cron\.)";
let MountRx = @"(?i)(--mount|--unmount).*(/mnt/c/Windows|/mnt/c/Users|/mnt/c/ProgramData)";

// =====================================================================
// Raw WSL activity
// =====================================================================
let RawWSL =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (WSLBins)
| extend CL = tolower(ProcessCommandLine),
         Parent = tolower(InitiatingProcessFileName);

// =====================================================================
// Signal extraction
// =====================================================================
let WithSignals =
RawWSL
| extend
    TouchesSensitive = CL has_any (SensitiveWSLPaths),
    HasCronBehaviour = CL matches regex CronEditRx or CL has_any (PersistenceIndicators),
    HasNetworkExec = CL matches regex NetworkExecRx,
    HasLoaderString = CL has_any (LoaderStrings),
    SuspiciousParent = Parent in~ (SuspiciousParents),
    MountAbuse = CL matches regex MountRx,
    UserWritableRef = CL matches regex UserWritableRx;

// =====================================================================
// Rarity & signer trust
// =====================================================================
let Prevalence =
DeviceFileEvents
| where Timestamp >= ago(30d)
| summarize DeviceCount=dcount(DeviceId) by SHA256;

let Enriched =
WithSignals
| join kind=leftouter (Prevalence) on $left.InitiatingProcessSHA256 == $right.SHA256
| extend DeviceCount = coalesce(DeviceCount,0),
         IsRare = iif(DeviceCount <= 2, 1, 0),
         TrustedSigner = iif(
            InitiatingProcessSigner in~ (
                "Microsoft Windows","Microsoft Windows Publisher",
                "Microsoft Corporation","Canonical","Debian Project"
            ), 1, 0);

// =====================================================================
// Behaviour-based scoring (L3 threshold)
// =====================================================================
Enriched
| extend SignalCount =
      toint(HasCronBehaviour)
    + toint(MountAbuse)
    + toint(HasNetworkExec)
    + toint(TouchesSensitive)
    + toint(HasLoaderString)
    + toint(UserWritableRef)
    + toint(SuspiciousParent)
    + toint(IsRare)
    + toint(1 - TrustedSigner)
| where SignalCount >= 3   // low noise

// =====================================================================
// Severity
// =====================================================================
| extend Severity = case(
    SignalCount >= 7, "High",
    SignalCount >= 5, "Medium",
    "Low"
)

// =====================================================================
// Hunting directives (concise, non-AI style)
// =====================================================================
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Parent=", InitiatingProcessFileName,
    "; Indicators=",
        iif(HasCronBehaviour,"Cron;",""),
        iif(HasNetworkExec,"NetExec;",""),
        iif(TouchesSensitive,"SensitiveFile;",""),
        iif(MountAbuse,"MountAbuse;",""),
        iif(HasLoaderString,"Loader;",""),
        iif(UserWritableRef,"UserWritable;",""),
        iif(SuspiciousParent,"SuspParent;",""),
        iif(IsRare,"RareBinary;",""),
    "; Next=",
    case(
        Severity == "High",  "Check for persistence (cron/systemd). Inspect mount targets and host file access. Review outbound network traffic. Consider host isolate.",
        Severity == "Medium","Review command line and parent chain. Verify user intent. Pivot ±24h across WSL, network, and file activity.",
        "Baseline unusual-but-benign usage; keep as a hunting cue."
    )
)

// =====================================================================
// Output
// =====================================================================
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          HasCronBehaviour, TouchesSensitive, HasNetworkExec,
          HasLoaderString, UserWritableRef, SuspiciousParent,
          MountAbuse, IsRare, TrustedSigner,
          SignalCount, Severity, HuntingDirectives
| order by SignalCount desc, Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
