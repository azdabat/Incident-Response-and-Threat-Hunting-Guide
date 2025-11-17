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

```
An Additional rule I built up over many weeks. Covers A LOT more
// =============================================================================
// WSL Privilege Escalation & Persistence Detection
// Author: Ala Dabat
// Description: High-fidelity detection for WSL abuse patterns focusing on 
//              privilege escalation, persistence, and container escape
// MITRE ATT&CK: T1611 - Escape to Host, T1068 - Exploitation for Privilege Escalation,
//               T1078 - Valid Accounts, T1055 - Process Injection
// =============================================================================

let WslExecutables = dynamic(["wsl.exe","wslhost.exe","bash.exe","ubuntu.exe","kali.exe","debian.exe"]);
let CriticalMaliciousFlags = dynamic([
    "--debug-shell", "--system", "-u root", "--user root",
    "/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa", "/var/run/docker.sock"
]);
let HighRiskParents = dynamic([
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", 
    "rundll32.exe", "installutil.exe"
]);
let NetworkExecPattern = @"\s(-e|--exec)\s+(""|')?(nc\s|curl\s+http|wget\s+http|python\s+-c\s+""import|perl\s+-e\s+""system)";
let SuspiciousMountPattern = @"(--mount|--unmount).*(/mnt/c/Windows|/mnt/c/ProgramData|/mnt/c/Users)";

let ProcessSuspicious =
DeviceProcessEvents
| where FileName in~ (WslExecutables)
| extend
    f = tolower(FileName),
    cli = tolower(ProcessCommandLine),
    p = tolower(InitiatingProcessFileName)
| where (
        (cli has_any (CriticalMaliciousFlags) and p in~ (HighRiskParents))
        or
        (cli matches regex NetworkExecPattern and p in~ (HighRiskParents))
        or
        (cli matches regex SuspiciousMountPattern)
        or
        (p in~ ("mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"))
    )
    and not (
        cli has_all ("--install", "ubuntu") or 
        cli has_all ("--update", "kernel") or
        cli has_all ("--list", "--verbose") or
        cli contains " --help" or
        cli contains " --version"
    )
// THREAT HUNTER DIRECTIVES - RISK & THREAT BASED
| extend HuntingDirectives = case(
    // THREAT-BASED: High confidence malicious activity
    p in~ ("mshta.exe", "wscript.exe", "cscript.exe") and cli has_any ("--debug-shell", "/etc/shadow", "/etc/sudoers"),
    "IMMEDIATE INVESTIGATION: Script engine spawning WSL with critical system access - Check for embedded scripts and parent process chain",
    
    // THREAT-BASED: Container escape attempt
    cli matches regex SuspiciousMountPattern,
    "CONTAINER ESCAPE ATTEMPT: WSL mounting Windows directories - Review mount targets and file access patterns",
    
    // RISK-BASED: Network tool execution
    cli matches regex NetworkExecPattern,
    "SUSPICIOUS EXECUTION: Network tools via WSL exec - Correlate with network connections and outbound traffic",
    
    // THREAT-BASED: Privilege escalation evidence
    cli has_any ("--user root", "-u root", "--system") and p in~ (HighRiskParents),
    "PRIVILEGE ESCALATION: Suspicious parent obtaining root access via WSL - Audit user account and group membership changes",
    
    // RISK-BASED: General suspicious execution
    true,
    "INVESTIGATE: Suspicious WSL execution pattern - Review command line arguments and initiating process context"
    ),
    MitreTactics = "T1611,T1068,T1078,T1055",
    InvestigationPriority = case(
        p in~ ("mshta.exe", "wscript.exe") and cli has_any ("--debug-shell", "/etc/shadow"), "CRITICAL",
        cli matches regex NetworkExecPattern, "HIGH", 
        cli matches regex SuspiciousMountPattern, "HIGH",
        true, "MEDIUM"
    )
| project
    Timestamp,
    DeviceName,
    Detection = "WSL-Privilege-Escalation-Persistence",
    ParentProcess = p,
    ParentCmdLine = InitiatingProcessCommandLine,
    FileName = f,
    ProcessCommandLine = cli,
    HuntingDirectives,
    InvestigationPriority,
    MitreTactics,
    InitiatingProcessAccountName,
    FolderPath,
    SHA256;

let CriticalSensitivePaths = dynamic([
    "/etc/shadow", "/etc/sudoers", "/etc/gshadow", 
    "/root/.ssh/authorized_keys", "/var/run/docker.sock"
]);
let CriticalPermissionRegex = @"\b(666|777|6[0-9][0-9]6|7[0-9][0-9]7)\b";

let FilePermsCritical =
DeviceFileEvents
| where ActionType in~ ("FileCreated", "FileModified", "PermissionsModified")
| where tolower(FolderPath) has_any (CriticalSensitivePaths)
| extend af = tostring(AdditionalFields)
| where af matches regex CriticalPermissionRegex
| where not (InitiatingProcessFileName in~ ("apt", "dpkg", "yum", "systemd", "init", "cron"))
// THREAT HUNTER DIRECTIVES - RISK & THREAT BASED
| extend HuntingDirectives = case(
    // THREAT-BASED: Critical system file permission weakening
    FolderPath contains "/etc/shadow" and af matches regex @"\b(666|777)\b",
    "CRITICAL THREAT: /etc/shadow permissions weakened - Immediate system compromise possible - Check for unauthorized account creation",
    
    // THREAT-BASED: SSH key exposure
    FolderPath contains "/root/.ssh/authorized_keys" and af matches regex @"\b(666|777)\b",
    "PERSISTENCE THREAT: SSH authorized_keys exposed - Attacker may have added backdoor keys - Audit SSH key changes",
    
    // RISK-BASED: Docker socket exposure
    FolderPath contains "/var/run/docker.sock" and af matches regex @"\b(666|777)\b",
    "CONTAINER ESCAPE RISK: Docker socket permissions weakened - Review container security context and privilege levels",
    
    // RISK-BASED: Sudoers file modification
    FolderPath contains "/etc/sudoers" and af matches regex @"\b(666|777)\b",
    "PRIVILEGE ESCALATION RISK: Sudoers file exposed - Check for unauthorized privilege grants",
    
    true,
    "INVESTIGATE: Critical file permission change - Review file integrity and process lineage"
    ),
    MitreTactics = "T1222.002,T1068,T1078",
    InvestigationPriority = case(
        FolderPath contains "/etc/shadow", "CRITICAL",
        FolderPath contains "/root/.ssh", "HIGH",
        FolderPath contains "/var/run/docker.sock", "HIGH",
        true, "MEDIUM"
    )
| project
    Timestamp,
    DeviceName,
    Detection = "Critical-File-Permission-Weakness",
    FileName,
    FolderPath,
    ActionType,
    AdditionalFields,
    HuntingDirectives,
    InvestigationPriority,
    MitreTactics,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName;

union ProcessSuspicious, FilePermsCritical
| order by Timestamp desc
```


The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
