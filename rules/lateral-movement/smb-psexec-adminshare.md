# SMB / PsExec-style ADMIN$ Lateral Movement – L3 Native Detection Rule
(Rule detections on other sensitive shares also)

## Threat Focus

SMB / PsExec-style ADMIN$ Lateral Movement is detected using pure native telemetry (no external TI) at L3 fidelity.

This rule will cover:
PsExec-style lateral movement

WMI + SC.exe service creation lateral movement

PowerShell remoting that is SMB-backed (tool transfer + service)

Copy-only SMB staging (dropping tools to ADMIN$/C$ without immediate execution)

Worm-like behaviour when the same source hits many hosts in a short window

- Category: lateral-movement
- MITRE: T1021.002, T1077

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ===================================================================
// SMB Lateral Movement — Enhanced (NotPetya / PsExec / WMI / SCExec)
// Author: Ala Dabat | Version: 2025-11
// Platform: Microsoft Sentinel / MDE
// Purpose: Detect SMB/ADMIN$/hidden-share-based lateral movement and
//          tool propagation using native telemetry only.
// MITRE: T1021.002 (SMB Admin Shares), T1569.002 (Service Execution),
//        T1078 (Valid Accounts)
// ===================================================================

// -------------------- Tunables --------------------
let lookback = 7d;
let corr_window = 15m;
let propagation_threshold = 3;   // >=3 remote hosts = likely worm-style spread
let procSet = dynamic(["psexec.exe","psexesvc.exe","wmic.exe","powershell.exe","pwsh.exe","cmd.exe","sc.exe","wmiadap.exe"]);

// Suspicious payload extensions
let SuspiciousExt = dynamic([".exe",".dll",".sys",".ps1",".psm1",".vbs",".js",".jse",".bat",".cmd",".msi",".scr"]);

// -------------------- SMB connection stage --------------------
let SmbNet =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort == 445
| where InitiatingProcessFileName in (procSet)
| extend SmbProc = InitiatingProcessFileName,
         SmbCmd  = InitiatingProcessCommandLine
| project SmbTime = Timestamp,
          DeviceId, DeviceName, RemoteIP, SmbProc, SmbCmd;

// -------------------- Admin / hidden share writes --------------------
let AdminShareWrites =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend LPath = tostring(FolderPath)
// Matches UNC paths to ADMIN$, C$, IPC$, PRINT$, SYSVOL, NETLOGON,
// and *any* hidden share that ends with $
| where LPath matches regex @"(?i)^\\\\[^\\]+\\(ADMIN\$|C\$|IPC\$|PRINT\$|SYSVOL|NETLOGON)"
   or LPath matches regex @"(?i)^\\\\[^\\]+\\[^\\]+\$"
| extend TargetHost = tostring(extract(@"\\\\([^\\]+)\\", 1, LPath))
// Focus on likely payloads / tools, not arbitrary files
| extend LName = tolower(FileName),
         Ext   = strcat(".", tostring(extract(@"([^.]+)$", 1, LName)))
| where Ext in (SuspiciousExt)
| project FileTime = Timestamp,
          DeviceName,
          DeviceId,
          TargetHost,
          FolderPath,
          FileName,
          SHA256,
          InitiatingProcessFileName;

// -------------------- Service creation / execution --------------------
let ServiceExec =
union
(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName in ("psexesvc.exe","svchost.exe","services.exe")
       or ProcessCommandLine has_any ("psexec","\\\\","\\ADMIN$","sc.exe create","sc.exe start")
    | project SvcTime = Timestamp,
              SvcHost = DeviceName,
              SvcFileName = FileName,
              SvcCmd = ProcessCommandLine,
              SvcInitiator = InitiatingProcessFileName
),
(
    SecurityEvent
    | where TimeGenerated >= ago(lookback)
    | where EventID == 7045  // Service created
    | extend SvcTime      = TimeGenerated,
              SvcHost      = Computer,
              SvcCmd       = tostring(EventData),
              SvcFileName  = "ServiceCreation",
              SvcInitiator = "System"
    | project SvcTime, SvcHost, SvcFileName, SvcCmd, SvcInitiator
);

// -------------------- DNS enrichment (hostnames for IPs) --------------------
let DnsMap =
DnsEvents
| where Timestamp >= ago(lookback)
| project DnsTime = Timestamp,
          DeviceName,
          RemoteIP,
          ResolvedHost = DomainName;

// -------------------- Optional auth correlation (sign-in IP → account) ------
let AuthLogons =
SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| project AuthTime = TimeGenerated,
          AccountUPN = UserPrincipalName,
          IPAddress;

// -------------------- Correlation --------------------
SmbNet
// attach DNS name for the remote target
| join kind=leftouter (DnsMap) on RemoteIP
| extend TargetHost = coalesce(ResolvedHost, RemoteIP)

// correlate SMB traffic → admin/hidden-share writes
| join kind=innerunique (
    AdminShareWrites
    | project FileTime, TargetHost, SrcDeviceName = DeviceName, FolderPath, FileName, SHA256
) on TargetHost
| where FileTime between (SmbTime .. SmbTime + corr_window)

// optional correlation with service execution (PsExec/WMI/sc.exe)
// leftouter so we still catch "copy-only" SMB lateral drops
| join kind=leftouter (
    ServiceExec
    | project SvcTime, SvcHost, SvcFileName, SvcCmd, SvcInitiator
) on $left.TargetHost == $right.SvcHost
| where isnull(SvcTime) or SvcTime between (FileTime .. FileTime + corr_window)

// optional sign-in mapping (who might be behind the IP)
| join kind=leftouter (
    AuthLogons
    | project AuthTime, AccountUPN, IPAddress
) on $left.RemoteIP == $right.IPAddress

// -------------------- Behaviour features (no TI) --------------------
| extend HasServiceExec = iif(isnotempty(SvcTime), 1, 0)
| extend IsPsExecStyle =
    iif(SmbProc in ("psexec.exe","psexesvc.exe") or SvcCmd has "psexesvc", 1, 0)
| extend IsWMICStyle =
    iif(SmbProc == "wmic.exe" or SvcCmd has "wmic ", 1, 0)
| extend IsSCExecStyle =
    iif(SmbProc == "sc.exe" or SvcCmd has "sc.exe create" or SvcCmd has "sc.exe start", 1, 0)
| extend IsPowershellRemoting =
    iif(SmbProc in ("powershell.exe","pwsh.exe")
        and SmbCmd has_any ("Invoke-Command","New-PSSession","Enter-PSSession"), 1, 0)

// count unique remote hosts per source (worm / mass propagation)
| summarize
      FirstSeen = min(SmbTime),
      LastSeen  = max(SmbTime),
      HostPropagationCount = dcount(TargetHost),
      any(RemoteIP),
      any(SmbProc),
      any(SmbCmd),
      any(FolderPath),
      any(FileName),
      any(SvcFileName),
      any(SvcCmd),
      any(AccountUPN)
  by SourceDevice = DeviceName

| extend SmbProc            = any_SmbProc,
         SmbCmd             = any_SmbCmd,
         RemoteIP           = any_RemoteIP,
         FolderPath         = any_FolderPath,
         DroppedFile        = any_FileName,
         SvcFileName        = any_SvcFileName,
         SvcCmd             = any_SvcCmd,
         AccountUPN         = any_AccountUPN

// base behaviour score (80) + technique weights
| extend ConfidenceScore =
    80
    + iif(HasServiceExec == 1, 10, 0)
    + iif(IsPsExecStyle == 1, 5, 0)
    + iif(IsWMICStyle == 1 or IsSCExecStyle == 1 or IsPowershellRemoting == 1, 3, 0)
    + iif(HostPropagationCount >= propagation_threshold, 10, 0);

// -------------------- Severity & MITRE mapping --------------------
| extend Severity = case(
    ConfidenceScore >= 95, "High",
    ConfidenceScore >= 85, "Medium",
    "Low"
)
| extend MITRE_Tactics =
    "TA0008 (Lateral Movement); TA0002 (Execution)",
         MITRE_Techniques =
    "T1021.002 (SMB/ADMIN$), T1569.002 (Service Execution), T1078 (Valid Accounts)"

// -------------------- Hunter directives --------------------
| extend ThreatHunterDirectives = strcat(
    "Severity=", Severity,
    "; SourceDevice=", SourceDevice,
    "; RemoteIP=", tostring(RemoteIP),
    "; HostPropagationCount=", tostring(HostPropagationCount),
    "; SMBProc=", SmbProc,
    "; DroppedFile=", DroppedFile,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Active lateral movement or worm-like propagation is likely. Pull full process tree on source host, inspect dropped binaries on admin/hidden shares, validate account usage from SigninLogs, and consider isolating the source. Pivot for SMB/WinRM/RDP activity from this host.",
        Severity == "Medium",
            "Confirm if this is sanctioned remote admin behaviour. Validate operator, change records, and service creation on targets. Tune procSet and share patterns for known-good tooling.",
        "Treat as a hunting lead. Baseline normal remote admin workflows and adjust thresholds; escalate if seen alongside other lateral-movement signals."
    )
)

// -------------------- Final projection --------------------
| where ConfidenceScore >= 85   // focus on Medium+ by default; tune as needed
| project
    FirstSeen,
    LastSeen,
    SourceDevice,
    RemoteIP,
    HostPropagationCount,
    FolderPath,
    DroppedFile,
    SmbProc,
    SmbCmd,
    SvcFileName,
    SvcCmd,
    AccountUPN,
    ConfidenceScore,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    ThreatHunterDirectives
| order by ConfidenceScore desc, LastSeen desc


```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.

Companion Rule:

Brute-force / spraying → lateral movement
Multiple SMB failures → a successful connection
Even with no PsExec/WMI/SC
Even with renamed binaries
Even if attacker uses built-in Windows tools
Credential compromise leading to lateral access
Succeeds even if attacker never writes to ADMIN$
Succeeds even with direct remote execution (cmd /c copy, powershell copy, custom tools)
Tool staging without service creation
Dropping malware into ADMIN$/C$ without starting a service (early-stage foothold)
Pure SMB logon abuse

Attackers using valid creds stolen from:
Mimikatz
LSASS dump
Token theft
Browser credential store
```
// =======================================================================
// SMB Brute Force → Successful Lateral Movement – L3 Native Detection
// Author: Ala Dabat | Platform: MDE / Sentinel
// Purpose: Detect password spraying or brute force against SMB followed by
//          successful ADMIN$/C$ access and potential lateral tool staging.
// MITRE: T1110.003 (Password Spraying), T1021.002 (SMB/Admin Shares),
//        T1078 (Valid Accounts), T1569.002 (Service Execution)
// =======================================================================

let lookback = 7d;
let fail_threshold = 15; // >=15 failures from same IP = brute-force/spray
let corr_window = 20m;

// -------------------- 1. SMB FAILURE EVENTS --------------------
let SmbFailures =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort == 445
| where ActionType in ("ConnectionFailed","InboundFailed","InboundConnectionFailed")
| summarize Failures=count() by SourceIP=RemoteIP, bin(Timestamp, 5m)
| where Failures >= fail_threshold
| project FailWindowStart = Timestamp, SourceIP, Failures;

// -------------------- 2. SMB SUCCESS EVENTS --------------------
let SmbSuccess =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort == 445
| where ActionType in ("ConnectionSuccess","InboundConnectionAccepted")
| project SuccessTime = Timestamp, DeviceName, DeviceId,
          SourceIP = RemoteIP, TargetIP = LocalIP, InitiatingProcessFileName, InitiatingProcessCommandLine;

// -------------------- 3. ADMIN$ / C$ WRITE EVENTS --------------------
let AdminShareWrites =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FolderPath matches regex @"(?i)^\\\\[A-Za-z0-9_\.-]+\\(ADMIN\$|C\$)"
| extend TargetHost=tostring(extract(@"\\\\([^\\]+)\\", 1, FolderPath))
| project WriteTime = Timestamp, TargetHost, FileName, FolderPath, SHA256, DeviceId;

// -------------------- 4. Correlate brute-force → success → file drop --------------------
SmbFailures
| join kind=inner (
    SmbSuccess
    | project SuccessTime, DeviceName, TargetIP, SourceIP, InitiatingProcessFileName, InitiatingProcessCommandLine
) on SourceIP
| where SuccessTime between (FailWindowStart .. FailWindowStart + corr_window)
| join kind=leftouter (
    AdminShareWrites
    | project WriteTime, TargetHost, FileName, FolderPath
) on $right.TargetHost == $left.TargetIP
| where isnull(WriteTime) or WriteTime between (SuccessTime .. SuccessTime + corr_window)

// -------------------- 5. Behaviour scoring --------------------
| extend HasShareWrite = iif(isnotempty(WriteTime), 1, 0)
| extend HasSuspiciousProc = iif(InitiatingProcessFileName in~ (
        "powershell.exe","cmd.exe","wmic.exe","sc.exe","rundll32.exe","psexec.exe"
    ), 1, 0)
| extend ConfidenceScore =
    80
    + iif(Failures >= fail_threshold, 5, 0)         // brute-force detection
    + iif(HasSuspiciousProc == 1, 5, 0)             // suspicious child
    + iif(HasShareWrite == 1, 10, 0)                // ADMIN$/C$ write
    + iif(Failures >= (fail_threshold * 2), 5, 0);  // heavy spraying

// -------------------- 6. Severity classification --------------------
| extend Severity = case(
    ConfidenceScore >= 95, "High",
    ConfidenceScore >= 85, "Medium",
    "Low"
)

// -------------------- 7. MITRE context --------------------
| extend MITRE_Tactics = "TA0006 (Credential Access); TA0008 (Lateral Movement)"
| extend MITRE_Techniques = strcat(
    "T1110.003 (Password Spraying), ",
    "T1021.002 (SMB/ADMIN$), ",
    iif(HasShareWrite == 1, "T1569.002 (Service Execution), ", ""),
    "T1078 (Valid Accounts)"
)

// -------------------- 8. Hunter directives --------------------
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; SourceIP=", SourceIP,
    "; TargetIP=", TargetIP,
    "; Failures=", tostring(Failures),
    "; SuspiciousProc=", tostring(InitiatingProcessFileName),
    "; ShareWrite=", tostring(HasShareWrite),
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "This pattern indicates brute-force → success → payload staging via SMB. Immediately verify the source IP, check for authorized logons, inspect dropped files on ADMIN$/C$, review NTLM/Kerberos logons, and isolate the device if malicious.",
        Severity == "Medium",
            "Review authentication logs for this IP. Validate process legitimacy (cmd/powershell/wmic/sc). Check C$/ADMIN$ for dropped tools and pivot across other SMB connections within ±24h.",
        "Baseline if this matches expected IT operations; otherwise, treat as a hunting lead and correlate with other lateral movement signals."
    )
)

// -------------------- 9. Final projection --------------------
| project
    FailWindowStart,
    SuccessTime,
    SourceIP,
    TargetIP,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    Failures,
    ConfidenceScore,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    HuntingDirectives
| where ConfidenceScore >= 85
| order by ConfidenceScore desc, SuccessTime desc
```

