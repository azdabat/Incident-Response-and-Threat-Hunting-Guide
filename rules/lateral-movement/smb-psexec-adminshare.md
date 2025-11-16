# SMB / PsExec-style ADMIN$ Lateral Movement – L3 Native Detection Rule

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
// Purpose: Detect SMB/ADMIN$-based lateral movement and tool propagation
// using native telemetry only (no external TI).
// MITRE: T1021.002 (SMB Admin Shares), T1569.002 (Service Execution), T1078 (Valid Accounts)
// ===================================================================

// -------------------- Tunables --------------------
let lookback = 7d;
let corr_window = 15m;
let propagation_threshold = 3;   // >=3 remote hosts = likely worm-style spread
let procSet = dynamic(["psexec.exe","wmic.exe","powershell.exe","cmd.exe","sc.exe"]);

// -------------------- SMB connection stage --------------------
let SmbNet =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort == 445
| where InitiatingProcessFileName in (procSet)
| extend SmbProc = InitiatingProcessFileName, SmbCmd = InitiatingProcessCommandLine
| project SmbTime = Timestamp,
          DeviceId, DeviceName, RemoteIP, SmbProc, SmbCmd;

// -------------------- ADMIN$ / C$ share writes --------------------
let AdminShareWrites =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FolderPath matches regex @"(?i)^\\\\[A-Za-z0-9_\.-]+\\(ADMIN\$|C\$)"
| extend TargetHost = tostring(extract(@"\\\\([^\\]+)\\", 1, FolderPath))
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
        or ProcessCommandLine has_any ("psexec", "\\\\", "\\ADMIN$", "sc.exe create", "sc.exe start")
    | project SvcTime = Timestamp,
              SvcHost = DeviceName,
              SvcFileName = FileName,
              SvcCmd = ProcessCommandLine,
              SvcInitiator = InitiatingProcessFileName
),
(
    SecurityEvent
    | where EventID == 7045  // Service created
    | extend SvcTime = TimeGenerated,
              SvcHost = Computer,
              SvcCmd = tostring(EventData),
              SvcFileName = "ServiceCreation",
              SvcInitiator = "System"
    | project SvcTime, SvcHost, SvcFileName, SvcCmd, SvcInitiator
);

// -------------------- DNS enrichment (hostnames for IPs) --------------------
let DnsMap =
DnsEvents
| where Timestamp >= ago(lookback)
| project DnsTime = Timestamp,
          DeviceName,
          RemoteIP = IPAddress,
          ResolvedHost = Name;

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

// correlate SMB traffic → ADMIN$/C$ writes
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

// -------------------- Behaviour scoring (no TI) --------------------
| extend HasServiceExec = iif(isnotempty(SvcTime), 1, 0)
| extend IsPsExecStyle =
    iif(SmbProc == "psexec.exe" or SvcCmd has "psexesvc", 1, 0)
| extend IsWMICStyle =
    iif(SmbProc == "wmic.exe" or SvcCmd has "wmic", 1, 0)
| extend IsSCExecStyle =
    iif(SmbProc == "sc.exe" or SvcCmd has "sc.exe create" or SvcCmd has "sc.exe start", 1, 0)
| extend IsPowershellRemoting =
    iif(SmbProc == "powershell.exe" and SmbCmd has_any ("Invoke-Command","New-PSSession","Enter-PSSession"), 1, 0)

// count unique remote hosts per source (worm / mass propagation)
| extend HostPropagationCount = dcount(TargetHost) over (DeviceName)

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
| extend MITRE_Tactics = "TA0008 (Lateral Movement); TA0002 (Execution)",
         MITRE_Techniques = "T1021.002 (SMB/ADMIN$), T1569.002 (Service Execution), T1078 (Valid Accounts)"

// -------------------- Hunter directives --------------------
| extend ThreatHunterDirectives = strcat(
    "Severity=", Severity,
    "; SourceDevice=", DeviceName,
    "; TargetHost=", TargetHost,
    "; SMBProc=", SmbProc,
    "; PropagationCount=", tostring(HostPropagationCount),
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Treat as likely active lateral movement or worm-like propagation. Immediately review full process tree on the source host, validate the account used for SMB connections (from SigninLogs), inspect the dropped binary on ADMIN$/C$ for malware, and consider isolating the source host. Check for additional lateral movement (WinRM, RDP, SMB to other subnets).",
        Severity == "Medium",
            "Validate whether the SMB/ADMIN$ activity is part of legitimate IT remote administration. Review service creation on the target host, confirm the operator and change ticket, and pivot across other devices contacted by the same source with HostPropagationCount.",
        "Use as a hunting signal. Baseline known-good remote admin behaviour and adjust propagation_threshold and procSet accordingly."
    )
)

// -------------------- Final projection --------------------
| project
    SmbTime,
    SourceDevice = DeviceName,
    RemoteIP,
    TargetHost,
    FolderPath,
    DroppedFile = FileName,
    SmbProc,
    SmbCmd,
    SvcFileName,
    SvcCmd,
    AccountUPN,
    HostPropagationCount,
    ConfidenceScore,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    ThreatHunterDirectives
| where ConfidenceScore >= 85   // focus on Medium+ by default; tune as needed
| order by ConfidenceScore desc, SmbTime desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
