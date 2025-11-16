# SQL Server xp_cmdshell / Agent Lateral Movement – L3 Native Detection Rule

## Threat Focus

SQL Server xp_cmdshell / Agent Lateral Movement is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: lateral-movement
- MITRE: T1505.001, T1059

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ===================================================================
// SQL Server xp_cmdshell / Agent Lateral Movement — L3 Native
// Author: Ala Dabat (Alstrum) | Version: 2025-11
// Platform: Microsoft Sentinel / MDE Advanced Hunting
// Category: lateral-movement
// Purpose: Detect SQL Server (xp_cmdshell) and SQL Agent abuse
//          to spawn OS processes and move laterally using native
//          endpoint + network telemetry only (no external TI).
// MITRE: T1505.001 (SQL Stored Procedures), T1059 (Command & Scripting),
//        T1021.* (Remote Services), T1047 (WMI), T1569.002 (Service Exec)
// ===================================================================

// -------------------- Tunables --------------------
let lookback = 7d;
let corr_window = 10m;
let min_confidence = 85;    // Default threshold for Medium+ signals

// Suspicious OS tools when launched by sqlservr / SQL Agent
let SuspiciousChildProcs = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe",
    "wscript.exe","cscript.exe",
    "bitsadmin.exe","certutil.exe",
    "psexec.exe","wmic.exe",
    "rundll32.exe","regsvr32.exe","mshta.exe",
    "schtasks.exe","at.exe",
    "ftp.exe","tftp.exe","curl.exe","wget.exe",
    "whoami.exe","net.exe","net1.exe","nltest.exe",
    "nslookup.exe","ipconfig.exe"
]);

// T-SQL patterns strongly associated with xp_cmdshell abuse
let XpCmdshellPatterns = dynamic([
    "xp_cmdshell",
    "EXEC xp_cmdshell",
    "exec xp_cmdshell",
    "exec master..xp_cmdshell",
    "sp_configure 'xp_cmdshell'",
    "sp_configure ''xp_cmdshell''"
]);

// -------------------- Stage 1: Suspicious processes from SQL Server / Agent --------------------
let SqlOsExec =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
// SQL Engine / Agent as parent or grand-parent
| where InitiatingProcessFileName in~ ("sqlservr.exe","sqlagent.exe","sqlagent90.exe","sqlagent$instance")
    or InitiatingProcessParentFileName in~ ("sqlservr.exe","sqlagent.exe","sqlagent90.exe","sqlagent$instance")
// Child is suspicious OS tooling OR the SQL client command line shows xp_cmdshell
| extend IsSuspiciousChild = iif(FileName in (SuspiciousChildProcs), 1, 0)
| extend HasXpCmdshellPattern =
    iif(ProcessCommandLine has_any (XpCmdshellPatterns)
        or InitiatingProcessCommandLine has_any (XpCmdshellPatterns),
        1, 0)
| where IsSuspiciousChild == 1 or HasXpCmdshellPattern == 1
| project
    ProcTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName;

// -------------------- Stage 2: Network correlation (lateral movement from SQL host) --------------------
let SqlLateralNet =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
// focus on internal / lateral or common admin ports
| where ipv4_is_private(RemoteIP)
    or RemotePort in (135,139,445,1433,1434,3389,5985,5986,22)
// Not strictly required, but helps give context
| project
    NetTime = Timestamp,
    DeviceId,
    DeviceName,
    RemoteIP,
    RemotePort,
    Protocol,
    LateralInitProc = InitiatingProcessFileName,
    LateralInitCmd = InitiatingProcessCommandLine;

// -------------------- Stage 3: Correlate process execution with network activity --------------------
SqlOsExec
| join kind=leftouter (
    SqlLateralNet
) on DeviceId
| extend HasLateralNet =
    iif(isnotempty(NetTime) and NetTime between (ProcTime .. ProcTime + corr_window), 1, 0)
| extend LateralRemoteIP = iif(HasLateralNet == 1, RemoteIP, "")
| extend LateralRemotePort = iif(HasLateralNet == 1, RemotePort, int(null))
| extend LateralProtocol   = iif(HasLateralNet == 1, Protocol, "")

// Per-device count of distinct lateral targets in the window
| extend LateralHostCount = dcountif(LateralRemoteIP, isnotempty(LateralRemoteIP)) over (DeviceId)

// -------------------- Stage 4: Behaviour scoring (no TI) --------------------
// SQL service / high-priv context?
| extend IsSqlServiceAccount =
    iif(AccountName has "NT SERVICE\\MSSQLSERVER"
        or AccountName has "NT SERVICE\\SQLSERVERAGENT"
        or AccountName has "NT AUTHORITY\\SYSTEM"
        or AccountName matches regex @"(?i).*sql.*svc.*",
        1, 0)

// xp_cmdshell / Agent execution strength
| extend BaseScore = 80;
| extend ConfidenceScore =
    BaseScore
    + iif(IsSuspiciousChild == 1, 10, 0)                     // sqlservr/Agent → LOLBIN/OS tooling
    + iif(HasXpCmdshellPattern == 1, 10, 0)                  // explicit xp_cmdshell or sp_configure
    + iif(IsSqlServiceAccount == 1, 5, 0)                    // high-priv SQL service context
    + iif(HasLateralNet == 1, 5, 0)                          // host is actively talking to others
    + iif(HasLateralNet == 1 and LateralRemotePort in (445,3389,5985,5986,1433,1434), 5, 0); // classic lateral ports
// Propagation bonus
| extend ConfidenceScore = ConfidenceScore
    + iif(LateralHostCount >= 3, 5, 0);                      // multiple targets from same SQL host

// -------------------- Severity & MITRE mapping --------------------
| extend Severity = case(
    ConfidenceScore >= 95, "High",
    ConfidenceScore >= 85, "Medium",
    "Low"
)
| extend MITRE_Tactics = "TA0002 (Execution); TA0008 (Lateral Movement); TA0003 (Persistence)",
         MITRE_Techniques = "T1505.001 (SQL Stored Procedures), T1059 (Command & Scripting), T1021.* (Remote Services), T1047 (WMI), T1569.002 (Service Execution)";

// -------------------- Threat Hunter Directives --------------------
| extend ThreatHunterDirectives = strcat(
    "Severity=", Severity,
    "; SQLHost=", DeviceName,
    "; SQLAccount=", AccountName,
    "; ChildProc=", FileName,
    "; ChildCmd=", substring(ProcessCommandLine, 0, 200),
    "; LateralIP=", tostring(LateralRemoteIP),
    "; LateralPort=", tostring(LateralRemotePort),
    "; LateralHostCount=", tostring(LateralHostCount),
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Treat as likely SQL Server-origin lateral movement. Immediately review the full process tree from sqlservr/SQLAgent, confirm who initiated the database session (application vs. direct DBA), check for SQL injection against front-end apps, and isolate the SQL host if unapproved. Validate whether the SQL service account has excessive rights and pivot to all hosts in LateralHostCount for follow-on activity (PsExec/WMI/RDP).",
        Severity == "Medium",
            "Validate whether this SQL-origin OS execution is part of a documented maintenance job. Correlate with SQL Agent job history and change tickets for the time window. If unapproved, treat as a compromise of the SQL service and expand hunting for the same AccountName and same DeviceName across the last 30 days.",
        "Use as a focused hunting signal. Baseline legitimate DBA / maintenance patterns (backup scripts, known Agent jobs) and tune out known-good combinations of AccountName, DeviceName, FileName, and ProcessCommandLine while keeping xp_cmdshell-like patterns and lateral net flows in scope."
    )
)

// -------------------- Final projection --------------------
| project
    ProcTime,
    SQLHost = DeviceName,
    SQLServiceAccount = AccountName,
    ParentProcess = InitiatingProcessFileName,
    ParentCmd = InitiatingProcessCommandLine,
    ChildProcess = FileName,
    ChildCmd = ProcessCommandLine,
    LateralRemoteIP,
    LateralRemotePort,
    LateralProtocol,
    LateralHostCount,
    IsSuspiciousChild,
    HasXpCmdshellPattern,
    IsSqlServiceAccount,
    ConfidenceScore,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    ThreatHunterDirectives
| where ConfidenceScore >= min_confidence
| order by ConfidenceScore desc, ProcTime desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
