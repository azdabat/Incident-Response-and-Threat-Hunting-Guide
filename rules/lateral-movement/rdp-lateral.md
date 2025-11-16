# RDP Lateral Movement – L3 Native Detection Rule

## Threat Focus

RDP Lateral Movement is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: lateral-movement
- MITRE: T1021.001

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================
// Advanced RDP Attack Patterns - L3 Detection
// Author: Ala Dabat | Version: 2025-11 | Platform: Microsoft Sentinel / MDE
// Purpose: Detect RDP-based lateral movement, credential dumping, recon and persistence
// MITRE: T1021.001 (RDP), T1003.001 (LSASS Dumping), T1053.005 (Scheduled Task), T1570 (Lateral Tool Transfer), T1018 (Discovery)
// =====================================

let lookback = 7d;

// ===== 1. RDP SESSION DETECTION (NETWORK LAYER) =====
let RDPSessions =
    DeviceNetworkEvents
    | where Timestamp >= ago(lookback)
    | where RemotePort == 3389 or LocalPort == 3389    // Standard RDP port
    | where ActionType in ("ConnectionSuccess","InboundConnectionAccepted")
    | extend RDP_Direction = iff(RemotePort == 3389, "Outbound", "Inbound")
    | project
        RDPTime       = Timestamp,
        DeviceId,
        DeviceName,
        RDP_RemoteIP  = RemoteIP,
        RDP_LocalIP   = LocalIP,
        RDP_Direction,
        ActionType;

// ===== 2. SUSPICIOUS PROCESS ACTIVITY IN RDP SESSIONS =====
let SuspiciousRDPProcesses =
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    // Processes that ran in a remote (RDP) session
    | where IsInitiatingProcessRemoteSession == true
    | extend RDP_SessionIP = tostring(InitiatingProcessRemoteSessionIP)
    // Credential dumping from RDP session
    | extend IsRDPCredentialDump =
        iif(FileName =~ "mimikatz.exe"
            or ProcessCommandLine has "sekurlsa::logonpasswords"
            or (ProcessCommandLine has "lsass" and FileName in~ ("procdump.exe","sqldumper.exe")),
            1, 0)
    // Recon / situational awareness via RDP
    | extend IsRDPRecon =
        iif(ProcessCommandLine has_any ("net user","net group","net localgroup","quser","qwinsta")
            or ProcessCommandLine has_any ("whoami /groups","whoami /priv","systeminfo"),
            1, 0)
    // Lateral tool transfer / remote tool execution
    | extend IsRDPToolTransfer =
        iif(FileName in~ ("psexec.exe","wmic.exe","sc.exe")
            and ProcessCommandLine has_any ("\\\\"," create "," start "),
            1, 0)
    // Persistence establishment from RDP
    | extend IsRDPPersistence =
        iif(ProcessCommandLine has_any ("schtasks"," at ","wmic ")
            and ProcessCommandLine has_any (" /create "," create "," start ")
            and ProcessCommandLine contains ".exe",
            1, 0)
    | project
        ProcTime      = Timestamp,
        DeviceId,
        DeviceName,
        RDP_SessionIP,
        FileName,
        ProcessCommandLine,
        IsRDPCredentialDump,
        IsRDPRecon,
        IsRDPToolTransfer,
        IsRDPPersistence;

// ===== 3. CORRELATE RDP SESSIONS WITH SUSPICIOUS ACTIVITY =====
RDPSessions
| join kind=inner SuspiciousRDPProcesses on DeviceId
// Activity must occur within 30 minutes of the RDP session
| where ProcTime between (RDPTime .. RDPTime + 30m)

// ===== 4. CONFIDENCE SCORING =====
| extend ConfidenceScore = case(
    IsRDPCredentialDump == 1,                         10,  // CRITICAL: RDP + LSASS/credential dumping
    IsRDPPersistence == 1 or IsRDPToolTransfer == 1,  9,   // HIGH: persistence or lateral tool transfer via RDP
    IsRDPRecon == 1 and RDP_Direction == "Inbound",   8,   // MED-HIGH: recon on inbound RDP
    IsRDPRecon == 1,                                  7,   // MED: recon from any RDP session
    5                                                      // LOW: any suspicious RDP-session process
)

// ===== 5. THREAT CONTEXT & MITRE MAPPING =====
| extend ThreatContext = case(
    ConfidenceScore == 10, "Credential dumping from within an RDP session – likely preparing for wider lateral movement.",
    ConfidenceScore == 9,  "Persistence or lateral movement tooling executed via RDP (scheduled tasks, psexec/wmic/sc).",
    ConfidenceScore == 8,  "Discovery and reconnaissance commands run inside an inbound RDP session.",
    ConfidenceScore == 7,  "Reconnaissance commands executed within an RDP session.",
    "Suspicious process execution in an active RDP session."
)
| extend MITRE_Techniques = case(
    IsRDPCredentialDump == 1, "T1003.001 (LSASS Dumping), T1021.001 (RDP)",
    IsRDPPersistence == 1,    "T1053.005 (Scheduled Task), T1021.001 (RDP)",
    IsRDPToolTransfer == 1,   "T1570 (Lateral Tool Transfer), T1021.001 (RDP)",
    IsRDPRecon == 1,          "T1018 (Remote System Discovery), T1021.001 (RDP)",
    "T1021.001 (Remote Desktop Protocol)"
)

// ===== 6. SEVERITY & HUNTING DIRECTIVES =====
| extend Severity = case(
    ConfidenceScore >= 9, "High",
    ConfidenceScore >= 7, "Medium",
    "Low"
)
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; RDPDirection=", RDP_Direction,
    "; SessionIP=", coalesce(RDP_SessionIP, RDP_RemoteIP),
    "; Device=", DeviceName,
    "; SuspiciousProcess=", FileName,
    "; CoreContext=", ThreatContext,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Confirm whether the RDP session is expected. Immediately review full process tree and user context. Pivot to DeviceLogonEvents for interactive logons, check for LSASS access, outbound lateral connections and new persistence. If activity is not explicitly authorised, terminate any active RDP sessions, reset affected credentials, and block the source IP.",
        Severity == "Medium",
            "Validate whether this RDP session and associated commands are part of legitimate admin activity. Pivot around DeviceNetworkEvents for subsequent SMB/WinRM connections and DeviceProcessEvents for tool execution. Consider temporary network blocks or session termination if behaviour is suspicious.",
        "Baseline behaviour for this host/user if legitimate remote admin activity is confirmed. Keep as a hunting signal and correlate with other alerts for escalation."
    )
)

// ===== 7. FINAL PROJECTION =====
| where ConfidenceScore >= 7    // Focus on Medium and High
| project
    RDP_StartTime   = RDPTime,
    ProcTime,
    DeviceName,
    RDP_Direction,
    RDP_SourceIP    = coalesce(RDP_SessionIP, RDP_RemoteIP),
    SuspiciousProcess = FileName,
    ProcessCommandLine,
    ThreatContext,
    MITRE_Techniques,
    ConfidenceScore,
    Severity,
    HuntingDirectives
| order by ConfidenceScore desc, ProcTime desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
