# RDP Lateral Movement – L3 Native Detection Rule

## Threat Focus

RDP Lateral Movement is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: lateral-movement
- MITRE: T1021.001

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ==========================================================================
//  Advanced RDP Lateral Movement & Credential Abuse – L3 Detection
//  Author: Ala Dabat (Alstrum) — 2025 Native Endpoint/Identity Pack
//  Purpose: Detect multi-stage RDP abuse: recon, LSASS dumping, DCSync prep,
//           tool transfer, persistence, and post-login pivots.
//  MITRE: T1021.001 (RDP), T1003.001 (LSASS), T1003.006 (DCSync),
//         T1053.005 (Scheduled Tasks), T1570 (Tool Transfer), T1018 (Discovery)
// ==========================================================================

let lookback = 7d;

// Optional tuning for legitimate admin hosts
let KnownAdminSubnets = dynamic(["10.0.0.", "192.168.1."]);  

// ---------------------------------------------------------------------------
// 1. RDP SESSION DETECTION (Network-layer truth)
// ---------------------------------------------------------------------------
let RDPSessions =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort == 3389 or LocalPort == 3389
| where ActionType in ("ConnectionSuccess","InboundConnectionAccepted")
| extend RDP_Direction = iff(RemotePort == 3389, "Outbound", "Inbound")
| extend RDP_SourceIP  = iff(RDP_Direction == "Outbound", RemoteIP, LocalIP)
| project RDPTime      = Timestamp,
          DeviceId,
          DeviceName,
          RDP_SourceIP,
          RDP_Direction,
          ActionType;

// ---------------------------------------------------------------------------
// 2. SUSPICIOUS BEHAVIOUR EXECUTED *INSIDE* AN RDP SESSION
// ---------------------------------------------------------------------------
let RDPProc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where IsInitiatingProcessRemoteSession == true  // TRUE RDP-bound process
| extend RDP_SessionIP = tostring(InitiatingProcessRemoteSessionIP)
| extend Cmd = tostring(ProcessCommandLine)
| extend Proc = FileName

// Credential dumping (LSASS → procdump, mimikatz, sqldumper)
| extend IsLSASSDump =
      (Proc in~ ("mimikatz.exe","procdump.exe","procdump64.exe","dumpert.exe"))
      or (Cmd has "sekurlsa::")
      or (Cmd has "lsass" and Proc in~ ("procdump.exe","sqldumper.exe"))

// DCSync prep (rare but happens inside RDP sessions)
| extend IsDCSyncPrep =
      Cmd has_any ("dcsync","GetNCChanges","lsadump","DirectoryServices")

// Recon
| extend IsRecon =
      Cmd has_any ("net user","net group","quser","qwinsta","whoami","systeminfo")

// Lateral movement tooling
| extend IsToolTransfer =
      (Proc in~ ("psexec.exe","wmic.exe","sc.exe"))
      and Cmd has @"\\"

// Persistence
| extend IsPersistence =
      Cmd has_any ("schtasks"," /create ","registry","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")

// Remote file operations common after RDP compromise
| extend IsFilePull =
      Cmd has_any ("copy \\\\", "move \\\\", "robocopy \\\\")

| project ProcTime = Timestamp,
          DeviceId, DeviceName, RDP_SessionIP,
          Proc, Cmd,
          IsLSASSDump, IsDCSyncPrep,
          IsRecon, IsToolTransfer,
          IsPersistence, IsFilePull;

// ---------------------------------------------------------------------------
// 3. CORRELATE SUSPICIOUS ACTIVITY WITH ACTIVE RDP SESSION
// ---------------------------------------------------------------------------
RDPSessions
| join kind=inner RDPProc on DeviceId
| where ProcTime between (RDPTime .. RDPTime + 45m)   // wider window for realistic RDP abuse

// ---------------------------------------------------------------------------
// 4. BEHAVIOUR → SEVERITY (No scoring requirement, L3 logic)
// ---------------------------------------------------------------------------
| extend Severity = case(
      IsLSASSDump == 1 or IsDCSyncPrep == 1,               "High",
      IsToolTransfer == 1 or IsPersistence == 1,           "High",
      IsRecon == 1 and RDP_Direction == "Inbound",         "Medium",
      IsFilePull == 1,                                      "Medium",
      IsRecon == 1,                                         "Low",
      "Low"
)

// ---------------------------------------------------------------------------
// 5. Reasoning (Human SOC Analyst Style)
// ---------------------------------------------------------------------------
| extend Reason = strcat(
      iif(IsLSASSDump,      "LSASS/credential dumping executed inside active RDP session. ", ""),
      iif(IsDCSyncPrep,     "DCSync-related commands run via RDP. ", ""),
      iif(IsToolTransfer,   "Lateral movement tooling invoked inside RDP. ", ""),
      iif(IsPersistence,    "Persistence mechanism created from RDP session. ", ""),
      iif(IsFilePull,       "Remote copy/move operations observed. ", ""),
      iif(IsRecon,          "Reconnaissance commands executed inside RDP session. ", ""),
      "RDP direction: ", RDP_Direction, ". "
)

// ---------------------------------------------------------------------------
// 6. L3 Hunting Directives (human-written, actionable)
// ---------------------------------------------------------------------------
| extend HuntingDirectives = strcat(
      "Severity=", Severity,
      "; Device=", DeviceName,
      "; SourceIP=", RDP_SourceIP,
      "; ObservedProcess=", Proc,
      "; Reason=", Reason,
      "; NextSteps=",
      case(
          Severity == "High",
              "Treat as probable RDP compromise. Validate whether the session was expected. Pull full process tree, check for LSASS access, persistence artefacts, tool transfer, outbound SMB/WMI, and new scheduled tasks. Consider isolating host and resetting credentials.",
          Severity == "Medium",
              "Validate operator legitimacy. Review session origin, command-line intent, file access, and SMB/WMI pivots. Check for escalation behaviours.",
          "Likely benign admin activity if justified — retain for hunting, correlate with other detections."
      )
)

// ---------------------------------------------------------------------------
| where Severity in ("High","Medium")
| project RDPTime, ProcTime,
          DeviceName, RDP_Direction, RDP_SourceIP,
          Proc, Cmd,
          Reason, Severity, HuntingDirectives
| order by Severity desc, ProcTime desc


```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
