# Long-Lived External Sessions (Implant-like) – L3 Native Detection Rule

## Threat Focus

Long-Lived External Sessions (Implant-like) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: c2
- MITRE: T1071

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ===================================================================
// Long-Lived External Sessions (Implant-like) — L3 Native
// Author: Ala Dabat (Alstrum) | Version: 2025-11
// Platform: Microsoft Sentinel / MDE Advanced Hunting
// Category: c2
// Purpose: Detect long-lived / beacon-like external C2 sessions
//          from non-browser processes using native telemetry only
//          (no external TI).
// MITRE: T1071 (Application Layer Protocol), TA0011 (Command & Control)
// ===================================================================

// -------------------- Tunables --------------------
let lookback = 7d;
let min_events_per_pair = 20;          // minimum events for a candidate "session"
let min_duration_minutes = 60;         // only consider relationships lasting >= 1h
let min_confidence = 85;               // Medium+ by default

// Legitimate user-facing processes (penalty to score)
let UserAppProcesses = dynamic([
    "chrome.exe","msedge.exe","iexplore.exe","firefox.exe","opera.exe","brave.exe",
    "outlook.exe","thunderbird.exe",
    "teams.exe","lync.exe","slack.exe","zoom.exe","discord.exe","whatsapp.exe",
    "onedrive.exe","dropbox.exe","steam.exe","epicgameslauncher.exe"
]);

// LOLBIN / toolset often abused as C2 launchers
let SuspiciousLauncherProcs = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe",
    "wscript.exe","cscript.exe",
    "rundll32.exe","regsvr32.exe","mshta.exe",
    "bitsadmin.exe","certutil.exe",
    "curl.exe","wget.exe",
    "python.exe","perl.exe","rclone.exe",
    "ssh.exe","plink.exe"
]);

// Ports commonly used for C2 over app-layer protocols (T1071.*)
let C2LikePorts = dynamic([80,443,8080,8443,8000,8008,53,587,993,995]);

// -------------------- Stage 1: Raw external connections --------------------
let RawConns =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
// external only
| where not(ipv4_is_private(RemoteIP))
// focus on TCP/UDP app-layer traffic with a process
| where isnotempty(InitiatingProcessFileName)
// very noisy infra can be tuned out later (CDN, O365, etc.) via allowlists
| extend IsOffHours = iif(hour(Timestamp) < 8 or hour(Timestamp) >= 18, 1, 0)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    IsOffHours;

// -------------------- Stage 2: Session-level aggregation --------------------
let SessionAgg =
RawConns
| summarize
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp),
    EventCount = count(),
    DaysActive = dcount(format_datetime(Timestamp, "yyyy-MM-dd")),
    OffHoursEvents = sum(IsOffHours),
    DistinctRemotePorts = dcount(RemotePort),
    AnyRemoteUrl = any(RemoteUrl)
  by DeviceId, DeviceName,
     InitiatingProcessFileName,
     InitiatingProcessCommandLine,
     InitiatingProcessAccountName,
     RemoteIP
| extend DurationMinutes = datetime_diff("minute", LastSeen, FirstSeen)
| extend OffHoursRatio = iff(EventCount == 0, real(0),
                              todouble(OffHoursEvents) / todouble(EventCount))
| where EventCount >= min_events_per_pair
  and DurationMinutes >= min_duration_minutes;

// -------------------- Stage 3: Beacon-like timing statistics (optional but strong) --------------------
let BeaconTiming =
RawConns
| sort by DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP, Timestamp asc
| extend
    PrevTime   = prev(Timestamp),
    PrevDevId  = prev(DeviceId),
    PrevDevice = prev(DeviceName),
    PrevProc   = prev(InitiatingProcessFileName),
    PrevIP     = prev(RemoteIP)
// only keep deltas within the same (Device, Proc, RemoteIP) chain
| where DeviceId == PrevDevId
    and DeviceName == PrevDevice
    and InitiatingProcessFileName == PrevProc
    and RemoteIP == PrevIP
| extend DeltaSeconds = real(datetime_diff("second", Timestamp, PrevTime))
| where DeltaSeconds > 0
| summarize
    AvgDeltaSeconds = avg(DeltaSeconds),
    StdDeltaSeconds = stdev(DeltaSeconds),
    Samples = count()
  by DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP;

// -------------------- Stage 4: Join and behavioural scoring --------------------
SessionAgg
| join kind=leftouter (
    BeaconTiming
) on DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP
| extend
    IsUserFacingApp     = iif(InitiatingProcessFileName in (UserAppProcesses), 1, 0),
    IsSuspiciousLauncher = iif(InitiatingProcessFileName in (SuspiciousLauncherProcs), 1, 0),
    IsC2Port            = iif(RemotePort in (C2LikePorts), 1, 0),
    IsBeaconLikeTiming  = iif(
        Samples >= 5
        and AvgDeltaSeconds between (30.0 .. 3600.0) // beacon every 30s–60m
        and StdDeltaSeconds <= AvgDeltaSeconds * 0.5, // reasonably stable
        1, 0
    )

// Base behaviour score (no TI)
| extend BaseScore = 70
| extend ConfidenceScore =
    BaseScore
    // longevity and persistence
    + iif(DurationMinutes >= 12 * 60, 10, 0)      // >= 12h
    + iif(DurationMinutes >= 24 * 60, 5, 0)       // >= 24h
    + iif(DaysActive >= 2, 10, 0)
    + iif(DaysActive >= 4, 5, 0)
    // volume and focus
    + iif(EventCount >= min_events_per_pair * 2, 5, 0)
    + iif(DistinctRemotePorts == 1, 5, 0)         // pinned to 1 port
    // off-hours weighting
    + iif(OffHoursRatio >= 0.5, 10, 0)
    // process context
    + iif(IsSuspiciousLauncher == 1, 10, 0)
    - iif(IsUserFacingApp == 1, 10, 0)
    // beacon timing
    + iif(IsBeaconLikeTiming == 1, 10, 0)
    // extra weight for classic C2 ports
    + iif(IsC2Port == 1, 5, 0);

// -------------------- Severity & MITRE mapping --------------------
| extend Severity = case(
    ConfidenceScore >= 95, "High",
    ConfidenceScore >= 85, "Medium",
    "Low"
)
| extend MITRE_Tactics =
    "TA0011 (Command and Control)",
         MITRE_Techniques =
    "T1071 (Application Layer Protocol — HTTP(S)/DNS/Other)";

// -------------------- Threat Hunter Directives --------------------
| extend ThreatHunterDirectives = strcat(
    "Severity=", Severity,
    "; Host=", DeviceName,
    "; Account=", InitiatingProcessAccountName,
    "; Proc=", InitiatingProcessFileName,
    "; RemoteIP=", RemoteIP,
    "; RemotePort=", tostring(RemotePort),
    "; DurationMinutes=", tostring(DurationMinutes),
    "; DaysActive=", tostring(DaysActive),
    "; EventCount=", tostring(EventCount),
    "; OffHoursRatio=", tostring(OffHoursRatio),
    "; AvgDeltaSeconds=", tostring(AvgDeltaSeconds),
    "; IsBeaconLikeTiming=", tostring(IsBeaconLikeTiming),
    "; IsSuspiciousLauncher=", tostring(IsSuspiciousLauncher),
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Treat as likely C2 implant / tunnel. Immediately review full process tree for the launcher (parent/children), verify binary path and signer, capture memory if possible, and isolate the host. Pull PCAP / proxy logs around this flow, check other hosts contacting the same RemoteIP/URL, and implement temporary egress blocks while scoping the incident.",
        Severity == "Medium",
            "Validate whether this long-lived external connection and process combination is part of a documented business application (e.g. update agent, backup client, remote support tool). Confirm with asset owner and change records. If not clearly legitimate, escalate as a potential backdoor and expand hunting for the same RemoteIP and InitiatingProcessFileName across other hosts.",
        "Use as a hunting signal. Baseline known-good long-lived connections (backup agents, monitoring tools, CDNs) and tune via allowlists on Host/Proc/RemoteIP/URL while keeping low-volume, off-hours, non-browser flows under scrutiny."
    )
)

// -------------------- Final projection --------------------
| project
    FirstSeen,
    LastSeen,
    Host = DeviceName,
    Account = InitiatingProcessAccountName,
    Process = InitiatingProcessFileName,
    ProcessCommandLine = InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl = AnyRemoteUrl,
    DurationMinutes,
    DaysActive,
    EventCount,
    OffHoursRatio,
    DistinctRemotePorts,
    AvgDeltaSeconds,
    StdDeltaSeconds,
    IsUserFacingApp,
    IsSuspiciousLauncher,
    IsBeaconLikeTiming,
    ConfidenceScore,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    ThreatHunterDirectives
| where ConfidenceScore >= min_confidence
| order by ConfidenceScore desc, DurationMinutes desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
