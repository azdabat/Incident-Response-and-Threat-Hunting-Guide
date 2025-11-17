# Suspicious 443 Beacon Patterns – L3 Native Detection Rule

## Threat Focus

Suspicious 443 Beacon Patterns is detected using pure native telemetry (no external TI) at L3 fidelity.

Classic HTTPS C2 beacons (Cobalt Strike / Sliver / Havoc etc.) calling home every N seconds/minutes from non-browser processes over 443, especially off-hours. 
Security Boulevard
Long-lived HTTPS tunnels (reverse shells / SOCKS over 443) fronted by powershell.exe, rundll32.exe, custom Go binaries, etc.
“Silent” service beacons that keep running when the user logs off, same dest IP, multi-day pattern. 
- Category: c2
- MITRE: T1071.001

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ===================================================================
// Suspicious 443 Beacon Patterns — L3 Native
// Author: Ala Dabat  | Version: 2025-11
// Platform: Microsoft Sentinel / MDE Advanced Hunting
// Category: c2
// Purpose: Detect HTTPS (443) beacon-like C2 traffic using only
//          native telemetry (no external TI).
// MITRE: T1071.001 (Web Protocols), TA0011 (Command & Control)
// ===================================================================

// -------------------- Tunables --------------------
let lookback = 7d;
let min_events_per_pair = 12;          // minimum connections per (host, proc, dest)
let min_duration_minutes = 30;         // minimum lifespan of relationship
let min_confidence = 85;               // Medium+ by default

// Common user-facing apps (likely legit 443 usage → penalise score)
let UserAppProcesses = dynamic([
    "chrome.exe","msedge.exe","iexplore.exe","firefox.exe","opera.exe","brave.exe",
    "outlook.exe","thunderbird.exe",
    "teams.exe","lync.exe","slack.exe","zoom.exe","discord.exe","whatsapp.exe",
    "onedrive.exe","dropbox.exe","steam.exe","epicgameslauncher.exe","spotify.exe"
]);

// LOLBIN / launchers often abused to front C2 beacons
let SuspiciousLauncherProcs = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe",
    "wscript.exe","cscript.exe",
    "rundll32.exe","regsvr32.exe","mshta.exe",
    "bitsadmin.exe","certutil.exe",
    "curl.exe","wget.exe",
    "python.exe","perl.exe","ruby.exe","rclone.exe",
    "ssh.exe","plink.exe"
]);

// -------------------- Stage 1: Raw 443 outbound connections --------------------
let Raw443 =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 443
// external / public only (tune if you proxy 443 internally)
| where RemoteIPType == "Public"
// only flows with a process
| where isnotempty(InitiatingProcessFileName)
| extend
    IsOffHours = iif(hour(Timestamp) < 8 or hour(Timestamp) >= 18, 1, 0)
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

// -------------------- Stage 2: Session-level aggregation per (host, proc, dest) --------------------
let SessionAgg =
Raw443
| summarize
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp),
    EventCount = count(),
    DaysActive = dcount(format_datetime(Timestamp, "yyyy-MM-dd")),
    OffHoursEvents = sum(IsOffHours),
    AnyRemoteUrl = any(RemoteUrl)
  by DeviceId,
     DeviceName,
     InitiatingProcessFileName,
     InitiatingProcessCommandLine,
     InitiatingProcessAccountName,
     RemoteIP,
     RemotePort
| extend
    DurationMinutes = datetime_diff("minute", LastSeen, FirstSeen),
    OffHoursRatio = iff(EventCount == 0, real(0),
                        todouble(OffHoursEvents) / todouble(EventCount))
| where EventCount >= min_events_per_pair
  and DurationMinutes >= min_duration_minutes;

// -------------------- Stage 3: Beacon timing (delta between connections) --------------------
let BeaconTiming =
Raw443
| sort by DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP, Timestamp asc
| extend
    PrevTime   = prev(Timestamp),
    PrevDevId  = prev(DeviceId),
    PrevDevice = prev(DeviceName),
    PrevProc   = prev(InitiatingProcessFileName),
    PrevIP     = prev(RemoteIP)
// only calculate deltas within same (host, proc, dest)
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

// -------------------- Stage 4: Join & behavioural scoring --------------------
SessionAgg
| join kind=leftouter (
    BeaconTiming
) on DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP

| extend
    IsUserFacingApp       = iif(InitiatingProcessFileName in (UserAppProcesses), 1, 0),
    IsSuspiciousLauncher  = iif(InitiatingProcessFileName in (SuspiciousLauncherProcs), 1, 0),
    // Simple beacon heuristic: reasonably consistent timing in a “beacon-y” range
    IsBeaconLikeTiming    = iif(
        Samples >= 5
        and AvgDeltaSeconds between (30.0 .. 3600.0) // every 30s–60min
        and StdDeltaSeconds <= AvgDeltaSeconds * 0.4, // low-ish jitter
        1, 0
    )

// Base behaviour score (no TI)
| extend BaseScore = 70
| extend ConfidenceScore =
    BaseScore
    // longevity / persistence
    + iif(DurationMinutes >= 60, 10, 0)          // ≥ 1h
    + iif(DurationMinutes >= 6 * 60, 5, 0)       // ≥ 6h
    + iif(DurationMinutes >= 24 * 60, 5, 0)      // ≥ 24h
    + iif(DaysActive >= 2, 5, 0)
    + iif(DaysActive >= 4, 5, 0)
    // volume
    + iif(EventCount >= min_events_per_pair * 2, 5, 0)
    + iif(EventCount >= min_events_per_pair * 4, 5, 0)
    // off-hours weighting
    + iif(OffHoursRatio >= 0.5, 10, 0)
    // process context
    + iif(IsSuspiciousLauncher == 1, 15, 0)
    - iif(IsUserFacingApp == 1, 15, 0)
    // beacon timing
    + iif(IsBeaconLikeTiming == 1, 15, 0);

// -------------------- Severity & MITRE mapping --------------------
| extend Severity = case(
    ConfidenceScore >= 95, "High",
    ConfidenceScore >= 85, "Medium",
    "Low"
)
| extend
    MITRE_Tactics    = "TA0011 (Command and Control)",
    MITRE_Techniques = "T1071.001 (Web Protocols)";

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
            "Treat as likely HTTPS C2 beacon. Immediately inspect the full process tree (parent/children), verify binary path and signer, capture memory if possible, and isolate the host. Pivot to all other devices contacting this RemoteIP/URL, and request proxy/NGFW logs for payload and SNI analysis. Consider emergency egress controls for this destination.",
        Severity == "Medium",
            "Validate whether this long-lived 443 pattern is a documented business app (backup agent, updater, monitoring tool, remote support). Confirm with app owners and change records. If not clearly legitimate, escalate as suspected C2 and extend hunting for the same RemoteIP and process across the estate.",
        "Use as a hunting signal. Baseline known-good 443 beacons (e.g. monitoring agents, CDNs, corporate apps) and tune via allowlists on (Host, Proc, RemoteIP/URL) while keeping low-volume, off-hours, non-browser patterns in scope."
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
    AvgDeltaSeconds,
    StdDeltaSeconds,
    Samples,
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
