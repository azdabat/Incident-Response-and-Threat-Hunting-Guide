# Long-Lived External Sessions (Implant-like) – L3 Native Detection Rule

## Threat Focus

Long-Lived External Sessions (Implant-like) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: c2
- MITRE: T1071

## Advanced Hunting Query (MDE / Sentinel)

```kql
// Long-Lived External Sessions (C2-like) — L3 Native
// Author: Ala Dabat (Alstrum) | 2025-11

let lookback = 7d;
let min_events = 20;
let min_duration = 60;
let min_conf = 85;

let UserApps = dynamic([
    "chrome.exe","msedge.exe","firefox.exe","opera.exe","brave.exe",
    "outlook.exe","teams.exe","slack.exe","zoom.exe","discord.exe","onedrive.exe"
]);

let SuspiciousLaunchers = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe",
    "rundll32.exe","regsvr32.exe","mshta.exe","bitsadmin.exe","certutil.exe",
    "curl.exe","wget.exe","python.exe","perl.exe","rclone.exe","ssh.exe","plink.exe"
]);

let C2Ports = dynamic([80,443,8080,8443,8000,8008,53,587,993,995]);

// Stage 1
let Raw =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where isnotempty(InitiatingProcessFileName)
| extend OffHours = iif(hour(Timestamp) < 8 or hour(Timestamp) >= 18, 1, 0)
| project Timestamp, DeviceId, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, OffHours;

// Stage 2 — session aggregation
let Sess =
Raw
| summarize
      FirstSeen=min(Timestamp),
      LastSeen=max(Timestamp),
      EventCount=count(),
      DaysActive=dcount(format_datetime(Timestamp,"yyyy-MM-dd")),
      OffHoursEvents=sum(OffHours),
      DistinctPorts=dcount(RemotePort),
      RemoteUrl=any(RemoteUrl)
  by DeviceId, DeviceName, InitiatingProcessFileName,
     InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP
| extend Duration = datetime_diff("minute", LastSeen, FirstSeen),
         OffHoursRatio = todouble(OffHoursEvents) / todouble(EventCount)
| where EventCount >= min_events
  and Duration >= min_duration;

// Stage 3 — beacon timing
let Beacon =
Raw
| sort by DeviceId, InitiatingProcessFileName, RemoteIP, Timestamp asc
| extend PrevT=prev(Timestamp), PrevD=prev(DeviceId),
         PrevP=prev(InitiatingProcessFileName), PrevIP=prev(RemoteIP)
| where DeviceId == PrevD
      and InitiatingProcessFileName == PrevP
      and RemoteIP == PrevIP
| extend DeltaSec = datetime_diff("second", Timestamp, PrevT)
| where DeltaSec > 0
| summarize AvgDelta=avg(DeltaSec), StdDelta=stdev(DeltaSec), Samples=count()
  by DeviceId, InitiatingProcessFileName, RemoteIP;

// Stage 4 — scoring
Sess
| join kind=leftouter Beacon
  on DeviceId, InitiatingProcessFileName, RemoteIP
| extend
    IsUserApp = InitiatingProcessFileName in (UserApps),
    IsSuspiciousLauncher = InitiatingProcessFileName in (SuspiciousLaunchers),
    IsC2Port = RemotePort in (C2Ports),
    IsBeacon = Samples >= 5
               and AvgDelta between (30.0 .. 3600.0)
               and StdDelta <= AvgDelta * 0.5
| extend Score =
      70
      + iif(Duration >= 720, 10, 0)
      + iif(Duration >= 1440, 5, 0)
      + iif(DaysActive >= 2, 10, 0)
      + iif(DaysActive >= 4, 5, 0)
      + iif(EventCount >= min_events*2, 5, 0)
      + iif(DistinctPorts == 1, 5, 0)
      + iif(OffHoursRatio >= 0.5, 10, 0)
      + iif(IsSuspiciousLauncher, 10, 0)
      - iif(IsUserApp, 10, 0)
      + iif(IsBeacon, 10, 0)
      + iif(IsC2Port, 5, 0)
| extend Severity = case(
      Score >= 95, "High",
      Score >= 85, "Medium",
      "Low"
)
| extend MITRE_Tactics = "TA0011 (Command and Control)",
         MITRE_Techniques = "T1071 (Application Layer Protocol)"
| extend Directives = strcat(
      "Severity=", Severity,
      "; Host=", DeviceName,
      "; Account=", InitiatingProcessAccountName,
      "; Proc=", InitiatingProcessFileName,
      "; RemoteIP=", RemoteIP,
      "; Port=", tostring(RemotePort),
      "; DurationMin=", tostring(Duration),
      "; DaysActive=", tostring(DaysActive)
)
| project FirstSeen, LastSeen,
          Host=DeviceName,
          Account=InitiatingProcessAccountName,
          Process=InitiatingProcessFileName,
          ProcessCommandLine=InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl,
          Duration, DaysActive, EventCount,
          OffHoursRatio, DistinctPorts,
          AvgDelta, StdDelta,
          IsUserApp, IsSuspiciousLauncher, IsBeacon,
          Score, Severity,
          MITRE_Tactics, MITRE_Techniques,
          Directives
| where Score >= min_conf
| order by Score desc, Duration desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
