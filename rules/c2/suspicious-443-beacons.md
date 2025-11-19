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

   // Suspicious 443 Beacon Patterns — L3 Native
// Author: Ala Dabat | 2025-11

let lookback = 7d;
let min_events = 12;
let min_duration = 30;
let min_conf = 85;

let UserApps = dynamic([
    "chrome.exe","msedge.exe","firefox.exe","opera.exe","brave.exe",
    "outlook.exe","teams.exe","slack.exe","zoom.exe","discord.exe",
    "onedrive.exe","dropbox.exe","steam.exe","spotify.exe"
]);

let SuspiciousLaunchers = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe",
    "rundll32.exe","regsvr32.exe","mshta.exe","bitsadmin.exe","certutil.exe",
    "curl.exe","wget.exe","python.exe","perl.exe","ruby.exe","rclone.exe",
    "ssh.exe","plink.exe"
]);

// -------- Stage 1: Raw outbound 443 ----------
let Raw =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 443
// Public IPv4/IPv6 filtering (MDE has no "Public" enum)
| where RemoteIP !in ("127.0.0.1")
| where RemoteIP !startswith "10."
| where RemoteIP !startswith "172.16."
| where RemoteIP !startswith "192.168."
| where isnotempty(InitiatingProcessFileName)
| extend OffHours = iif(hour(Timestamp) < 8 or hour(Timestamp) >= 18, 1, 0)
| extend RemoteDnsName = tostring(RemoteDnsName)  // safe cast, optional
| project Timestamp, DeviceId, DeviceName, RemoteIP, RemotePort,
          RemoteDnsName, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, OffHours;

// -------- Stage 2: Session-level aggregation ----------
let Sess =
Raw
| summarize
      FirstSeen=min(Timestamp),
      LastSeen=max(Timestamp),
      EventCount=count(),
      DaysActive=dcount(format_datetime(Timestamp,"yyyy-MM-dd")),
      OffHoursEvents=sum(OffHours),
      RemoteDnsName=any(RemoteDnsName)  // optional, only if exists
  by DeviceId, DeviceName, InitiatingProcessFileName,
     InitiatingProcessCommandLine, InitiatingProcessAccountName,
     RemoteIP, RemotePort
| extend Duration = datetime_diff("minute", LastSeen, FirstSeen),
         OffHoursRatio = todouble(OffHoursEvents)/todouble(EventCount)
| where EventCount >= min_events
  and Duration >= min_duration;

// -------- Stage 3: Timing deltas ----------
let Beacon =
Raw
| order by DeviceId asc, InitiatingProcessFileName asc, RemoteIP asc, Timestamp asc
| extend PrevT=prev(Timestamp), PrevD=prev(DeviceId),
         PrevP=prev(InitiatingProcessFileName), PrevIP=prev(RemoteIP)
| where DeviceId == PrevD
    and InitiatingProcessFileName == PrevP
    and RemoteIP == PrevIP
| extend DeltaSec = datetime_diff("second", Timestamp, PrevT)
| where DeltaSec > 0
| summarize AvgDelta=avg(DeltaSec), StdDelta=stdev(DeltaSec), Samples=count()
  by DeviceId, InitiatingProcessFileName, RemoteIP;

// -------- Stage 4: Scoring & Enrichment ----------
Sess
| join kind=leftouter Beacon
  on DeviceId, InitiatingProcessFileName, RemoteIP
| extend
    IsUserApp = InitiatingProcessFileName in (UserApps),
    IsSuspiciousLauncher = InitiatingProcessFileName in (SuspiciousLaunchers),
    IsBeacon = Samples >= 5
               and AvgDelta between (30.0 .. 3600.0)
               and StdDelta <= AvgDelta * 0.4
| extend Score =
      70
      + iif(Duration >= 60, 10, 0)
      + iif(Duration >= 360, 5, 0)
      + iif(Duration >= 1440, 5, 0)
      + iif(DaysActive >= 2, 5, 0)
      + iif(DaysActive >= 4, 5, 0)
      + iif(EventCount >= min_events*2, 5, 0)
      + iif(EventCount >= min_events*4, 5, 0)
      + iif(OffHoursRatio >= 0.5, 10, 0)
      + iif(IsSuspiciousLauncher, 15, 0)
      - iif(IsUserApp, 15, 0)
      + iif(IsBeacon, 15, 0)
| extend Severity = case(
      Score >= 95, "High",
      Score >= 85, "Medium",
      "Low"
)
| extend MITRE_Tactics = "TA0011 (Command and Control)",
         MITRE_Techniques = "T1071.001 (Web Protocols)"
| extend Directives = strcat(
      "Severity=", Severity,
      "; Host=", DeviceName,
      "; Account=", InitiatingProcessAccountName,
      "; Proc=", InitiatingProcessFileName,
      "; RemoteIP=", RemoteIP,
      "; Port=", tostring(RemotePort),
      "; DurationMin=", tostring(Duration),
      "; DaysActive=", tostring(DaysActive),
      "; Events=", tostring(EventCount),
      "; OffHoursRatio=", tostring(OffHoursRatio),
      "; AvgDelta=", tostring(AvgDelta),
      "; Beacon=", tostring(IsBeacon),
      "; DNS=", RemoteDnsName
)
| project FirstSeen, LastSeen,
          Host=DeviceName, Account=InitiatingProcessAccountName,
          Process=InitiatingProcessFileName,
          ProcessCommandLine=InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteDnsName,
          Duration, DaysActive,
          EventCount, OffHoursRatio, AvgDelta, StdDelta, Samples,
          IsUserApp, IsSuspiciousLauncher, IsBeacon,
          Score, Severity, MITRE_Tactics, MITRE_Techniques, Directives
| where Score >= min_conf
| order by Score desc, Duration desc


```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
