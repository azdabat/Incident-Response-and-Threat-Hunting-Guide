# Unknown or Rare User-Agent C2 – L3 Native Detection Rule

## Threat Focus

Unknown or Rare User-Agent C2 is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: c2
- MITRE: T1071

## Advanced Hunting Query (MDE / Sentinel)

```kql
// Unknown or Rare HTTPS C2 – MDE Native (Process + JA3 + SNI)
// Author: Ala Dabat | 2025-11

let Lookback = 7d;
let MinEvents = 10;

// Human-readable process allowlists
let NormalApps = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","outlook.exe","teams.exe"]);
let SuspiciousLaunchers = dynamic(["powershell.exe","pwsh.exe","cmd.exe","python.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","java.exe","curl.exe","wget.exe","rclone.exe"]);

// Stage 1: Raw HTTPS traffic
let Raw =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 443
| where isnotempty(InitiatingProcessFileName)
| extend ProcessName = InitiatingProcessFileName,
         CommandLine = InitiatingProcessCommandLine,
         ParentProcess = InitiatingProcessParentFileName,
         SNI = tostring(NetworkMessageSecurityInfo.SniHostname),
         JA3 = tostring(NetworkMessageSecurityInfo.Ja3Hash),
         OffHours = iif(hour(Timestamp) < 8 or hour(Timestamp) >= 18, 1, 0);

// Stage 2: Session aggregation
let Agg =
Raw
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EventCount=count(), UniqueDays=dcount(format_datetime(Timestamp, "yyyy-MM-dd")), OffHoursEvents=sum(OffHours), AnySNI=any(SNI), AnyJA3=any(JA3)
  by DeviceId, DeviceName, ProcessName, CommandLine, ParentProcess, RemoteIP, RemotePort
| extend DurationMinutes = datetime_diff("minute", LastSeen, FirstSeen),
         OffHoursRatio = todouble(OffHoursEvents)/toreal(EventCount)
| where EventCount >= MinEvents;

// Stage 3: Timing deltas (beaconing)
let Beacon =
Raw
| order by DeviceId asc, ProcessName asc, RemoteIP asc, Timestamp asc
| extend PrevTime = prev(Timestamp)
| where isnotempty(PrevTime)
| extend DeltaSeconds = datetime_diff("second", Timestamp, PrevTime)
| summarize AvgDelta = avg(DeltaSeconds), StdDelta = stdev(DeltaSeconds), Samples=count()
  by DeviceId, ProcessName, RemoteIP;

// Stage 4: Join + scoring
Agg
| join kind=leftouter Beacon on DeviceId, ProcessName, RemoteIP
| extend IsSuspiciousLauncher = ProcessName in (SuspiciousLaunchers),
         IsNormalLauncher = ProcessName in (NormalApps),
         LooksLikeBeacon = Samples >= 5 and AvgDelta between (30 .. 3600) and StdDelta <= AvgDelta * 0.40
| extend Score =
      70
      + iif(IsSuspiciousLauncher, 15, 0)
      - iif(IsNormalLauncher, 15, 0)
      + iif(LooksLikeBeacon, 15, 0)
      + iif(OffHoursRatio >= 0.4, 10, 0)
      + iif(DurationMinutes >= 60, 5, 0)
      + iif(DurationMinutes >= 240, 5, 0)
| extend Severity = case(Score >= 95, "High", Score >= 85, "Medium", "Low"),
         MITRE_Tech = "T1071.001 (Web Protocols)",
         MITRE_Tactic = "TA0011 (Command & Control)"
| extend AnalystNotes = strcat("Severity=",Severity,"; Device=",DeviceName,"; Process=",ProcessName,"; Parent=",ParentProcess,"; CommandLine=",CommandLine,"; RemoteIP=",RemoteIP,"; SNI=",AnySNI,"; JA3=",AnyJA3,"; AvgDelta=",AvgDelta,"; Score=",Score)
| project FirstSeen, LastSeen, DeviceName, ProcessName, ParentProcess, CommandLine, RemoteIP, AnySNI, AnyJA3, DurationMinutes, EventCount, OffHoursRatio, AvgDelta, StdDelta, Samples, LooksLikeBeacon, Score, Severity, MITRE_Tactic, MITRE_Tech, AnalystNotes
| order by Score desc, DurationMinutes desc


```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
