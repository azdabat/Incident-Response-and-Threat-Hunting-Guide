# Unknown or Rare User-Agent C2 – L3 Native Detection Rule

## Threat Focus

Unknown or Rare User-Agent C2 is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: c2
- MITRE: T1071

## Advanced Hunting Query (MDE / Sentinel)

```kql
// Unknown or Rare User-Agent C2 — Sentinel / CloudAppEvents
// Source: CloudAppEvents (Microsoft Defender for Cloud Apps)
// Author: Ala Dabat | 2025-11

let lookback   = 7d;
let min_ua_cnt = 5;
let min_conf   = 85;

// Substrings commonly seen in custom C2 / tooling User-Agents
let UAIndicators = dynamic([
    "Go-http-client","Python-urllib","Java","curl","Wget",
    "bot","agent","implant","beacon","stage","loader","update-check","custom"
]);

// -------------------------------------------------------------------
// Stage 1 — Raw events with User-Agent
// -------------------------------------------------------------------
let Raw =
CloudAppEvents
| where TimeGenerated >= ago(lookback)
| where isnotempty(UserAgent)
| extend
    EventTime       = TimeGenerated,
    UserAgentString = UserAgent,
    UserAccount     = coalesce(AccountDisplayName, AccountId, AccountObjectId),
    ClientIP        = IPAddress,
    CloudApp        = Application,
    Country         = CountryCode,
    CityName        = City,
    ISPName         = ISP,
    OSPlatformName  = OSPlatform
| project
    EventTime,
    UserAccount,
    ClientIP,
    CloudApp,
    UserAgentString,
    Country,
    CityName,
    ISPName,
    OSPlatformName;

// -------------------------------------------------------------------
// Stage 2 — UA rarity across the tenant
// -------------------------------------------------------------------
let UAStats =
Raw
| summarize
      UA_GlobalCount  = count(),
      DistinctAccounts = dcount(UserAccount),
      DistinctIPs      = dcount(ClientIP)
  by UserAgentString;

// -------------------------------------------------------------------
// Stage 3 — Join + classify
// -------------------------------------------------------------------
let Enriched =
Raw
| join kind=inner UAStats on UserAgentString
| extend
    IsRareUA           = UA_GlobalCount < min_ua_cnt,
    UA_HasC2Indicators = UserAgentString has_any (UAIndicators),
    UA_Length          = strlen(UserAgentString),
    UA_TokenCount      = array_length(split(UserAgentString," "));   // rough complexity marker

// -------------------------------------------------------------------
// Stage 4 — Behavioural scoring
// -------------------------------------------------------------------
let Scored =
Enriched
| extend BaseScore = 70
| extend Score =
      BaseScore
      + iif(IsRareUA,           15, 0)   // never/rarely seen UA in tenant
      + iif(UA_HasC2Indicators, 10, 0)   // contains classic tool / implant markers
      + iif(UA_Length < 20,      5, 0)   // suspiciously short UA
      + iif(UA_Length > 180,     5, 0)   // overly long UA (stuffed)
      + iif(UA_TokenCount <= 2,  5, 0)   // very simple UA structure
      + iif(UA_TokenCount >= 6,  5, 0);  // very complex UA structure

// Map score → severity
Scored
| extend Severity =
      case(
          Score >= 95, "High",
          Score >= 85, "Medium",
          "Low"
      )
| extend
    MITRE_Tactics   = "TA0011 (Command and Control)",
    MITRE_Techniques= "T1071.001 (Web Protocols)"

// -------------------------------------------------------------------
// Stage 5 — Human directives for the analyst
// -------------------------------------------------------------------
| extend AnalystNotes = strcat(
      "Severity=", Severity,
      "; UserAccount=", coalesce(UserAccount, "<none>"),
      "; ClientIP=", tostring(ClientIP),
      "; CloudApp=", tostring(CloudApp),
      "; UserAgent=", UserAgentString,
      "; RareUA=", tostring(IsRareUA),
      "; UAIndicators=", tostring(UA_HasC2Indicators),
      "; UA_GlobalCount=", tostring(UA_GlobalCount),
      "; DistinctAccounts=", tostring(DistinctAccounts),
      "; DistinctIPs=", tostring(DistinctIPs),
      "; Score=", tostring(Score),
      "; RecommendedAction=",
      case(
          Severity == "High",
              "Likely custom or tool-based User-Agent. Check if this UA is expected for this app/user/IP. Pivot on UserAgentString and ClientIP across all logs. If unknown, raise an incident, investigate upstream proxy logs and consider containment.",
          Severity == "Medium",
              "User-Agent not commonly seen. Validate with app owners or developers. If not recognised, escalate and hunt for similar UAs over a wider time window.",
          "Weak but interesting hunting signal. Consider baselining or adding to an allowlist if benign."
      )
)

// Final output
| where Score >= min_conf
| project
    EventTime,
    UserAccount,
    ClientIP,
    CloudApp,
    Country,
    CityName,
    ISPName,
    OSPlatformName,
    UserAgentString,
    UA_GlobalCount,
    DistinctAccounts,
    DistinctIPs,
    IsRareUA,
    UA_HasC2Indicators,
    UA_Length,
    UA_TokenCount,
    Score,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    AnalystNotes
| order by Score desc, EventTime desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
