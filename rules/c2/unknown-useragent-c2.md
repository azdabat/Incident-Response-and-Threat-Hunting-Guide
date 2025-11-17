# Unknown or Rare User-Agent C2 – L3 Native Detection Rule

## Threat Focus

Unknown or Rare User-Agent C2 is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: c2
- MITRE: T1071

## Advanced Hunting Query (MDE / Sentinel)

```kql
// Unknown or Rare User-Agent C2 — L3 Native
// Author: Ala Dabat | 2025-11

let lookback = 7d;
let min_ua_count = 5;
let min_conf = 85;

let UserApps = dynamic([
    "chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe",
    "outlook.exe","teams.exe","slack.exe","zoom.exe","onedrive.exe","dropbox.exe"
]);

let SuspiciousLaunchers = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe",
    "python.exe","perl.exe","ruby.exe","java.exe",
    "rundll32.exe","mshta.exe","regsvr32.exe",
    "wscript.exe","cscript.exe","curl.exe","wget.exe",
    "bitsadmin.exe","rclone.exe","ssh.exe","plink.exe"
]);

let UAIndicators = dynamic([
    "Go-http-client","Python-urllib","Java","curl","Wget",
    "bot","agent","implant","beacon","stage","loader","update-check","custom"
]);

// Stage 1 — raw UA data
let Raw =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemotePort in (80,443,8080,8443)
| where isnotempty(UserAgent)
| extend Proc = InitiatingProcessFileName,
         ProcCL = InitiatingProcessCommandLine,
         ParentProc = InitiatingProcessParentFileName,
         Account = InitiatingProcessAccountName
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          UserAgent, Proc, ProcCL, ParentProc, Account;

// Stage 2 — UA rarity
let UAStats =
Raw
| summarize UA_GlobalCount = count(), DistinctHosts = dcount(DeviceName) by UserAgent;

// Stage 3 — join rarity + classify
let Enriched =
Raw
| join kind=inner UAStats on UserAgent
| extend IsRareUA = UA_GlobalCount < min_ua_count,
         HasC2Pattern = UserAgent has_any (UAIndicators),
         IsSuspiciousLauncher = Proc in (SuspiciousLaunchers),
         IsUserApp = Proc in (UserApps),
         UA_Length = strlen(UserAgent),
         UA_Entropy = strlen(split(UserAgent,";"));    // simple complexity marker

// Stage 4 — scoring
let Scored =
Enriched
| extend Base = 70
| extend Score =
      Base
      + iif(IsRareUA, 15, 0)
      + iif(HasC2Pattern, 10, 0)
      + iif(IsSuspiciousLauncher, 10, 0)
      - iif(IsUserApp, 15, 0)
      + iif(UA_Length < 20, 5, 0)
      + iif(UA_Length > 180, 5, 0)
      + iif(UA_Entropy <= 2, 5, 0)
      + iif(UA_Entropy >= 6, 5, 0)
| extend Severity = case(
      Score >= 95, "High",
      Score >= 85, "Medium",
      "Low"
)
| extend MITRE_Tactics = "TA0011 (Command & Control)",
         MITRE_Techniques = "T1071 (HTTP/S User-Agent C2)";

// Stage 5 — directives
Scored
| extend Directives = strcat(
      "Severity=", Severity,
      "; Host=", DeviceName,
      "; Proc=", Proc,
      "; Parent=", ParentProc,
      "; UserAgent=", UserAgent,
      "; RareUA=", tostring(IsRareUA),
      "; Score=", tostring(Score),
      "; Next=",
      case(
          Severity == "High",
              "Likely custom UA beacon. Review process tree, signer, hash. Pivot on RemoteIP and UA across estate. Consider isolation and memory capture.",
          Severity == "Medium",
              "Check if UA belongs to internal or custom app. If not baselined, escalate and pivot to similar UAs.",
          "Hunting signal. Baselining required."
      )
)

// Final output
| project Timestamp, DeviceName, Account, Proc, ParentProc,
          RemoteIP, RemotePort, RemoteUrl,
          UserAgent, UA_GlobalCount,
          IsRareUA, HasC2Pattern, IsSuspiciousLauncher,
          UA_Length, UA_Entropy,
          Score, Severity,
          MITRE_Tactics, MITRE_Techniques, Directives
| where Score >= min_conf
| order by Score desc, Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
