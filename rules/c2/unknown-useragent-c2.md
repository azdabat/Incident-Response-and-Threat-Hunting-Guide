# Unknown or Rare User-Agent C2 – L3 Native Detection Rule

## Threat Focus

Unknown or Rare User-Agent C2 is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: c2
- MITRE: T1071

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ===================================================================
// Unknown or Rare User-Agent C2 — L3 Native Detection Rule
// Author: Ala Dabat (Alstrum)
// Version: 2025-11
// Category: C2
// MITRE: T1071 (Application Layer Protocol), TA0011 (Command & Control)
// Purpose: Detect rare / unknown / custom User-Agent headers typically
//          used by HTTP(S) backdoors, implants, and loaders.
// Note: Pure native telemetry — no external TI lists.
// ===================================================================

// -------------------- Tunables --------------------
let lookback = 7d;
let min_occurrences_threshold = 5;       // Rare UAs occur < 5 times globally
let min_confidence = 85;                 // Medium+ by default

// Known legitimate "browsing" processes — penalised in scoring
let UserAppProcesses = dynamic([
    "chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe",
    "outlook.exe","teams.exe","slack.exe","zoom.exe",
    "onedrive.exe","dropbox.exe"
]);

// Suspicious LOLBIN / loaders / C2 launchers — boost scoring
let SuspiciousLaunchers = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe",
    "python.exe","perl.exe","ruby.exe","java.exe","rundll32.exe",
    "mshta.exe","regsvr32.exe","wscript.exe","cscript.exe",
    "curl.exe","wget.exe","bitsadmin.exe",
    "rclone.exe","ssh.exe","plink.exe"
]);

// Patterns associated with custom C2 User-Agents
let C2UserAgentIndicators = dynamic([
    "Go-http-client","Python-urllib","Java","curl",
    "Wget","bot","agent","implant","beacon",
    "stage","loader","update-check","custom"
]);

// -------------------- Stage 1: Extract User-Agent telemetry --------------------
let RawUA =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemotePort in (80,443,8080,8443)
| where isnotempty(UserAgent)
// Keep full process attribution
| extend
    Proc       = InitiatingProcessFileName,
    ProcCL     = InitiatingProcessCommandLine,
    ParentProc = InitiatingProcessParentFileName,
    Account    = InitiatingProcessAccountName
| project
    Timestamp, DeviceId, DeviceName,
    RemoteIP, RemotePort, RemoteUrl, Protocol,
    UserAgent,
    Proc, ProcCL, ParentProc, Account;

// -------------------- Stage 2: Global UA rarity score --------------------
let UserAgentStats =
RawUA
| summarize UA_GlobalCount = count(), DistinctHosts = dcount(DeviceName)
  by UserAgent;

// -------------------- Stage 3: Join UA rarity back to raw data --------------------
let Enriched =
RawUA
| join kind=inner UserAgentStats on UserAgent
| extend
    IsRareUserAgent = iif(UA_GlobalCount < min_occurrences_threshold, 1, 0),
    HasC2Pattern    = iif(UserAgent has_any (C2UserAgentIndicators), 1, 0),
    IsSuspiciousLauncher = iif(Proc in (SuspiciousLaunchers), 1, 0),
    IsUserFacingApp = iif(Proc in (UserAppProcesses), 1, 0),
    UA_Length = strlen(UserAgent),
    UA_Entropy = strlen(split(UserAgent, ";"))       // basic weirdness marker
;

// -------------------- Stage 4: Behavioural scoring (native-only) --------------------
let Scored =
Enriched
| extend BaseScore = 70
| extend ConfidenceScore =
    BaseScore
    + iif(IsRareUserAgent == 1, 15, 0)             // truly unknown UA
    + iif(HasC2Pattern == 1, 10, 0)                // C2-like markers
    + iif(IsSuspiciousLauncher == 1, 10, 0)        // launched from LOLBIN/tool
    - iif(IsUserFacingApp == 1, 15, 0)             // browsers → suppress
    + iif(UA_Length < 20, 5, 0)                    // unusually short UA = common in implants
    + iif(UA_Length > 180, 5, 0)                   // overlong UA = obfuscation
    + iif(UA_Entropy <= 2, 5, 0)                   // too simple (bot-like)
    + iif(UA_Entropy >= 6, 5, 0)                   // too complex (custom encoding)
;

// -------------------- Severity & MITRE --------------------
let Final =
Scored
| extend Severity = case(
        ConfidenceScore >= 95, "High",
        ConfidenceScore >= 85, "Medium",
        "Low"
    ),
    MITRE_Tactics = "TA0011 (Command & Control)",
    MITRE_Techniques = "T1071 (HTTP/S User-Agent C2)";

// -------------------- Hunter Directives --------------------
Final
| extend ThreatHunterDirectives = strcat(
    "Severity=", Severity,
    "; Host=", DeviceName,
    "; Process=", Proc,
    "; Parent=", ParentProc,
    "; RareUA=", tostring(IsRareUserAgent),
    "; UserAgent=", UserAgent,
    "; Confidence=", tostring(ConfidenceScore),
    "; RecommendedNextSteps=",
        case(
            Severity == "High",
                "Likely custom HTTP/S implant with rare User-Agent. Investigate process lineage, review binary signer/hash, isolate host, pivot on RemoteIP and UA across environment, and capture memory if possible.",
            Severity == "Medium",
                "Validate business context. Check whether the UA belongs to an update agent or custom application. If not baseline-approved, escalate and pivot to similar UAs across hosts.",
            "Hunting-only signal. Baseline your environment and tune out known-good rare UAs from internal apps."
        )
)

// -------------------- Final Output --------------------
| project
    Timestamp,
    DeviceName,
    Account,
    Proc,
    ParentProc,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    UserAgent,
    UA_GlobalCount,
    IsRareUserAgent,
    HasC2Pattern,
    IsSuspiciousLauncher,
    UA_Length,
    UA_Entropy,
    ConfidenceScore,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    ThreatHunterDirectives
| where ConfidenceScore >= min_confidence
| order by ConfidenceScore desc, Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
