# Browser → LOLBIN Execution Chain – L3 Native Detection Rule

## Threat Focus

Browser → LOLBIN Execution Chain is detected using pure native telemetry (no external TI) at L3 fidelity.

Rule Logic (Annotated)

Browser → LOLBIN process correlation
Detects any LOLBIN launched directly or indirectly within 5 minutes of a browser process — common in drive-by attacks, JS droppers, weaponized HTA, malicious downloads.

LOLBIN Enumeration
Covers PowerShell, rundll32, regsvr32, mshta, script hosts, cmd, certutil, bitsadmin, msiexec.

Encoded & Base64 payload detection
Detects -enc, -encodedcommand, embedded Base64 stagers.

Download cradle detection
Flags IWR, IRM, curl/wget, Net.WebClient — typical for payload retrieval.

Suspicious download-origin execution
Execution from Downloads, Users\AppData, Temp — common malware staging locations.

LOLBIN chaining detection
Classic attacker pattern: mshta → rundll32 → powershell.

Defense evasion
Flags scripts attempting MpPreference tampering.

Weighted scoring
Browser origin + encoded payload + download cradle + LOLBIN chain = High severity.

L3 directives
Provides immediate, SOC-ready action steps: tree pivot, URL investigation, isolation, cross-alert correlation.

- Category: execution
- MITRE: T1203, T1059, T1218

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================
// Browser → LOLBIN Execution Chain – L3 Native Detection
// Author: Ala Dabat | Version: 2025-11
// Detects browser-originated process chains leading to LOLBIN execution,
// a common vector in phishing, drive-by downloads, and initial access.
// MITRE: T1203, T1059, T1218
// =====================================================

let lookback = 14d;

// -------------------------------------------
// 1. Define browser parents + LOLBIN children
// -------------------------------------------
let Browsers = dynamic([
    "chrome.exe", "msedge.exe", "firefox.exe",
    "iexplore.exe", "brave.exe", "opera.exe"
]);

let LOLBINs = dynamic([
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "cmd.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe"
]);

// -------------------------------------------
// 2. Select LOLBIN executions
// -------------------------------------------
let LolbinExec =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (LOLBINs)
| extend Cmd = tostring(ProcessCommandLine);

// -------------------------------------------
// 3. Select browser-origin executions (pivot on parents)
// -------------------------------------------
let BrowserParents =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (Browsers)
| project ParentTime = Timestamp,
          DeviceId, DeviceName,
          BrowserProc = FileName,
          BrowserCommandLine = ProcessCommandLine,
          InitiatingProcessId = ProcessId;

// -------------------------------------------
// 4. Join LOLBIN executions to browser parents
// -------------------------------------------
LolbinExec
| join kind=leftouter BrowserParents on DeviceId
| where ParentTime <= Timestamp
      and Timestamp <= ParentTime + 5m // chain window
| extend FromBrowser = iif(isnotempty(BrowserProc), 1, 0)

// -------------------------------------------
// 5. Deep behavior scoring
// -------------------------------------------

// Encoded/obfuscated payloads
| extend HasEncoded = Cmd has_any ("-enc ", "-encodedcommand", "-e ")
| extend HasBase64 = Cmd has_any ("FromBase64String", " JAB", "SQBvAHUAdA")

// Staged script execution
| extend HasIEX = Cmd has_any ("iex ", "Invoke-Expression", "Invoke-Command")

// Download cradles
| extend HasCradle =
      Cmd has_any ("iwr", "Invoke-WebRequest", "curl ", "wget ", "Invoke-RestMethod")

// Suspicious file origin (downloaded stuff)
| extend HasDownloadPath =
      FolderPath has_any (@"\Users\", @"\Downloads\", @"\AppData\", @"\Temp\")

// Secondary LOLBIN chains (rundll32 → powershell, etc.)
| extend ChildIsLOLChain =
      Cmd has_any ("javascript:", "vbscript:", "mshta", "regsvr32 /s", "rundll32")

// Defense evasion
| extend HasDefenseTamper =
      Cmd has_any ("Set-MpPreference", "DisableRealtimeMonitoring", "Add-MpPreference")

// Weighted scoring
| extend ConfidenceScore =
      0
      + iif(FromBrowser == 1, 4, 0)                                // browser to LOLBIN
      + iif(HasEncoded, 3, 0)                                      // encoded command
      + iif(HasBase64, 2, 0)                                       // base64 payload
      + iif(HasCradle, 3, 0)                                       // download cradle
      + iif(HasIEX, 3, 0)                                          // inline execution
      + iif(HasDefenseTamper, 3, 0)                                // tampering
      + iif(HasDownloadPath, 2, 0)                                 // downloaded file origin
      + iif(ChildIsLOLChain, 3, 0);                                // LOLBIN → LOLBIN chaining

// -------------------------------------------
// 6. Reason summary
// -------------------------------------------
| extend Reason = strcat(
      iif(FromBrowser == 1, "Browser-origin execution; ", ""),
      iif(HasEncoded, "Encoded payload; ", ""),
      iif(HasBase64, "Base64 payload; ", ""),
      iif(HasCradle, "Download cradle invoked; ", ""),
      iif(HasIEX, "IEX/inline execution; ", ""),
      iif(ChildIsLOLChain, "LOLBIN-to-LOLBIN chaining; ", ""),
      iif(HasDefenseTamper, "Defender tampering attempt; ", ""),
      iif(HasDownloadPath, "Suspicious download/execution directory; ", "")
)

// -------------------------------------------
// 7. Severity
// -------------------------------------------
| extend Severity = case(
      ConfidenceScore >= 12, "High",
      ConfidenceScore >= 8,  "Medium",
      ConfidenceScore >= 5,  "Low",
      "Informational"
)

// -------------------------------------------
// 8. L3 Hunting Directives
// -------------------------------------------
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Browser=", tostring(BrowserProc),
    "; LOLBIN=", FileName,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
           "Investigate full process tree. Extract downloaded file if any. Review browser history and downloads. Check for credential harvesting scripts, LSASS access, persistence creation. Isolate if malicious.",
        Severity == "Medium",
           "Review downloaded content and command-line arguments. Check email/URL origin. Inspect ±24h for related alerts.",
        Severity == "Low",
           "Baseline if known admin tools triggered it. Validate user activity.",
        "Context only."
    )
)

// -------------------------------------------
// 9. Final output
// -------------------------------------------
| project Timestamp, DeviceId, DeviceName, AccountName,
          BrowserProc, BrowserCommandLine,
          FileName, Cmd, FolderPath,
          ConfidenceScore, Severity,
          Reason, HuntingDirectives
| where ConfidenceScore >= 5
| order by Timestamp desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
