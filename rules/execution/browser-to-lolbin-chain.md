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
// =====================================================================
//  Browser → LOLBIN Execution Chain — L3 Native Detection
//  MITRE: T1203 (Exploitation), T1059 (Script Execution), T1218 (LOLBAS)
//  Author: Ala Dabat (Alstrum) — 2025 LOLBIN Chain Pack
// =====================================================================

let lookback = 14d;

let Browsers = dynamic([
    "chrome.exe","msedge.exe","firefox.exe",
    "iexplore.exe","brave.exe","opera.exe"
]);

let LOLBINs = dynamic([
    "powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
    "mshta.exe","rundll32.exe","regsvr32.exe",
    "cmd.exe","certutil.exe","bitsadmin.exe","msiexec.exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)

// --- Browser spawning LOLBIN (high-signal base condition)
| where FileName in~ (LOLBINs)
| where InitiatingProcessFileName in~ (Browsers)

| extend BrowserProc        = InitiatingProcessFileName,
         BrowserCommandLine = InitiatingProcessCommandLine,
         Cmd                = tostring(ProcessCommandLine)

// === Behavioural Indicators ===========================================

// Obfuscation / encoded execution
| extend HasEncoded = Cmd has_any ("-enc ", "-encodedcommand", "-e ")

// Base64 payload markers
| extend HasBase64 = Cmd has_any ("FromBase64String"," JAB","SQBvAHUAdA")

// Inline execution (IEX)
| extend HasIEX = Cmd has_any ("iex ","Invoke-Expression","Invoke-Command")

// Download cradle indicators
| extend HasCradle = Cmd has_any ("iwr","Invoke-WebRequest","curl ","wget ","Invoke-RestMethod")

// Downloaded/staged file origin
| extend HasDownloadPath =
       Cmd has_any (@"\Users\", @"\Downloads\", @"\AppData\", @"\Temp\")

// Secondary LOLBINs invoked within same command
| extend HasLOLBINChain =
       Cmd has_any ("javascript:","vbscript:","mshta","regsvr32 /s","rundll32")

// Defender tampering attempts
| extend HasDefenderTamper =
       Cmd has_any ("Set-MpPreference","DisableRealtimeMonitoring","Add-MpPreference")

// === Severity Mapping ==================================================

| extend Severity = case(
        HasEncoded or HasBase64 or HasCradle or HasIEX or HasLOLBINChain or HasDefenderTamper,
            "High",                         // clearly malicious behaviour
        HasDownloadPath,
            "Medium",                       // suspicious payload source
        true,
            "Low"                           // generic browser → LOLBIN chain
    )

| where Severity in ("High","Medium","Low")

// === Analyst-Friendly Reason ==========================================

| extend Reason = strcat(
      "Browser → LOLBIN chain. ",
      iif(HasEncoded,          "Encoded command. ", ""),
      iif(HasBase64,           "Base64 payload. ", ""),
      iif(HasCradle,           "Download cradle. ", ""),
      iif(HasIEX,              "IEX inline execution. ", ""),
      iif(HasLOLBINChain,      "Secondary LOLBIN chain. ", ""),
      iif(HasDefenderTamper,   "Defender tampering attempt. ", ""),
      iif(HasDownloadPath,     "Downloaded file origin. ", "")
)

// === L3 Hunting Directives ============================================

| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Browser=", BrowserProc,
    "; LOLBIN=", FileName,
    "; Reason=", Reason,
    "; NextSteps=",
        case(
            Severity == "High",
                "Investigate full process tree. Extract any downloaded payload. Review browser history, credential harvesting, and persistence activity. Containment recommended.",
            Severity == "Medium",
                "Check the downloaded file or payload. Validate user intent and originating URL/email. Pivot 24h around process and network activity.",
            "Low-confidence chain. Validate if legitimate administration or testing; baseline if recurring."
        )
)

// === Output ============================================================

| project Timestamp, DeviceId, DeviceName, AccountName,
          BrowserProc, BrowserCommandLine,
          FileName, Cmd, FolderPath,
          Severity, Reason, HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
