# Modern LOLBIN – Winget Package Abuse – L3 Native Detection Rule

## Threat Focus

Modern LOLBIN – Winget Package Abuse is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: execution
- MITRE: T1218, T1059

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
//  Suspicious Winget Execution (Non-Microsoft Sources / Silent Install)
//  MITRE: T1105 (Ingress Tool Transfer), T1059, T1218
//  Author: Ala Dabat — 2025 LOLBAS / Installer Abuse Pack
// =====================================================================

let lookback = 14d;

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "winget.exe"
| extend Cmd = tostring(ProcessCommandLine),
         Parent = tostring(InitiatingProcessFileName)

// =====================================================================
// 1. Behaviour Flags (Winget Abuse)
// =====================================================================

// Custom source pointing to external repo (non-Microsoft)
| extend CustomSource =
       Cmd has_any ("--source","-s")
       and Cmd has_any ("http://","https://")
       and Cmd !has "microsoft"

// Silent or auto-agreement flags (common in drive-by installs)
| extend SilentInstall =
       Cmd has_any ("--silent","--accept-package-agreements","--accept-source-agreements")

// Installation of arbitrary package from external source
| extend ExternalInstall =
       CustomSource
       and Cmd has_any ("install","--install","-i")

// Temp / user-directory staging paths (payload landing zones)
| extend TempExec =
       Cmd has_any (@"\Users\", @"\AppData\", @"\Temp\")

// Suspicious parent (phishing / LOLBIN chain / browser / script host)
| extend SuspiciousParent =
       Parent in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe",
                   "outlook.exe","winword.exe","excel.exe","wscript.exe",
                   "cscript.exe","mshta.exe","pwsh.exe","powershell.exe")

// =====================================================================
// 2. Severity Mapping (Behaviour → Severity, no scoring)
// =====================================================================

| extend Severity = case(

        // High: install from external source + silent flags → drive-by tool dropper
        (ExternalInstall and SilentInstall)
        or (CustomSource and SuspiciousParent)
        or (CustomSource and TempExec),
        "High",

        // Medium: external source OR silent install from unknown context
        CustomSource or SilentInstall,
        "Medium",

        // Low: winget invoked but no signs of malicious behaviour
        true,
        "Low"
    )

| where Severity in ("High","Medium","Low")

// =====================================================================
// 3. Analyst Reason (Full Detail)
// =====================================================================

| extend Reason = strcat(
      "Winget execution detected. ",
      iif(CustomSource,   "Non-Microsoft source used. ", ""),
      iif(SilentInstall,  "Silent/auto-agreement flags detected. ", ""),
      iif(ExternalInstall,"External package install request. ", ""),
      iif(SuspiciousParent,"Suspicious parent process. ", ""),
      iif(TempExec,       "Temp/AppData staging path referenced. ", "")
    )

// =====================================================================
// 4. L3 Analyst Directives
// =====================================================================

| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Parent=", Parent,
    "; Reason=", Reason,
    "; NextSteps=",
        case(
            Severity == "High",
                "Likely malicious winget abuse (drive-by install / external package source). Verify parent process (browser, Office, script host). Examine resulting installed binaries. Isolate host if malicious.",
            Severity == "Medium",
                "Review the winget command. Confirm whether external package sources are approved. Check user’s activity and verify package integrity.",
            "Low-confidence signal. Baseline legitimate winget usage in the environment; tune for known admin workflows."
        )
)

// =====================================================================
// 5. Output
// =====================================================================

| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, Cmd, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          Severity, Reason, HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
