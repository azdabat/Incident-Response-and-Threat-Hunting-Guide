# Phishing → Office Macro → LOLBIN Chain – L3 Native Detection Rule

## Threat Focus

Phishing → Office Macro → LOLBIN Chain is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: execution
- MITRE: T1566, T1204, T1059, T1218

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================================
//  Phishing → Macro → LOLBIN Execution Chain
//  MITRE: T1204 (User Execution), T1566 (Phishing), T1059, T1218 (LOLBAS)
//  Author: Ala Dabat (Alstrum) — 2025 Macro/LOLBIN Detection Pack
// =====================================================================

let lookback = 14d;

// Office applications commonly used to deliver macros
let OfficeApps = dynamic([
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe","visio.exe"
]);

// LOLBINs frequently spawned by malicious macros
let LOLBINs = dynamic([
    "powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe",
    "cmd.exe","wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe","msiexec.exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (LOLBINs)
| where InitiatingProcessFileName in~ (OfficeApps)     // macro → LOLBIN chain

| extend OfficeProc  = InitiatingProcessFileName,
         OfficeCmd    = InitiatingProcessCommandLine,
         Cmd          = tostring(ProcessCommandLine)

// --- Behaviour Flags ---------------------------------------------------

// Encoded/obfuscated execution
| extend HasEncoded = Cmd has_any ("-enc","-encodedcommand")

// Download cradle or payload retrieval
| extend HasCradle = Cmd has_any ("iwr","Invoke-WebRequest","curl ","wget ","Invoke-RestMethod")

// Inline execution (IEX) commonly seen in macro droppers
| extend HasIEX = Cmd has_any ("iex ","Invoke-Expression","Invoke-Command")

// Staging paths (Downloads, AppData, Temp)
| extend HasStagingPath =
       Cmd has_any (@"\Downloads\", @"\AppData\", @"\Temp\")

// Secondary LOLBIN chain within same command
| extend HasLOLBINChain =
       Cmd has_any ("mshta","rundll32","regsvr32","wscript","cscript")

// --- Severity -----------------------------------------------------------

| extend Severity = case(
        HasEncoded or HasCradle or HasIEX or HasLOLBINChain, "High",
        HasStagingPath,                                      "Medium",
        true,                                                 "Low"
    )

| where Severity in ("High","Medium","Low")

// --- Reason ------------------------------------------------------------

| extend Reason = strcat(
        "Office → LOLBIN chain. ",
        iif(HasEncoded,       "Encoded command. ", ""),
        iif(HasCradle,        "Download cradle. ", ""),
        iif(HasIEX,           "Inline execution (IEX). ", ""),
        iif(HasLOLBINChain,   "Secondary LOLBIN chain. ", ""),
        iif(HasStagingPath,   "Suspicious staging path. ", "")
    )

// --- L3 Hunting Directives ---------------------------------------------

| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Office=", OfficeProc,
    "; LOLBIN=", FileName,
    "; Reason=", Reason,
    "; NextSteps=",
        case(
            Severity == "High",
                "Treat as likely phishing macro execution. Review originating email, Office document, and user actions. Inspect dropped files, network activity, and any follow-on persistence. Consider containment.",
            Severity == "Medium",
                "Validate if the file path or LOLBIN use is expected. Check whether the user recently opened external documents. Pivot 24h before/after.",
            "Low-confidence chain. Baseline if legitimate workflow; correlate with URL clicks or email context."
        )
)

// --- Output ------------------------------------------------------------

| project Timestamp, DeviceId, DeviceName, AccountName,
          OfficeProc, OfficeCmd,
          FileName, Cmd,
          Severity, Reason, HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
