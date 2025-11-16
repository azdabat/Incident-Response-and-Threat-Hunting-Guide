# Suspicious PowerShell Script Abuse – L3 Native Detection Rule

## Threat Focus

Suspicious PowerShell Script Abuse is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: execution
- MITRE: T1059.001

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================
// Suspicious PowerShell Script Abuse - Enhanced Detection
// Author: Ala Dabat | Version: 2025-11 | Platform: Microsoft Sentinel
// Purpose: Detect suspicious PowerShell execution patterns including encoded commands, download cradles, AMSI bypass, and offensive tool usage
// MITRE: T1059.001 (Command and Scripting Interpreter: PowerShell), T1218 (System Binary Proxy Execution)
// =====================================

let lookback = 14d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"  // Include PowerShell Core
| extend Cmd = tostring(ProcessCommandLine)
// ===== DETECTION SCENARIOS =====
// 1. Encoded Command Abuse with Suspicious Content [citation:4]
| extend HasEncodedCommand = Cmd has_any(" -EncodedCommand", " -enc ", " -e ")
| extend HasSuspiciousExpression = Cmd has_any("IEX", "Invoke-Expression", "Invoke-Command")
| extend HasDownloadCradle = Cmd has_any("DownloadString", "DownloadFile", "DownloadData", "WebClient", "WebRequest", "System.Net.WebClient")
| extend HasAssemblyLoad = Cmd has_any("Assembly.Load", "FromBase64String")
// 2. Web Request with Expression and Suspicious Domains
| extend HasWebRequest = Cmd has_any("Invoke-WebRequest", "iwr ", "curl ", "wget ")
| extend HasSuspiciousDomain = Cmd has_any("http://", "https://", "raw.githubusercontent.com", "pastebin.com", 
    "cdn.discordapp.com", "anonfiles", "transfer.sh", "bit.ly", "tinyurl", ".ru", ".xyz", ".pw")
// 3. Defense Evasion and AMSI Bypass
| extend HasAMSIBypass = Cmd has_any("AmsiUtils", "amsiInitFailed", "AMSIContest", "AmsiScanBuffer")
| extend HasDefenseTampering = Cmd has_any("Set-MpPreference", "DisableRealtimeMonitoring", "Add-MpPreference", 
    "DisableIOAVProtection", "DisableScriptScanning", "DisableBehaviorMonitoring")
// 4. Suspicious Parent Processes (LOLBin Execution) [citation:8][citation:10]
| extend SuspiciousParent = InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "wscript.exe", 
    "cscript.exe", "mshta.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe")
| extend TempPathExecution = Cmd contains @"\AppData\" or Cmd contains @"\Temp\"
// 5. Scheduled Task Script Abuse
| extend HasSchtasks = Cmd contains "schtasks" and Cmd contains ".ps1"
// 6. Offensive Tool Execution Patterns [citation:4]
| extend HasOffensiveTool = Cmd has_any("Invoke-Mimikatz", "Invoke-NinjaCopy", "Invoke-DllInjection", 
    "Invoke-ReflectivePEInjection", "Invoke-Shellcode", "Invoke-PSInject", "Invoke-ProcessHollow", 
    "Invoke-SharpCradle", "Seatbelt", "SharpHound", "Rubeus")
// ===== CONFIDENCE SCORING =====
| extend ConfidenceScore = case(
    // High confidence scenarios
    (HasEncodedCommand and (HasSuspiciousExpression or HasDownloadCradle)) or
    (HasAMSIBypass and HasDefenseTampering) or
    HasOffensiveTool, 9,
    // Medium-High confidence
    (HasWebRequest and HasSuspiciousExpression and HasSuspiciousDomain) or
    (SuspiciousParent and TempPathExecution) or
    (HasEncodedCommand and HasAssemblyLoad), 8,
    // Medium confidence  
    HasDefenseTampering or 
    (HasDownloadCradle and HasSuspiciousExpression) or
    HasSchtasks, 7,
    // Low confidence
    HasEncodedCommand or HasWebRequest or SuspiciousParent, 5,
    // Baseline
    3
)
// ===== FALSE POSITIVE EXCLUSIONS =====
| where not(InitiatingProcessFileName in~ ("QualysAgent.exe", "ndtrack.exe", "gc_worker.exe"))
// ===== RESULT ENRICHMENT =====
| extend Reason = case(
    ConfidenceScore == 9, "High-confidence PowerShell abuse: encoded commands with suspicious execution OR AMSI bypass with defense evasion OR offensive tool usage",
    ConfidenceScore == 8, "Medium-high confidence: web request with expression and suspicious domains OR suspicious parent process with temp path execution",
    ConfidenceScore == 7, "Medium confidence: defense tampering OR download cradle with expression OR scheduled task script abuse", 
    ConfidenceScore == 5, "Low confidence: encoded commands OR web requests OR suspicious parent process",
    "Baseline PowerShell activity"
)
| extend Severity = case(
    ConfidenceScore >= 8, "High",
    ConfidenceScore >= 5, "Medium", 
    ConfidenceScore >= 3, "Low",
    "Informational"
)
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", tostring(DeviceName), 
    "; User=", tostring(AccountName),
    "; ParentProcess=", tostring(InitiatingProcessFileName),
    "; CoreReason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High", "Immediately investigate process chain, check for subsequent network connections and file writes, isolate host if confirmed malicious",
        Severity == "Medium", "Review command-line arguments in detail, check for file downloads from suspicious sources, correlate with other alerts on same host/user",
        Severity == "Low", "Baseline this activity for the asset/user, review parent process legitimacy, treat as hunting signal",
        "Use as contextual signal only"
    )
)
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
    FileName, Cmd, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
    ConfidenceScore, Severity, Reason, HuntingDirectives
| where ConfidenceScore >= 5  // Filter to meaningful alerts
| order by ConfidenceScore desc, Timestamp desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
