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
Enhanced rule to detect suspicious PowerShell execution patterns including encoded commands, AMSI bypass, defense tampering, and offensive tool usage with dynamic confidence scoring.

```kql
// =====================================
// Suspicious PowerShell Script Abuse - L3 Enhanced
// Author: Ala Dabat | Version: 2025-11 | Platform: Microsoft Sentinel / MDE
// Purpose: Detect suspicious PowerShell execution patterns including encoded commands,
//          AMSI bypass, defense tampering, and offensive tool usage with dynamic confidence scoring.
// MITRE: T1059.001 (PowerShell), T1562.001 (Disable Security Tools), T1027 (Obfuscation)
// =====================================

let lookback = 14d;

DeviceProcessEvents
| where Timestamp >= ago(lookback)
// Focus on PowerShell processes (legacy + Core)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| extend Cmd = tostring(ProcessCommandLine)

// --- 1. Encoded Command & Obfuscation Detection ---
| extend HasEncodedCommand =
    Cmd has_any (" -encodedcommand", " -enc ", " -e ", " -enco", " -ec")
| extend HasBase64 =
    Cmd has_any ("FromBase64String", "Base64String", " JAB", "SQBvAHUAdABQAHUAdA")  // common PS base64 fragments
| extend HasObfuscation =
    countof(Cmd, @"\^", "regex") > 5
    or countof(Cmd, @"\+", "regex") > 5
    or countof(Cmd, @"\$[A-Za-z0-9]{3,}", "regex") > 3

// Common stealth switches (no profile, no logo, hidden, non-interactive)
| extend HasStealthFlags =
    Cmd has_any (" -nop", " -noprofile", " -w hidden", " -windowstyle hidden",
                 " -noni", " -noninteractive", " -nol", " -nologo")

// --- 2. Download Cradles & Remote Content ---
| extend HasDownloadCmdlet =
    Cmd has_any ("Invoke-WebRequest", " iwr ", "Invoke-RestMethod", " irm ", " curl ", " wget ")
| extend HasNetWebClient =
    Cmd has_any ("New-Object Net.WebClient", "System.Net.WebClient", "DownloadString", "DownloadFile", "DownloadData")
| extend HasSuspiciousDomain =
    Cmd has_any ("http://", "https://", "raw.githubusercontent.com", "pastebin.com",
                 "cdn.discordapp.com", "githubusercontent.com")

| extend HasExpression =
    Cmd has_any (" IEX", "Invoke-Expression", "Invoke-Command", " iex ")

// --- 3. Defense Evasion & AMSI Bypass ---
| extend HasAMSIBypass =
    Cmd has_any ("AmsiUtils", "amsiInitFailed", "AmsiScanBuffer", "amsiContext")
| extend HasDefenseTampering =
    Cmd has_any ("Set-MpPreference", "DisableRealtimeMonitoring", "Add-MpPreference",
                 "DisableIOAVProtection", "DisableScriptScanning", "DisableBehaviorMonitoring")

// --- 4. Suspicious Parent Processes ---
| extend SuspiciousParent =
    InitiatingProcessFileName in~ (
        "winword.exe", "excel.exe", "outlook.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "chrome.exe", "firefox.exe", "iexplore.exe"
    )

// --- 5. Offensive Tool Execution ---
| extend HasOffensiveTool =
    Cmd has_any ("Invoke-Mimikatz", " Mimikatz", "Invoke-NinjaCopy",
                 "Invoke-DllInjection", "PowerSploit",
                 "Invoke-ReflectivePEInjection", "Empire", "Covenant")

// --- 6. Dynamic Confidence Scoring ---
| extend ConfidenceScore = case(
    // CRITICAL: AMSI bypass + defender tampering
    (HasAMSIBypass and HasDefenseTampering), 10,

    // HIGH: Encoded + expression/offensive, or offensive alone
    (HasEncodedCommand and (HasExpression or HasOffensiveTool)), 9,
    (HasOffensiveTool), 9,

    // HIGH: Download cradle with obfuscation/suspicious target
    ((HasDownloadCmdlet or HasNetWebClient) and HasExpression and (HasObfuscation or HasSuspiciousDomain)), 8,

    // MEDIUM-HIGH: Defense tampering or browser/Office parent with encoded/expr
    (HasDefenseTampering), 7,
    (SuspiciousParent and (HasEncodedCommand or HasExpression)), 7,

    // MEDIUM: Encoded/obfuscated/stealth alone
    (HasEncodedCommand or HasObfuscation or (HasBase64 and HasStealthFlags)), 6,

    // LOW: Basic cradle + expression (no obfuscation, no bad domain)
    ((HasDownloadCmdlet or HasNetWebClient) and HasExpression), 5,

    // BASELINE
    3
)

// --- 7. False Positive Mitigation ---
// Exclude known legitimate parent tools (TUNE FOR YOUR ENV)
| where not (InitiatingProcessFileName in~ ("QualysAgent.exe", "ndtrack.exe", "gc_worker.exe", "SCCM.exe"))

// --- 8. Result Enrichment & Formatting ---
| extend Reason = case(
    ConfidenceScore == 10,
        "CRITICAL: AMSI bypass combined with Defender tampering attempt.",
    ConfidenceScore == 9,
        "HIGH: Encoded command with suspicious expression and/or offensive tool usage.",
    ConfidenceScore == 8,
        "HIGH: Download cradle with obfuscation and/or suspicious external domain.",
    ConfidenceScore == 7,
        "MEDIUM-HIGH: Defender tampering or Office/Browser parent with encoded/expressive PowerShell.",
    ConfidenceScore == 6,
        "MEDIUM: Encoded command, heavy obfuscation, or base64 with stealth flags.",
    ConfidenceScore == 5,
        "LOW: Download cradle with expression invocation but limited obfuscation.",
    "Baseline PowerShell activity."
)
| extend Severity = case(
    ConfidenceScore >= 9, "High",
    ConfidenceScore >= 7, "Medium",
    ConfidenceScore >= 5, "Low",
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
        Severity == "High",
            "Immediately review the full process tree. Decode any -EncodedCommand/Base64 payloads. Check for follow-on file writes, LSASS/credential access and outbound C2. Isolate host if activity is not clearly administrative.",
        Severity == "Medium",
            "Inspect PowerShell script content and network destinations. Correlate with email delivery, Office macro events or phishing alerts. Pivot ±24h for same user/device.",
        Severity == "Low",
            "Baseline for this host/user if recurring. Validate parent process legitimacy (admin consoles vs. user apps). Escalate only if combined with other detections.",
        "Use as contextual telemetry only and combine with higher-confidence alerts."
    )
)

// --- 9. Final Projection & Filtering ---
| project
    Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
    FileName, Cmd, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
    HasEncodedCommand, HasBase64, HasObfuscation, HasDownloadCmdlet, HasNetWebClient,
    HasAMSIBypass, HasDefenseTampering, HasOffensiveTool, SuspiciousParent, HasSuspiciousDomain,
    ConfidenceScore, Severity, Reason, HuntingDirectives
| where ConfidenceScore >= 5  // Focus on actionable signals
| order by ConfidenceScore desc, Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
-  `Additional rule` - – a deep-inspection PowerShell detection that analyzes ScriptBlockText from Event ID 4104 to catch pattern-free obfuscation, Unicode/char-based payload reconstruction, reflection-based execution, AST manipulation, and fileless malware that remove all command-line indicators. This companion detection expands coverage across MITRE techniques T1059.001 (PowerShell), T1027 (Obfuscated/Encrypted Files & Payloads) and T1562.001 (Disable Security Tools), filling the visibility gaps left by command-line telemetry alone.


  
