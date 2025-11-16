# ETW / AMSI Tampering Behaviour – L3 Native Detection Rule

## Threat Focus

ETW / AMSI Tampering Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1562

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =============================================================================
// LOLBins with Defense Evasion Patterns (AMSI bypass/memory dumping)
// Author: Ala Dabat 
// Purpose: Detect living-off-the-land binaries used for defense evasion
// Hunter Directive: Analyze LOLBin usage for AMSI bypass, memory dumping, or service disruption
// =============================================================================

let Lookback = 7d;
let LoLBinCmds = dynamic(["rundll32.exe", "regsvr32.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wmic.exe", "taskkill.exe", "sc.exe", "net.exe", "certutil.exe", "bitsadmin.exe"]);
let SuspiciousIndicators = dynamic(["comsvcs.dll", "MiniDump", "AmsiUtils", "AmsiScanBuffer", "amsiInitFailed", "-enc", "IEX(", "DownloadString", "FromBase64String", "net stop", "sc stop", "taskkill", "Stop-Service"]);

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in (LoLBinCmds)
| where ProcessCommandLine has_any (SuspiciousIndicators)
| extend 
    IndicatorType = case(
        ProcessCommandLine contains "comsvcs.dll" or ProcessCommandLine contains "MiniDump", "LSASS Memory Dumping",
        ProcessCommandLine contains "AmsiUtils" or ProcessCommandLine contains "AmsiScanBuffer", "AMSI Bypass Attempt", 
        ProcessCommandLine contains "-enc" or ProcessCommandLine contains "FromBase64String", "Encoded Command",
        ProcessCommandLine contains "net stop" or ProcessCommandLine contains "sc stop", "Service Termination",
        "Suspicious LOLBin Usage"
    ),
    RiskScore = case(
        ProcessCommandLine contains "comsvcs.dll", 10,
        ProcessCommandLine contains "AmsiScanBuffer", 9,
        ProcessCommandLine contains "-enc", 8,
        ProcessCommandLine contains "net stop", 7,
        5
    )
| extend HunterDirective = strcat(
    "HIGH PRIORITY: Investigate ", FileName, " with ", IndicatorType, " indicator. ",
    "Command: ", substring(ProcessCommandLine, 0, 200), 
    ". Parent process: ", InitiatingProcessFileName,
    ". User: ", InitiatingProcessAccountUpn,
    ". Check for successful execution and review process tree for additional malicious activity."
)
| project 
    Timestamp,
    DeviceName,
    ProcessName = FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessAccountUpn,
    IndicatorType,
    RiskScore,
    HunterDirective,
    RuleName = "LOLBins with Defense Evasion Patterns"
| order by RiskScore desc, Timestamp desc;
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
