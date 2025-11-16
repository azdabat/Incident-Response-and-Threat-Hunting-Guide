# LSASS Credential Dumping Behaviour – L3 Native Detection Rule

## Threat Focus

LSASS Credential Dumping Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1003.001, T1055

## LSASS Credential Dumping – L3 Native Detection Rule  
**Category:** Credential Access  
**MITRE:** T1003.001 (OS Credential Dumping), T1055 (Process Injection)  
**Detection Fidelity:** L3 (Behaviour-Based, Native Only)

LSASS (Local Security Authority Subsystem Service) is one of the highest-value processes on a Windows system. It stores:
- NTLM password hashes
- Kerberos tickets (TGT/TGS)
- SSP credentials (WDigest, Kerberos, Negotiate)
- DPAPI master keys
- Token material and credential caches

Adversaries frequently target LSASS to extract credential material for lateral movement and privilege escalation.  
Common LSASS dumping vectors include:

- Sysinternals ProcDump abuse (`procdump -ma lsass.exe`)
- Mimikatz sekurlsa functionality
- MiniDumpWriteDump injections
- NanoDump / Dumpert (direct syscalls)
- LSASS memory handle duplication
- Impacket-based LSASS extraction
- OffSec BOF modules and renamed dumping tools
- Shadow copy based LSASS extraction
- Rundll32 / COM hijacking for dump generation

This analytic detects LSASS credential dumping using pure native telemetry without requiring signatures or threat intelligence.  
The rule correlates multiple independent signals:

1. Known dumping tools and masquerades  
2. LSASS-rela


## Advanced Hunting Query (MDE / Sentinel)

```kql
// ========================================================================
// LSASS Credential Dumping – L3 Native Detection (Noise-Reduced)
// Author: Ala Dabat (Alstrum)
// MITRE: T1003.001 (LSASS Dump), T1055 (Process Injection)
// ========================================================================

let lookback = 14d;

// -----------------------------
// 0. Known benign LSASS dump users (tune per environment)
// -----------------------------
let KnownSafeProcesses = dynamic([
    "taskmgr.exe",      // Task Manager
    "procexp.exe",      // Sysinternals Process Explorer
    "procexp64.exe",
    "msmpeng.exe",      // Defender
    "senseIR.exe",      // Defender for Endpoint
    "lsass.exe"         // Allowed self-access
]);

let KnownBackupTools = dynamic([
    "veeamagent.exe","veeamservice.exe",
    "sqlvsswriter.exe","vssvc.exe", "wbengine.exe"
]);

let KnownMonitoringTools = dynamic([
    "splunkd.exe","qualys.exe","tanium.exe","crowdstrike.exe"
]);

// -----------------------------
// 1. TRUE LSASS access via handle opens (high fidelity)
// -----------------------------
let LsassAccess =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName !in (KnownSafeProcesses)
| where InitiatingProcessFileName !in (KnownSafeProcesses)
| extend Cmd = tostring(ProcessCommandLine)
| where ProcessCommandLine has "lsass" 
    or InitiatingProcessCommandLine has "lsass"
    or Cmd has "lsass"
| project LsassTime = Timestamp,
          DeviceId, DeviceName, AccountName,
          Proc = FileName, Cmd,
          Parent = InitiatingProcessFileName;

// -----------------------------
// 2. Dump-related DLL load correlation
// -----------------------------
let DumpDllLoads =
DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| where ImageFileName has_any ("dbghelp","comsvcs","minidump","dbgcore")
| where InitiatingProcessFileName !in (KnownSafeProcesses)
| project DllTime = Timestamp,
          DeviceId, DeviceName,
          ImageFileName, Proc = InitiatingProcessFileName;

// -----------------------------
// 3. Suspicious dumping tools / renamed binaries
// -----------------------------
let SuspiciousDumpTools =
dynamic([
    "procdump.exe","procdump64.exe",
    "nanodump.exe","nanodump64.exe",
    "mimikatz.exe","lsassy.exe",
    "dumpert.exe","dmp.exe","secretsdump.py",
    "outflank.dll"
]);

let ProcHits =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (SuspiciousDumpTools)
      or ProcessCommandLine has_any ("-ma","MiniDump","sekurlsa","dump")
| where FileName !in (KnownSafeProcesses)
| project HitTime = Timestamp, DeviceId, DeviceName, 
          Proc = FileName, Cmd = ProcessCommandLine;

// -----------------------------
// 4. Correlate LSASS access + dump DLL loads + dump tooling
// -----------------------------
LsassAccess
| join kind=leftouter (DumpDllLoads) on DeviceId
| join kind=leftouter (ProcHits)     on DeviceId
| extend HasDumpDll = iif(isnotempty(ImageFileName), 1, 0)
| extend HasDumpTool = iif(isnotempty(Proc1), 1, 0)
| extend HasLsassAccess = 1

// -----------------------------
// 5. Scoring (noise-resistant)
// -----------------------------
| extend ConfidenceScore =
    70
    + iif(HasDumpTool == 1, 10, 0)
    + iif(HasDumpDll == 1, 8, 0)
    + iif(Cmd has_any ("-ma","minidump","sekurlsa"), 6, 0)
    + iif(Parent in ("powershell.exe","cmd.exe","rundll32.exe","mshta.exe"), 4, 0)

// -----------------------------
// 6. Reason
// -----------------------------
| extend Reason = strcat(
    iif(HasDumpTool == 1, strcat("Known LSASS dumping tool executed: ", Proc1, ". "), ""),
    iif(HasDumpDll == 1, strcat("Dump-related DLL loaded: ", ImageFileName, ". "), ""),
    iif(Cmd has_any ("-ma","minidump","sekurlsa"), "Dump switches detected. ", ""),
    iif(Parent in ("powershell.exe","cmd.exe","rundll32.exe","mshta.exe"),
        strcat("Suspicious parent: ", Parent, ". "), "")
)

// -----------------------------
// 7. Severity
// -----------------------------
| extend Severity = case(
    ConfidenceScore >= 90, "High",
    ConfidenceScore >= 80, "Medium",
    ConfidenceScore >= 70, "Low",
    "Informational"
)

// -----------------------------
// 8. Hunter Directives
// -----------------------------
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Strong LSASS dumping indicator. Immediately isolate host. Review LSASS handle access, check for credential theft, correlate with DCSync/PTH/PTT attempts, collect full process tree and memory.",
        Severity == "Medium",
            "Investigate process lineage. Confirm if admin using legitimate tools. Check for unauthorized Sysinternals use. Pivot around process chain ±24h.",
        "Review as potential baseline. Tune KnownSafeProcesses and KnownBackupTools."
    )
)

// -----------------------------
// 9. Final Filtering
// -----------------------------
| where ConfidenceScore >= 80       // Medium+ by default
| project LsassTime, DeviceName, AccountName,
          Proc, Cmd, Parent,
          HasDumpDll, ImageFileName,
          HasDumpTool, ConfidenceScore,
          Severity, HuntingDirectives
| order by ConfidenceScore desc, LsassTime desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
