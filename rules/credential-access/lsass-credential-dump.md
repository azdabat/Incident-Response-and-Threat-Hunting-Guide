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
// LSASS Credential Dumping — L3 Native
// Author: Ala Dabat | 2025-11

let lookback = 14d;

let SafeProcs = dynamic([
    "taskmgr.exe","procexp.exe","procexp64.exe",
    "msmpeng.exe","senseIR.exe","lsass.exe"
]);

let BackupTools = dynamic([
    "veeamagent.exe","veeamservice.exe","sqlvsswriter.exe","vssvc.exe","wbengine.exe"
]);

let MonitoringTools = dynamic([
    "splunkd.exe","qualys.exe","tanium.exe","crowdstrike.exe"
]);

let DumpTools = dynamic([
    "procdump.exe","procdump64.exe","nanodump.exe","nanodump64.exe",
    "mimikatz.exe","lsassy.exe","dumpert.exe","dmp.exe","secretsdump.py","outflank.dll"
]);

// 1. LSASS access via command line reference (first indicator)
let LsassAccess =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName !in (SafeProcs)
| where InitiatingProcessFileName !in (SafeProcs)
| extend Cmd=tostring(ProcessCommandLine)
| where Cmd has "lsass" or InitiatingProcessCommandLine has "lsass"
| project Time=Timestamp, DeviceId, DeviceName, AccountName,
          Proc=FileName, Cmd,
          Parent=InitiatingProcessFileName;

// 2. Dump-related DLL loads (high-fidelity correlation)
let DumpDll =
DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| where ImageFileName has_any ("dbghelp","comsvcs","minidump","dbgcore")
| where InitiatingProcessFileName !in (SafeProcs)
| project DeviceId, ImageFileName, DllTime=Timestamp;

// 3. Suspicious dump tools or dump switches
let ToolHits =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (DumpTools)
   or ProcessCommandLine has_any ("-ma","minidump","sekurlsa","dump")
| where FileName !in (SafeProcs)
| project DeviceId, HitTime=Timestamp,
          HitProc=FileName, HitCmd=ProcessCommandLine;

// 4. Correlation
LsassAccess
| join kind=leftouter DumpDll on DeviceId
| join kind=leftouter ToolHits on DeviceId
| extend HasDumpDll = isnotempty(ImageFileName),
         HasDumpTool = isnotempty(HitProc),
         HasLsassAccess = 1

// 5. Scoring (simple, noise-resistant)
| extend Score =
      70
      + iif(HasDumpTool, 15, 0)
      + iif(HasDumpDll, 10, 0)
      + iif(Cmd has_any ("-ma","minidump","sekurlsa"), 8, 0)
      + iif(Parent in ("powershell.exe","cmd.exe","rundll32.exe","mshta.exe"), 5, 0)

// 6. Severity
| extend Severity = case(
      Score >= 90, "High",
      Score >= 80, "Medium",
      "Low"
)

// 7. Directives
| extend Directives = strcat(
      "Severity=", Severity,
      "; Host=", DeviceName,
      "; User=", AccountName,
      "; Reason=",
         iif(HasDumpTool, strcat("DumpTool:", HitProc, "; "), ""),
         iif(HasDumpDll, strcat("DumpDLL:", ImageFileName, "; "), ""),
         iif(Cmd has_any ("-ma","minidump","sekurlsa"), "DumpSwitch; ", ""),
         iif(Parent in ("powershell.exe","cmd.exe","rundll32.exe","mshta.exe"),
             strcat("SuspiciousParent:", Parent, "; "), ""),
      "; Action=",
      case(
          Severity == "High",
              "Isolate host, review LSASS access, check for credential theft, collect memory, pivot for further lateral movement.",
          Severity == "Medium",
              "Validate admin activity, check process lineage, review Sysinternals use, pivot ±24h.",
          "Baseline check; tune safe processes for environment."
      )
)

// 8. Output
| where Score >= 80
| project Time, DeviceName, AccountName,
          Proc, Cmd, Parent,
          HasDumpDll, ImageFileName,
          HasDumpTool, Score, Severity,
          Directives
| order by Score desc, Time desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
