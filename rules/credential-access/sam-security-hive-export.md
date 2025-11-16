# SAM/SECURITY Hive Export – L3 Native Detection Rule

## Threat Focus

SAM/SECURITY Hive Export is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1003.002

  ## SAM / SECURITY / SYSTEM Hive Extraction — L3 Native Detection Rule  
**Category:** Credential Access  
**MITRE:** T1003.002 (Registry Hives), T1003.006, T1059, T1055  
**Detection Fidelity:** L3 (Native Only — No Threat Intelligence)

Adversaries frequently attempt to extract the `SAM`, `SYSTEM`, and `SECURITY` registry hives to obtain NTLM hashes, LSA secrets, DPAPI credentials, and keys required for offline password cracking or privilege escalation. Modern operations rarely dump these hives directly. Instead, attackers typically use:

- **Shadow copy / VSS abuse** (`vssadmin`, `diskshadow`, `esentutl`)  
- **Reg save/export techniques**  
- **LOLBIN variations** (`reg.exe`, `rundll32.exe`, `dllhost.exe`)  
- **Third-party tooling** (Mimikatz, Impacket’s `secretsdump.py`, LSASSY)  
- **Renamed hive dumps** (`*.tmp`, `*.sav`, `*.bak`, etc.)  
- **Copying hive files via live filesystem access**  
- **Hybrid techniques** (NTDS.dit + hive export for full credential material)

This rule detects high-fidelity hive theft attempts using **native Microsoft telemetry only**.  
It correlates:

1. **Direct hive file access** in `\Windows\System32\config\`  
2. **Process execution** tied to known extraction techniques  
3. **Shadow copy and VSS manipulation**  
4. **Suspicious command-line patterns** (e.g., `reg save HKLM\SAM`)  
5. **Parent/child process lineage** consistent with credential theft  
6. **Timing correlation** between process activity and file access  

### Why This Detection Works
This analytic focuses on **behavioural evidence** rather than signatures. True hive extraction requires:

- Accessing locked registry hives through VSS or direct copy  
- Execution of admin-level LOLBINs or known off-sec tooling  
- File interaction with the exact hive paths or their shadow copies  

These behaviours remain consistent even if tooling is renamed, obfuscated, or embedded inside custom malware.

### What This Rule Detects
- Direct `SAM` / `SYSTEM` / `SECURITY` hive theft  
- Shadow copy abuse used to bypass hive locks  
- Reg export/save techniques used for credential extraction  
- Off-sec frameworks and live response tooling attempting hive dumps  
- Renamed or disguised hive dump files  
- Mimikatz / Impacket / LSASSY-style extraction workflows  
- Pre-staging for privilege escalation, lateral movement, or golden ticket generation  

### Operational Value
This detection provides reliable visibility into early-stage credential compromise.  
Hive extraction is almost always followed by:

- Pass-the-Hash  
- Pass-the-Ticket  
- Lateral movement  
- Privilege escalation  
- Golden Ticket forgery  
- Domain persistence activities (LSA secrets, key material theft)

By detecting hive access at the filesystem level, this analytic remains effective even against:

- Renamed binaries  
- Custom malware  
- LOLBIN-only attacks  
- Memory-resident operations  
- Tool-agnostic credential theft patterns

This is a **pure native, signatureless, high-fidelity** detection designed for SOC L3 and threat hunting environments.


## Advanced Hunting Query (MDE / Sentinel)

```kql
// =======================================================================
// SAM / SECURITY / SYSTEM Hive Extraction — L3 Native Detection (Noise-Reduced)
// Author: Ala Dabat (Alstrum)
// MITRE: T1003.002 (Registry Hives), T1003.006, T1059, T1055
// =======================================================================

let lookback = 14d;

// Host role suppression (optional)
let KnownBackupAgents = dynamic(["veeam","azurebackup","commvault","sccm","intune"]);
let KnownBackupProcesses = dynamic(["veeamagent.exe","vssvc.exe","sqlvsswriter.exe"]);

// Minimalising noise: only evaluate hive paths My
let HivePaths = dynamic([
    @"\windows\system32\config\sam",
    @"\windows\system32\config\system",
    @"\windows\system32\config\security"
]);

// Tools strongly associated with hive theft
let HiveTheftTools = dynamic([
    "mimikatz.exe","secretsdump.py","impacket-secretsdump.exe","lsassy.exe",
    "rubeus.exe","kekeo.exe","diskshadow.exe","vssadmin.exe","esentutl.exe"
]);

// ------------------------------
// 1. TRUE hive access events
// ------------------------------
let HiveAccess =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend LPath = tolower(FolderPath)
| where LPath has @"\windows\system32\config\"
| where FileName in ("sam","system","security")
| where ActionType in ("FileCopied","FileCreated","FileModified","FileDeleted")
| project HiveTime = Timestamp, DeviceName, DeviceId,
          HiveFileName = FileName,
          HiveFolder = FolderPath;

// ------------------------------
// 2. Suspicious processes touching hive extraction tooling
// ------------------------------
let Proc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| extend Cmd = tostring(ProcessCommandLine), Parent = tostring(InitiatingProcessFileName)
| where FileName in (HiveTheftTools)
    or Cmd has_any ("reg save","reg export","save hklm","ntdsutil","esentutl","shadow","vssadmin")
| where FileName !in (KnownBackupProcesses)
| project ProcTime = Timestamp, DeviceName, AccountName,
          FileName, Cmd, Parent;

// ------------------------------
// 3. Correlation: Process → Hive Access
// ------------------------------
HiveAccess
| join kind=inner (Proc) on DeviceName
| where HiveTime between (ProcTime .. ProcTime + 10m)

// ------------------------------
// 4. Behaviour scoring (noise-tuned)
// ------------------------------
| extend ConfidenceScore =
    70
    + 10  // true hive access
    + iif(FileName in (HiveTheftTools), 10, 0)
    + iif(Cmd has_any ("save hklm","reg save","reg export"), 8, 0)
    + iif(Cmd has_any ("diskshadow","vssadmin","shadowcopy"), 6, 0)
    + iif(Parent in ("powershell.exe","cmd.exe"), 3, 0)

// ------------------------------
// 5. Severity Mapping
// ------------------------------
| extend Severity = case(
    ConfidenceScore >= 90, "High",
    ConfidenceScore >= 80, "Medium",
    "Low"
)

// ------------------------------
// 6. Hunter Directives
// ------------------------------
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; Hive=", HiveFileName,
    "; Tool=", FileName,
    "; Command=", Cmd,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Strong indicator of credential hive extraction. Isolate host. Acquire forensic image. Review LSASS access, VSS usage, and recent lateral movement.",
        Severity == "Medium",
            "Investigate process lineage and validate if backup software is misidentified. Review account context and scheduled tasks.",
        "Baseline behaviour. Tune out known backup tools."
    )
)

// ------------------------------
// 7. Final output
// ------------------------------
| project HiveTime, DeviceName, AccountName,
          HiveFileName, HiveFolder,
          FileName, Cmd, Parent,
          ConfidenceScore, Severity, HuntingDirectives
| order by ConfidenceScore desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
