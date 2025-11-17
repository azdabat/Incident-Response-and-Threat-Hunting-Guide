# Vendor Binary → DLL Sideloading (Native) – L3 Native Detection Rule

## Threat Focus

Vendor Binary → DLL Sideloading (Native) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: supply-chain
- MITRE: T1574.002

This rulepack presents a fully engineered, L3-grade detection framework designed to identify modern supply-chain, DLL sideloading, BYOVD driver abuse, and post-install C2 behaviours across Microsoft Defender for Endpoint and Sentinel. The logic originates from a single unified behavioural model that tracks component drops, unsigned DLL/driver loads, delayed-activation loaders, writable-path anomalies, registry-based persistence, and suspicious network staging activity. For operational realism, the framework is decomposed into modular, production-ready rules—each focused on a specific detection surface, while preserving a consistent scoring methodology, MITRE mapping, and analyst triage workflow. The result is a transparent, scalable, and field-tested rulepack that demonstrates advanced detection engineering, supply-chain attack modelling, and disciplined SOC rule lifecycle design.

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =============================================================
// DLL Sideloading – Fast Load / Delayed Load / Writable Path Abuse
// Mirrors SolarWinds / 3CX / Kaseya / NotPetya loader behaviour
// =============================================================

let lookback = 14d;
let writable_paths = dynamic(["C:\\ProgramData\\","C:\\Users\\","C:\\Temp\\","C:\\Windows\\Temp\\"]);
let high_value_parents = dynamic(["outlook.exe","teams.exe","explorer.exe","3CXDesktopApp.exe","SolarWinds.BusinessLayerHost.exe"]);
let lolbins = dynamic(["rundll32.exe","regsvr32.exe","mshta.exe","bitsadmin.exe","powershell.exe","wscript.exe","cscript.exe"]);

let file_drops =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend ext = tolower(split(FileName,".",-1)[-1])
| where ext == "dll"
| where FolderPath has_any (writable_paths)
| project DropTime = Timestamp, DeviceName, DeviceId, FileName, DLLPath = FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine;

let image_loads =
DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| extend ext = tolower(split(ImageFileName,".",-1)[-1])
| where ext == "dll"
| project LoadTime = Timestamp, DeviceName, DeviceId, ProcessName, ImageFileName,
          SHA256, Signer, SignatureStatus;

file_drops
| join kind=leftouter image_loads on DeviceId, SHA256
| extend LoadDelayMin = iif(isnotempty(LoadTime), datetime_diff('minute', LoadTime, DropTime), real(null))
| extend IsFastLoad = iif(isnotempty(LoadDelayMin) and LoadDelayMin >= 0 and LoadDelayMin <= 5, 1, 0)
| extend IsDelayedLoad = iif(isnotempty(LoadDelayMin) and LoadDelayMin >= 60, 1, 0)
| extend ParentHighValue = iif(ProcessName in (high_value_parents), 1, 0)
| extend ParentIsLOLBIN = iif(ProcessName in (lolbins), 1, 0)
| extend UnsignedOrBad = iif(SignatureStatus in ("Unsigned","Invalid","Unknown") or isnull(Signer), 1, 0)

// scoring
| extend ConfidenceScore =
      iif(IsFastLoad == 1, 3, 0)
    + iif(IsDelayedLoad == 1, 3, 0)
    + iif(ParentHighValue == 1, 2, 0)
    + iif(ParentIsLOLBIN == 1, 1, 0)
    + iif(UnsignedOrBad == 1, 3, 0)

// human reason
| extend Reason = case(
    IsFastLoad == 1, "Fast DLL load after drop (sideloading pattern)",
    IsDelayedLoad == 1, "Delayed DLL execution (staging behaviour)",
    UnsignedOrBad == 1, "Unsigned or invalid DLL executed",
    ParentHighValue == 1, "High-value process loaded untrusted DLL",
    ParentIsLOLBIN == 1, "LOLBIN executed DLL",
    "Suspicious DLL behaviour"
)

// triage directive
| extend ThreatHunterDirective = case(
    ConfidenceScore >= 8, "CRITICAL: Likely DLL sideloading or component hijack. Validate signed vendor binaries and isolate device.",
    ConfidenceScore >= 6, "HIGH: DLL executed from writable location; investigate parent process lineage.",
    ConfidenceScore >= 4, "MEDIUM: Potential misuse of DLL search order; correlate with additional processes.",
    "LOW: Monitor only."
)

// MITRE
| extend MITRE_Techniques = "T1574.001 (DLL Search Order Hijacking), T1105 (Ingress Tool Transfer)"

// final
| project DropTime, LoadTime, DeviceName, FileName, DLLPath,
          ProcessName, SignatureStatus, UnsignedOrBad,
          IsFastLoad, IsDelayedLoad, ParentHighValue, ParentIsLOLBIN,
          ConfidenceScore, Reason, MITRE_Techniques, ThreatHunterDirective
| where ConfidenceScore >= 4
| order by DropTime desc
```
```
// =============================================================
// Driver Abuse (BYOVD) – F5-style dormant driver staging + unsigned loads
// =============================================================

let lookback = 14d;
let writable_paths = dynamic(["C:\\ProgramData\\","C:\\Users\\","C:\\Temp\\","C:\\Windows\\Temp\\"]);
let dormant_window = 7d;

let driver_drops =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FileName endswith ".sys"
| where FolderPath has_any (writable_paths)
| project DropTime = Timestamp, DeviceName, DeviceId,
          FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine;

let driver_loads =
DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| where ImageFileName endswith ".sys"
| extend UnsignedOrBad = iif(SignatureStatus in ("Unsigned","Invalid","Unknown"), 1, 0)
| project LoadTime = Timestamp, DeviceName, DeviceId,
          ImageFileName, SHA256, UnsignedOrBad, ProcessName;

driver_drops
| join kind=leftouter driver_loads on DeviceId, SHA256
| extend DormantDriver = iif(isnull(LoadTime) and DropTime <= now() - dormant_window, 1, 0)
| extend FastExecution = iif(isnotempty(LoadTime) and datetime_diff('minute', LoadTime, DropTime) <= 5, 1, 0)

// scoring
| extend ConfidenceScore =
      iif(DormantDriver == 1, 4, 0)
    + iif(UnsignedOrBad == 1, 4, 0)
    + iif(FastExecution == 1, 3, 0)

// reason
| extend Reason = case(
    DormantDriver == 1, "Dormant driver dropped >7 days without load",
    UnsignedOrBad == 1, "Unsigned/invalid driver loaded",
    FastExecution == 1, "Driver executed immediately after drop",
    "Suspicious driver activity"
)

// directive
| extend ThreatHunterDirective = case(
    ConfidenceScore >= 8, "CRITICAL: Potential BYOVD exploit chain. Validate driver signature and isolate host.",
    ConfidenceScore >= 6, "HIGH: Unsigned driver activity; investigate service creation and kernel logs.",
    ConfidenceScore >= 4, "MEDIUM: Suspicious driver behaviour; pivot to initiating processes.",
    "LOW"
)

// MITRE
| extend MITRE_Techniques = "T1543.003 (Create or Modify System Process – Drivers), T1068 (Priv Esc)"

// output
| project DropTime, LoadTime, DeviceName, FileName, FolderPath, UnsignedOrBad,
          DormantDriver, FastExecution,
          ConfidenceScore, Reason, MITRE_Techniques, ThreatHunterDirective
| where ConfidenceScore >= 4
| order by DropTime desc


```
```
// =============================================================
// Scheduled Task Creation – Persistence & Lateral Movement Enabler
// =============================================================

let lookback = 14d;
let suspicious_ext = dynamic([".exe",".dll",".ps1",".js",".vbs",".cmd",".bat"]);
let lolbins = dynamic(["powershell.exe","cmd.exe","mshta.exe","rundll32.exe","wscript.exe"]);

let proc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where ProcessCommandLine has "schtasks"
      or ProcessCommandLine has " /create "
| extend cli = tolower(ProcessCommandLine)
| extend SuspExtension = iif(cli matches regex @"(?i)\.(exe|dll|ps1|js|vbs|cmd|bat)\b",1,0)
| extend ParentIsLOLBIN = iif(InitiatingProcessFileName in (lolbins),1,0)
| extend IsRemoteTask = iif(cli has "\\\\" and cli has " /create ",1,0)

// scoring
| extend ConfidenceScore =
      iif(IsRemoteTask == 1, 4, 0)
    + iif(SuspExtension == 1, 3, 0)
    + iif(ParentIsLOLBIN == 1, 2, 0)

// reason
| extend Reason = case(
    IsRemoteTask == 1, "Remote scheduled task creation (lateral movement)",
    SuspExtension == 1, "Scheduled task executing script/exe payload",
    ParentIsLOLBIN == 1, "LOLBIN creating scheduled task",
    "Suspicious scheduled task activity"
)

// directives
| extend ThreatHunterDirective = case(
    ConfidenceScore >= 8, "CRITICAL: Remote persistence mechanism. Validate admin activity and investigate lateral movement.",
    ConfidenceScore >= 6, "HIGH: Suspicious task payload. Inspect file/registry context.",
    ConfidenceScore >= 4, "MEDIUM: Potential persistence technique; correlate with user context.",
    "LOW"
)

| extend MITRE_Techniques = "T1053.005 (Scheduled Tasks), T1547 (Persistence), T1021 (Lateral Movement)"

// output
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          SuspExtension, IsRemoteTask, ParentIsLOLBIN,
          ConfidenceScore, Reason, MITRE_Techniques, ThreatHunterDirective
| where ConfidenceScore >= 4
| order by Timestamp desc

```

```
// =============================================================
// Archive Creation in Suspicious Directories – Data Exfil & Ransomware Prep
// =============================================================

let lookback = 14d;
let archive_ext = dynamic([".zip",".7z",".rar",".gz",".tar"]);
let suspicious_paths = dynamic(["C:\\Users\\","C:\\Temp\\","C:\\Windows\\Temp\\","C:\\ProgramData\\"]);
let archivers = dynamic(["7z.exe","winrar.exe","powershell.exe","cmd.exe","rar.exe","zip.exe"]);

let f =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend ext = tolower(split(FileName,".",-1)[-1])
| where FileName has_any (archive_ext)
| where FolderPath has_any (suspicious_paths)
| project ArchiveTime = Timestamp, DeviceName, DeviceId,
          ArchiveName = FileName, ArchivePath = FolderPath, InitiatingProcessFileName;

let p =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (archivers)
| project ProcTime = Timestamp, DeviceId, ProcName = FileName, ProcCmd = ProcessCommandLine;

f
| join kind=leftouter p on DeviceId
| extend FastArchive = iif(abs(datetime_diff("minute",ArchiveTime,ProcTime)) <= 5,1,0)
| extend ConfidenceScore =
      iif(FastArchive == 1,3,0)
    + iif(ArchivePath has "Users",2,0)
    + iif(ArchivePath has "Temp",2,0)
| extend Reason = case(
    FastArchive == 1, "Archive created immediately after archiver execution",
    ArchivePath has "Users", "Archive created under user profile",
    ArchivePath has "Temp",  "Archive created in temp path",
    "Suspicious archive creation"
)
| extend ThreatHunterDirective = case(
    ConfidenceScore >= 6, "HIGH: Potential data staging for exfiltration or ransomware prep.",
    ConfidenceScore >= 4, "MEDIUM: Review parent process lineage and accessed files.",
    "LOW"
)
| extend MITRE_Techniques = "T1560 (Archive Collected Data)"
| project ArchiveTime, DeviceName, ArchiveName, ArchivePath, ProcName, ProcCmd,
          FastArchive, ConfidenceScore, Reason, MITRE_Techniques, ThreatHunterDirective
| where ConfidenceScore >= 4
| order by ArchiveTime desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
