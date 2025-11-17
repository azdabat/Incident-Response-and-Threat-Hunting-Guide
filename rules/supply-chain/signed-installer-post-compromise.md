# Signed Installer Post-Install C2 Behaviour – L3 Native Detection Rule

## Threat Focus

Signed Installer Post-Install C2 Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: supply-chain
- MITRE: T1195, T1105

Fast DLL load detection (3CX/SolarWinds)
Dormant driver detection (F5/BYOVD)
Dormant DLL loaders (SolarWinds)
Writable-path drops
Registry persistence correlation
Network-delivered component correlation
LOLBIN loaders
High-value parent process correlation
Driver-abuse detection

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ======================================================================
// Supply-Chain / DLL Sideload / BYOVD Detection — L3 Native, No TI
// Detects 3CX/SolarWinds-style fast DLL loads, F5-style dormant drivers,
// and staged DLLs in writable paths, using native telemetry only.
// ======================================================================

let lookback = 14d;
let dormant_window = 7d;
let confidence_threshold = 3;

// Suspicious / user-writable component-drop locations
let suspicious_folders = dynamic([
  @"C:\ProgramData\", @"C:\Users\", @"C:\Temp\",
  @"C:\Windows\Tasks\", @"C:\Windows\Temp\"
]);

// Writable paths where drivers/DLLs normally should NOT be
let writable_driver_locations = suspicious_folders;

// High-value processes (supply-chain targets / high-trust apps)
let high_value_processes = dynamic([
  "3CXDesktopApp.exe","SolarWinds.BusinessLayerHost.exe",
  "outlook.exe","teams.exe","slack.exe","explorer.exe",
  "svchost.exe","services.exe","winlogon.exe","lsass.exe"
]);

// LOLBIN loaders used in component hijacking
let lolbin_loaders = dynamic([
  "rundll32.exe","regsvr32.exe","mshta.exe",
  "powershell.exe","wscript.exe","cscript.exe","cmd.exe"
]);

// Registry persistence indicator keywords
let registry_keywords = dynamic([
  ".dll",".exe",".ps1",".bat",".vbs",".cmd",".js",
  "rundll32.exe","mshta.exe","powershell.exe","cmd.exe"
]);

// ---------------------------------------------------------
// Step 1 — File drops (.dll / .sys / .exe) in writable paths
// ---------------------------------------------------------
let file_drops =
  DeviceFileEvents
  | where Timestamp >= ago(lookback)
  | where FolderPath has_any (suspicious_folders)
  | extend FileExt = tolower(tostring(split(FileName, ".", -1)[-1]))
  | where FileExt in ("dll","sys","exe")
  | extend
      IsDriver = iif(FileExt == "sys", 1, 0),
      IsDLL    = iif(FileExt == "dll", 1, 0)
  | project
      DropTime = Timestamp,
      DeviceName, DeviceId,
      FileName, FileExt, SHA256, FolderPath,
      InitiatingProcessFileName, InitiatingProcessCommandLine;

// ---------------------------------------------------------
// Step 2 — Suspicious DLL/SYS loads (unsigned/bad-signed)
// ---------------------------------------------------------
let image_loads =
  DeviceImageLoadEvents
  | where Timestamp >= ago(lookback)
  | extend FileExt = tolower(tostring(split(ImageFileName, ".", -1)[-1]))
  | where FileExt in ("dll","sys")
  | extend UnsignedOrBad =
      iif(SignatureStatus in ("Unsigned","Invalid","Unknown") or isnull(Signer), 1, 0)
  | where UnsignedOrBad == 1
  | project
      LoadTime = Timestamp,
      DeviceName, DeviceId,
      ProcessName, ProcessId,
      ImageFileName, FileExt,
      ImageSHA256 = SHA256,
      UnsignedOrBad;

// ---------------------------------------------------------
// Step 3 — Registry persistence referencing components
// ---------------------------------------------------------
let reg_persistence =
  DeviceRegistryEvents
  | where Timestamp >= ago(lookback)
  | where ActionType in ("RegistryValueSet","RegistryValueAdded")
  | where RegistryValueData has_any (registry_keywords)
  | project
      RegTime = Timestamp,
      DeviceName, DeviceId,
      RegistryKey, RegistryValueName, RegistryValueData,
      RegInitiatingProcessFileName = InitiatingProcessFileName,
      RegInitiatingProcessCommandLine = InitiatingProcessCommandLine;

// ---------------------------------------------------------
// Step 4 — Network-delivered components (DLL/SYS/EXE)
// ---------------------------------------------------------
let net_downloads =
  DeviceNetworkEvents
  | where Timestamp >= ago(lookback)
  | where isnotempty(RemoteUrl)
  | where RemoteUrl has_any (".dll",".sys",".exe",".bin",".dat")
  | project
      DownloadTime = Timestamp,
      DeviceName, DeviceId,
      RemoteUrl, RemoteIP, RemotePort,
      NetInitiatingProcessFileName = InitiatingProcessFileName,
      NetInitiatingProcessCommandLine = InitiatingProcessCommandLine;

// ---------------------------------------------------------
// Step 5 — Correlation: Drops ↔ Loads ↔ Downloads ↔ Registry
// ---------------------------------------------------------
file_drops
| join kind=leftouter (
    image_loads
  ) on DeviceId, DeviceName, $left.SHA256 == $right.ImageSHA256
| join kind=leftouter (net_downloads) on DeviceId, DeviceName
| join kind=leftouter (reg_persistence) on DeviceId, DeviceName

| extend LoadDelayMin =
    iif(isnotempty(LoadTime),
        datetime_diff("minute", LoadTime, DropTime),
        real(null))

| extend DroppedInWritable =
    iif(FolderPath has_any (writable_driver_locations), 1, 0)

| extend IsHighValueProc =
    iif(ProcessName in (high_value_processes)
        or NetInitiatingProcessFileName in (high_value_processes), 1, 0)

| extend IsLolbinLoader =
    iif(InitiatingProcessFileName in (lolbin_loaders)
        or NetInitiatingProcessFileName in (lolbin_loaders), 1, 0)

// ---------------------------------------------------------
// Behaviour flags — Fast DLL, Dormant Driver, Dormant DLL
// ---------------------------------------------------------

// Fast DLL load (3CX / SolarWinds)
| extend SuspiciousDLLFast =
    iif(IsDLL == 1
        and isnotempty(LoadTime)
        and LoadDelayMin >= 0 and LoadDelayMin <= 5,
        1, 0)

// High-value process was the loader
| extend FastDLL_ParentHighValue =
    iif(SuspiciousDLLFast == 1
        and ProcessName in (high_value_processes),
        1, 0)

// Dormant driver (F5/BYOVD)
| extend DormantDriver =
    iif(IsDriver == 1
        and DropTime <= now() - dormant_window
        and isnull(LoadTime),
        1, 0)

// Dormant DLL loader (SolarWinds-style)
| extend DormantDLL =
    iif(IsDLL == 1
        and DroppedInWritable == 1
        and DropTime <= now() - dormant_window
        and isnull(LoadTime),
        1, 0)

// ---------------------------------------------------------
// Native Confidence Score (no TI)
// ---------------------------------------------------------
| extend ConfidenceScore =
      iif(DroppedInWritable == 1, 2, 0)
    + iif(isnotempty(RegistryKey), 2, 0)
    + iif(SuspiciousDLLFast == 1, 2, 0)
    + iif(DormantDriver == 1, 3, 0)
    + iif(DormantDLL == 1, 3, 0)
    + iif(IsHighValueProc == 1, 2, 0)
    + iif(IsLolbinLoader == 1, 1, 0)

// ---------------------------------------------------------
// Reason (human-readable)
// ---------------------------------------------------------
| extend Reason =
    case(
        DormantDriver == 1, "Dormant driver >7 days with no load",
        DormantDLL == 1, "Dormant DLL in writable directory >7 days",
        SuspiciousDLLFast == 1, "DLL loaded <5m after drop (possible sideloading)",
        DroppedInWritable == 1, "File dropped in writable directory",
        isnotempty(RegistryKey), "Registry-based persistence referencing component",
        isnotempty(RemoteUrl), "Component downloaded from remote URL",
        "—"
    )

// ---------------------------------------------------------
// MITRE mapping
// ---------------------------------------------------------
| extend MITRE_Techniques =
    strcat_array(
      bag_keys(
        pack(
          "T1574.001", iif(SuspiciousDLLFast == 1, 1, 0),
          "T1543.003", iif(IsDriver == 1, 1, 0),
          "T1547.001", iif(isnotempty(RegistryKey), 1, 0),
          "T1105",     iif(isnotempty(RemoteUrl), 1, 0),
          "T1195",     1
        )
      ),
      ", "
    )

// ---------------------------------------------------------
// Triage directive (single-line)
// ---------------------------------------------------------
| extend ThreatHunterDirective = case(
    SuspiciousDLLFast == 1 and FastDLL_ParentHighValue == 1,
        "CRITICAL: Likely 3CX/SolarWinds-style DLL sideloading. Validate parent binary integrity and isolate if suspicious.",
    DormantDriver == 1,
        "CRITICAL: Dormant driver drop consistent with BYOVD/F5-style staging. Validate driver and check services.",
    DormantDLL == 1,
        "HIGH: Staged DLL in writable directory. Validate whether it is a loader or replaced vendor file.",
    isnotempty(RegistryKey),
        "HIGH: Registry persistence referencing executable or script.",
    isnotempty(RemoteUrl),
        "MEDIUM: Remote download of executable component.",
    DroppedInWritable == 1,
        "MEDIUM: Component dropped in writable path; review creation process.",
    "LOW: Monitor for escalation."
)

// ---------------------------------------------------------
// Multi-step hunting checklist
// ---------------------------------------------------------
| extend HuntingDirectives = pack_array(
    "1) Confirm DLL/driver legitimacy; check vendor signatures and baseline.",
    "2) Analyse process lineage; confirm installer/update legitimacy.",
    "3) Investigate DLL sideload patterns for trusted applications.",
    "4) Investigate driver installations: signer, origin, associated services.",
    "5) Check network context for staging/C2 infrastructure.",
    "6) Hunt for same SHA256, filename, or persistence pattern across estate.",
    "7) If malicious, isolate host and collect forensic artefacts."
)

// ---------------------------------------------------------
// Final projection
// ---------------------------------------------------------
| where ConfidenceScore >= confidence_threshold
| project
    DropTime, LoadTime, DownloadTime, RegTime,
    DeviceName, FileName, SHA256, FolderPath,
    ImageFileName, ProcessName, RemoteUrl, RemoteIP,
    RegistryKey, RegistryValueData,
    SuspiciousDLLFast, DormantDriver, DormantDLL,
    DroppedInWritable, IsDriver, IsDLL,
    ConfidenceScore, Reason,
    MITRE_Techniques, ThreatHunterDirective, HuntingDirectives
| order by DropTime desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
