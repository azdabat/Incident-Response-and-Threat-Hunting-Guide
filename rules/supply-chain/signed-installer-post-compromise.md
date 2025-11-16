# Signed Installer Post-Install C2 Behaviour – L3 Native Detection Rule

## Threat Focus

Signed Installer Post-Install C2 Behaviour is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: supply-chain
- MITRE: T1195, T1105

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =============================================================
// Supply-Chain & Sideloading / Driver Abuse Detection
// Targets: 3CX, F5 BIG-IP, SolarWinds SUNBURST, NotPetya-style loaders
// Author: Ala Dabat
// Environment: Microsoft Defender for Endpoint Advanced Hunting
// Tables: DeviceFileEvents, DeviceImageLoadEvents, DeviceRegistryEvents,
//         DeviceNetworkEvents, ThreatIntelligenceIndicator
// =============================================================

let lookback = 14d;

// Suspicious / user-writable locations commonly abused in supply-chain and sideload attacks
let suspicious_folders = dynamic([
  @"C:\ProgramData\",
  @"C:\Users\",
  @"C:\Temp\",
  @"C:\Windows\Tasks\",
  @"C:\Windows\Temp\"
]);

// Locations where drivers / DLLs should NOT normally live (for BYOVD / F5-style abuse)
let writable_driver_locations = dynamic([
  @"C:\ProgramData\",
  @"C:\Users\",
  @"C:\Temp\",
  @"C:\Windows\Tasks\",
  @"C:\Windows\Temp\"
]);

// High-value processes (trusted apps / business-critical / common supply-chain targets)
let high_value_processes = dynamic([
  "3CXDesktopApp.exe",
  "3CXDesktopApp",
  "SolarWinds.BusinessLayerHost.exe",
  "outlook.exe",
  "teams.exe",
  "slack.exe",
  "explorer.exe",
  "svchost.exe",
  "services.exe",
  "winlogon.exe",
  "lsass.exe"
]);

// LOLBIN loaders commonly used in component hijacking and staged execution
let lolbin_loaders = dynamic([
  "rundll32.exe",
  "regsvr32.exe",
  "mshta.exe",
  "powershell.exe",
  "wscript.exe",
  "cscript.exe",
  "cmd.exe"
]);

// Registry indicators of persistence or execution
let registry_keywords = dynamic([
  ".dll", ".exe", ".ps1", ".bat", ".vbs", ".cmd", ".js",
  "rundll32.exe", "mshta.exe", "powershell.exe", "cmd.exe"
]);

// Known malicious hashes (seed from MISP / TI)
let known_malicious_hashes = dynamic([
  "f1e2d3c4b5a6..."   // TODO: replace with supply-chain IOCs
]);

let dormant_window = 7d;
let confidence_threshold = 3;

// Threat Intelligence enrichment (MISP / TI table)
let TI =
  ThreatIntelligenceIndicator
  | where TimeGenerated >= ago(30d)
  | where IndicatorType in ("FileHash","IP","URL","DomainName")
  | project
      TI_Indicator = Indicator,
      TI_Type      = IndicatorType,
      TI_Threat    = ThreatType,
      TI_Confidence = toint(ConfidenceScore),
      TI_LastSeen  = TimeGenerated;

// ------------------------------------------------------------
// Step 1: File drops (DLL / SYS / EXE in suspicious locations)
// ------------------------------------------------------------
let file_drops =
  DeviceFileEvents
  | where Timestamp >= ago(lookback)
  | where FolderPath has_any (suspicious_folders)
  | extend FileExt = tolower(tostring(split(FileName, ".", -1)[-1]))
  | where FileExt in ("dll","sys","exe")
  | extend
      IsDriver = iif(FileExt == "sys", 1, 0),
      IsDLL    = iif(FileExt == "dll", 1, 0),
      IsExe    = iif(FileExt == "exe", 1, 0)
  | project
      DropTime = Timestamp,
      DeviceName,
      DeviceId,
      FileName,
      FileExt,
      SHA256,
      FolderPath,
      InitiatingProcessFileName,
      InitiatingProcessCommandLine;

// ------------------------------------------------------------
// Step 2: DLL / SYS image loads (unsigned/bad signature)
// ------------------------------------------------------------
let image_loads =
  DeviceImageLoadEvents
  | where Timestamp >= ago(lookback)
  | extend FileExt = tolower(tostring(split(ImageFileName, ".", -1)[-1]))
  | where FileExt in ("dll","sys")
  | extend UnsignedOrBad =
      iif(SignatureStatus in ("Unsigned","Invalid","Unknown") or isnull(Signer), 1, 0)
  | where UnsignedOrBad == 1
  | project
      LoadTime    = Timestamp,
      DeviceName,
      DeviceId,
      ProcessName,
      ProcessId,
      ImageFileName,
      FileExt,
      ImageSHA256 = SHA256,
      UnsignedOrBad,
      Signer,
      SignatureStatus;

// ------------------------------------------------------------
// Step 3: Registry persistence referencing executables/scripts
// ------------------------------------------------------------
let reg_persistence =
  DeviceRegistryEvents
  | where Timestamp >= ago(lookback)
  | where ActionType in ("RegistryValueSet","RegistryValueAdded")
  | where RegistryValueData has_any (registry_keywords)
  | project
      RegTime = Timestamp,
      DeviceName,
      DeviceId,
      RegistryKey,
      RegistryValueName,
      RegistryValueData,
      RegInitiatingProcessFileName      = InitiatingProcessFileName,
      RegInitiatingProcessCommandLine   = InitiatingProcessCommandLine;

// ------------------------------------------------------------
// Step 4: Network downloads of DLL/driver/EXE payloads
// ------------------------------------------------------------
let net_downloads =
  DeviceNetworkEvents
  | where Timestamp >= ago(lookback)
  | where isnotempty(RemoteUrl)
  | where RemoteUrl has_any (".dll", ".sys", ".exe", ".bin", ".dat")
  | project
      DownloadTime = Timestamp,
      DeviceName,
      DeviceId,
      RemoteUrl,
      RemoteIP,
      RemotePort,
      NetInitiatingProcessFileName      = InitiatingProcessFileName,
      NetInitiatingProcessCommandLine   = InitiatingProcessCommandLine;

// ------------------------------------------------------------
// Step 5: Correlate drops ↔ image loads ↔ net downloads ↔ registry
// ------------------------------------------------------------
file_drops
| join kind=leftouter (
    image_loads
  ) on DeviceId, DeviceName, $left.SHA256 == $right.ImageSHA256
| join kind=leftouter (
    net_downloads
  ) on DeviceId, DeviceName
| join kind=leftouter (
    reg_persistence
  ) on DeviceId, DeviceName
| extend
    LoadDelayMin =
      iif(isnotempty(LoadTime),
          datetime_diff("minute", LoadTime, DropTime),
          real(null)),
    DroppedInWritable =
      iif(FolderPath has_any (writable_driver_locations), 1, 0),
    IsHighValueProc =
      iif(ProcessName in (high_value_processes)
          or NetInitiatingProcessFileName in (high_value_processes), 1, 0),
    IsLolbinLoader =
      iif(InitiatingProcessFileName in (lolbin_loaders)
          or NetInitiatingProcessFileName in (lolbin_loaders), 1, 0)

// TI join – hash-based enrichment
| join kind=leftouter (
    TI
    | where TI_Type == "FileHash"
  ) on $left.SHA256 == $right.TI_Indicator
| extend
    HashTI_Confidence = coalesce(TI_Confidence, 0),
    HashTI_Threat     = TI_Threat

// TI join – network-based enrichment
| join kind=leftouter (
    TI
    | where TI_Type in ("IP","URL","DomainName")
  ) on $left.RemoteUrl == $right.TI_Indicator
     or $left.RemoteIP == $right.TI_Indicator
| extend
    NetTI_Confidence = coalesce(TI_Confidence, 0),
    NetTI_Threat     = TI_Threat

// ------------------------------------------------------------
// Behavioural flags – fast DLL, dormant driver, dormant DLL
// ------------------------------------------------------------

// Quick DLL load (3CX / SolarWinds-style fast sideload)
| extend SuspiciousDLLFast =
    iif(IsDLL == 1
        and isnotempty(LoadTime)
        and LoadDelayMin >= 0
        and LoadDelayMin <= 5,
        1, 0)

// Parent is high-value process (3CX/SolarWinds style)
| extend FastDLL_ParentHighValue =
    iif(IsDLL == 1
        and SuspiciousDLLFast == 1
        and ProcessName in (high_value_processes),
        1, 0)

// DLL loader is a LO(L)BIN
| extend FastDLL_LoaderLOLBIN =
    iif(IsDLL == 1
        and SuspiciousDLLFast == 1
        and ProcessName in (lolbin_loaders),
        1, 0)

// Dormant driver (F5-style BYOVD)
| extend DormantDriver =
    iif(IsDriver == 1
        and DropTime <= now() - dormant_window
        and isnull(LoadTime),
        1, 0)

// Dormant DLL (SolarWinds-style staged loader)
// NOTE: constrained to writable paths to avoid noise.
| extend DormantDLL =
    iif(IsDLL == 1
        and DroppedInWritable == 1
        and DropTime <= now() - dormant_window
        and isnull(LoadTime),
        1, 0)

// ------------------------------------------------------------
// Confidence scoring
// ------------------------------------------------------------
| extend ConfidenceScore =
    iif(SHA256 in (known_malicious_hashes), 5, 0) +
    iif(HashTI_Confidence > 0, 4, 0) +
    iif(NetTI_Confidence > 0, 3, 0) +
    iif(DroppedInWritable == 1, 2, 0) +
    iif(isnotempty(RegistryKey), 2, 0) +
    iif(SuspiciousDLLFast == 1, 2, 0) +
    iif(DormantDriver == 1, 3, 0) +
    iif(IsHighValueProc == 1, 2, 0) +
    iif(IsLolbinLoader == 1, 1, 0) +
    iif(DormantDLL == 1, 3, 0)

// Human-readable reason
| extend Reason =
    case(
        SHA256 in (known_malicious_hashes), "Known malicious hash",
        HashTI_Confidence > 0, strcat("Hash matched TI (", HashTI_Threat, ")"),
        DormantDriver == 1, "Dormant driver >7d with no load",
        DormantDLL == 1, "Dormant DLL in writable directory >7d",
        SuspiciousDLLFast == 1, "DLL loaded <5m after drop (sideloading suspected)",
        DroppedInWritable == 1, "File dropped in user-writable/system-abused directory",
        isnotempty(RegistryKey), "Registry persistence referencing executable/script",
        NetTI_Confidence > 0, strcat("Network IOC matched TI (", NetTI_Threat, ")"),
        isnotempty(RemoteUrl), "Downloaded executable payload from remote URL",
        "—"
    )

// MITRE ATT&CK techniques
| extend MITRE_Techniques =
    strcat_array(
      bag_keys(
        pack(
          "T1574.001", iif(SuspiciousDLLFast == 1, 1, 0),   // DLL sideloading/component hijack
          "T1543.003", iif(IsDriver == 1, 1, 0),            // Windows service / driver install
          "T1547.001", iif(isnotempty(RegistryKey), 1, 0),  // Registry Run keys / persistence
          "T1105",     iif(isnotempty(RemoteUrl), 1, 0),    // Ingress Tool Transfer
          "T1195",     1                                   // Supply-chain compromise (contextual)
        )
      ),
      ", "
    )

// Analyst notes
| extend ThreatHunterNotes = strcat(
    iif(SuspiciousDLLFast == 1, "DLL rapidly executed after drop. ", ""),
    iif(DormantDriver == 1, "Driver has been dormant >7 days with no observed load. ", ""),
    iif(DormantDLL == 1, "DLL has been dormant >7 days in writable directory. ", ""),
    iif(DroppedInWritable == 1, "File dropped in user-writable or commonly abused folder. ", ""),
    iif(isnotempty(RegistryKey), strcat("Registry persistence key: ", RegistryKey, ". "), ""),
    iif(isnotempty(RemoteUrl), strcat("Downloaded from: ", RemoteUrl, ". "), ""),
    iif(HashTI_Confidence > 0, strcat("Hash matched TI: ", HashTI_Threat, ". "), ""),
    iif(NetTI_Confidence > 0, strcat("Network IOC matched TI: ", NetTI_Threat, ". "), "")
)

// Filter by score
| where ConfidenceScore >= confidence_threshold

// Threat Hunter triage guidance (single-line)
| extend ThreatHunterDirective = case(
    ConfidenceScore >= 9 and SuspiciousDLLFast == 1 and IsDLL == 1 and FastDLL_ParentHighValue == 1,
        "CRITICAL: Likely DLL sideloading supply-chain compromise (3CX/SolarWinds-style). Isolate host, validate parent binary integrity, and hunt for lateral movement.",
    ConfidenceScore >= 9 and IsDriver == 1,
        "CRITICAL: Suspicious driver activity consistent with BYOVD/F5-style compromise. Isolate device, validate driver signing and source, review services and ELAM logs.",
    ConfidenceScore >= 8 and DormantDriver == 1,
        "HIGH: Dormant driver dropped >7 days ago with no load events. Investigate origin, creation process, and check for scheduled tasks or services that may activate it.",
    ConfidenceScore >= 7 and DormantDLL == 1,
        "HIGH: Dormant DLL in writable path; potential staged loader (SolarWinds-style). Confirm if DLL is legitimate, compare against vendor baselines, and assess for tampering.",
    ConfidenceScore >= 6 and isnotempty(RegistryKey),
        "HIGH: Registry-based persistence referencing executable/script. Validate key against baseline, check legitimacy of initiating process, and inspect for follow-on payloads.",
    ConfidenceScore >= 5 and isnotempty(RemoteUrl),
        "MEDIUM: Remote download of executable component. Review parent process, subsequent DLL/driver loads, and any second-stage downloads.",
    ConfidenceScore >= 4 and DroppedInWritable == 1,
        "MEDIUM: Executable or component dropped in user-writable/system-abused directory. Inspect user context, initiating process, and correlate with image loads and network activity.",
    ConfidenceScore < 4,
        "LOW: Monitor for escalation; correlate with future anomalous events.",
    "No action required."
)

// Multi-step hunting checklist (array for UI rendering)
| extend HuntingDirectives = pack_array(
    "1) Confirm whether this DLL/driver is expected for the application or vendor; compare against golden image or known-good baseline.",
    "2) Review initiating process lineage (parent, grandparent) and command line. Check if it matches known installer/update behaviour.",
    "3) For DLL sideload patterns, inspect the parent process (e.g. 3CX/SolarWinds or other high-trust software) and verify their binaries and signatures.",
    "4) For drivers, validate signing state, origin of installation, and associated services. Review system event logs for driver load failures or tampering.",
    "5) Pivot into DeviceNetworkEvents around drop/load times to identify C2 or staging infrastructure (unusual IPs, domains, or URLs).",
    "6) If compromise is suspected, isolate the endpoint, acquire forensic artefacts, and feed confirmed hashes/URLs/IPs into MISP/TI for future scoring.",
    "7) Hunt across the environment for the same hash, filename, persistence pattern, or RemoteUrl to identify additional impacted hosts."
)

// Final projection
| project DropTime, LoadTime, DownloadTime, RegTime, DeviceName, FileName, SHA256, FolderPath,ImageFileName, ProcessName, RemoteUrl, RemoteIP,RegistryKey,RegistryValueData, SuspiciousDLLFast, DormantDriver, DormantDLL, DroppedInWritable, IsDriver, IsDLL,ConfidenceScore, Reason,ThreatHunterNotes, MITRE_Techniques,ThreatHunterDirective, HuntingDirectives
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
