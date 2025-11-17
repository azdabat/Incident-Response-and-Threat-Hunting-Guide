# Registry Run / Startup Folder Persistence – L3 Native Detection Rule

## Threat Focus

Registry Run / Startup Folder Persistence is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: persistence
- MITRE: T1060, T1547.001

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ---------- CONFIG ----------
let PersistenceKeys = dynamic([
  // Classic
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
  @"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components", @"HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components",
  @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
  @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", @"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
  @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
  @"HKLM\SYSTEM\CurrentControlSet\Services",
  // Hijacks
  @"HKCU\Software\Classes\mscfile\shell\open\command", @"HKCU\Software\Classes\exefile\shell\open\command",
  @"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths", @"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths",
  // IFEO / COM / LSA
  @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
  @"HKCU\Software\Classes\CLSID", @"HKLM\Software\Classes\CLSID",
  @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
  // WOW64 mirrors
  @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
  @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
  @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
]);

let BadStrings = dynamic([
  // PowerShell & AMSI bypass/common stagers
  "-EncodedCommand"," -enc "," -e ","-ep bypass"," -w hidden","IEX(","Invoke-Expression","FromBase64String",
  "Invoke-WebRequest","DownloadString","Start-BitsTransfer",
  // LOLBAS
  "mshta ","rundll32 ","regsvr32 ","certutil ","bitsadmin ","curl ",
  // Injection API markers (if attackers stash commands)
  "WriteProcessMemory","VirtualAllocEx","CreateRemoteThread"
]);

let SuspExt = dynamic(["exe","dll","js","jse","vbs","vbe","wsf","hta","ps1","psm1","bat","cmd","scr"]);
let UserWritableRx = @"(?i)^[a-z]:\\(Users|Public|ProgramData|PerfLogs|Temp|Windows\\Temp|Windows\\Tasks|Windows\\Fonts)\\";
let Base64ChunkedRx = @"(?:[A-Za-z0-9+/]{20,}={0,2})(?:\s+[A-Za-z0-9+/]{20,}={0,2})+";
let IPv4Rx = @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b";
let IPv6Rx = @"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b";
let DomainRx = @"\b([a-z0-9][a-z0-9\-]{1,62}\.)+[a-z]{2,}\b";

let OrgPrevalence =
DeviceFileEvents
| where Timestamp > ago(14d)
| summarize DeviceCount=dcount(DeviceId), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SHA256, FileName, FolderPath;

let Raw =
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (PersistenceKeys)
| extend ValueData = tostring(RegistryValueData);

// Join creating/initiating process context
let WithProc =
Raw
| join kind=leftouter (
    DeviceProcessEvents
    | project Timestamp, DeviceId, InitiatingProcessId,
             IPFile=InitiatingProcessFileName,
             IPPath=InitiatingProcessFolderPath,
             IPCL=InitiatingProcessCommandLine,
             IPSHA256=InitiatingProcessSHA256,
             IPSigner=InitiatingProcessSigner,
             IPCompany=InitiatingProcessVersionInfoCompanyName,
             IPIntegrityLevel=InitiatingProcessIntegrityLevel,
             IPAccount=InitiatingProcessAccountName
) on InitiatingProcessId, DeviceId
| extend LowerData = tolower(ValueData);

// Extract indicators
let WithIOC =
WithProc
| extend HasBadString = LowerData has_any (BadStrings),
         HasBase64 = LowerData matches regex Base64ChunkedRx or LowerData matches regex @"[A-Za-z0-9+/]{40,}={0,2}",
         HasNet = LowerData matches regex @"https?://[^\s'\""]+" or LowerData matches regex IPv4Rx or LowerData matches regex IPv6Rx or LowerData matches regex DomainRx,
         PointsToUserWritable = ValueData matches regex UserWritableRx
                                or LowerData matches regex @"\\appdata\\|\\programdata\\|\\temp\\|\\public\\",
         SuspFileRef = LowerData matches regex @"(?i)\.(exe|dll|js|jse|vbs|vbe|wsf|hta|ps1|psm1|bat|cmd|scr)\b",
         IsIFEO = tolower(RegistryKey) has @"\image file execution options\",
         IsCOM = tolower(RegistryKey) has @"\clsid\" and tolower(RegistryKey) has @"inprocserver32",
         IsLSA = tolower(RegistryKey) has @"\control\lsa",
         Hive = iif(startswith(tolower(RegistryKey),"hklm"), "System-wide (HKLM)", "Per-user (HKCU/Classes)");

// Bring in prevalence & signer trust
let Enriched =
WithIOC
| join kind=leftouter (OrgPrevalence) on $left.IPSHA256 == $right.SHA256
| extend IsTrustedPublisher = iif(IPSigner in~ ("Microsoft Windows","Microsoft Windows Publisher","Microsoft Corporation","Microsoft Windows Hardware Compatibility Publisher"), true, false),
         IsRare = coalesce(DeviceCount, 0) <= 2;

// High-fidelity scoring (stack multiple independent signals)
Enriched
| extend SignalCount =
    toint(HasBadString) + toint(HasBase64) + toint(HasNet) + toint(PointsToUserWritable) +
    toint(not(IsTrustedPublisher)) + toint(IsRare) + toint(IsIFEO or IsCOM or IsLSA)
| where SignalCount >= 3  // <- L3 threshold (tune 3–4)
| project
    Timestamp, DeviceName, Hive, RegistryKey, RegistryValueName, ValueData,
    IPFile, IPPath, IPCL, IPSHA256, IPSigner, IPCompany, IPIntegrityLevel, IPAccount,
    HasBadString, HasBase64, HasNet, PointsToUserWritable, SuspFileRef, IsIFEO, IsCOM, IsLSA, IsTrustedPublisher, IsRare, SignalCount
| extend MITRE_Tactics = "TA0003 Persistence; TA0002 Execution; TA0005 Defense Evasion", 
         MITRE_Techniques =
           strcat_array(
             bag_keys(
               pack_array(
                 iif(HasBadString and LowerData has "powershell","T1059.001 PowerShell",""),
                 iif(HasBadString and LowerData has "regsvr32","T1218.010 Regsvr32",""),
                 iif(HasBadString and LowerData has "rundll32","T1218.011 Rundll32",""),
                 iif(HasBadString and LowerData has "mshta","T1218.005 Mshta",""),
                 iif(HasNet,"T1105 Ingress Tool Transfer",""),
                 iif(IsIFEO,"T1546.012 Image File Execution Options Injection",""),
                 iif(IsCOM,"T1546.015 COM Hijacking",""),
                 iif(IsLSA,"T1547.009 Security Support Provider",""),
                 iif(tolower(RegistryKey) has @"\run","T1547.001 Registry Run Keys",""),
                 iif(tolower(RegistryKey) has @"\services","T1543.003 Windows Service","")
               )
             ), "; "),
           ThreatSeverity = case(
             HasBadString and (HasBase64 or HasNet), "CRITICAL",
             (IsIFEO or IsCOM or IsLSA) and (not IsTrustedPublisher), "HIGH",
             PointsToUserWritable and (HasNet or HasBase64) and IsRare, "HIGH",
             SignalCount >= 4, "HIGH",
             "MEDIUM"
           )
| order by ThreatSeverity desc, Timestamp desc






// Hunt-mode: High-fidelity SignalCount for registry persistence writes (human review)
// Lookback
let lookback = 14d;

// Tunable allowlists (replace with watchlist joins in prod)
let TrustedPublishers = dynamic(["Microsoft Corporation","Microsoft Windows","Google LLC","Mozilla Corporation"]);
let TrustedInitiators = dynamic(["msiexec.exe","IntelGraphics.exe","sppsvc.exe","IntuneManagementExtension.exe","UpdateInstaller.exe"]);

// Persistence keys
let PersistenceKeys = dynamic([
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
  @"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components", @"HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components",
  @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
  @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", @"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
  @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
  @"HKLM\SYSTEM\CurrentControlSet\Services",
  @"HKCU\Software\Classes\mscfile\shell\open\command", @"HKCU\Software\Classes\exefile\shell\open\command",
  @"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths", @"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths",
  @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
  @"HKCU\Software\Classes\CLSID", @"HKLM\Software\Classes\CLSID",
  @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
  @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
  @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
  @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
]);

// Heuristics / regexes
let UserWritableRx = @"(?i)^[a-z]:\\(users|public|programdata|temp|downloads|appdata)\\";
let Base64ChunkedRx = @"(?:[A-Za-z0-9+/]{20,}={0,2})(?:\s+[A-Za-z0-9+/]{20,}={0,2})+";
let IPv4Rx = @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b";
let DomainRx = @"\b([a-z0-9][a-z0-9\-]{1,62}\.)+[a-z]{2,}\b";
let BadStrings = dynamic(["-encodedcommand","-enc","-ep bypass","iex(","invoke-expression","frombase64string","invoke-webrequest","downloadstring","start-bitstransfer","rundll32","regsvr32","mshta","certutil","bitsadmin","curl","writeprocessmemory","virtualallocex","createremotethread"]);

// Prevalence: where file hash has been seen recently
let OrgPrevalence = DeviceFileEvents
| where Timestamp >= ago(30d)
| summarize DeviceCount=dcount(DeviceId) by SHA256, FileName, FolderPath;

// Raw registry persistence writes
let Raw = DeviceRegistryEvents
| where Timestamp >= ago(lookback)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (PersistenceKeys)
| extend ValueData = tostring(RegistryValueData), ValueName = tostring(RegistryValueName), RegistryKeyLower = tolower(RegistryKey)
| extend LowerData = tolower(ValueData);

// Join initiating process context (best effor tmatch)
let WithProc = Raw
| join kind=leftouter (
    DeviceProcessEvents
    | project ProcTime = Timestamp, DeviceId, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessSigner, InitiatingProcessVersionInfoCompanyName, InitiatingProcessAccountName
) on InitiatingProcessId, DeviceId
| extend ProcFile = coalesce(InitiatingProcessFileName, ""), ProcPath = coalesce(InitiatingProcessFolderPath,""), ProcCL = coalesce(InitiatingProcessCommandLine,""), ProcSHA = InitiatingProcessSHA256, ProcSigner = InitiatingProcessSigner, ProcCompany = InitiatingProcessVersionInfoCompanyName, ProcUser = InitiatingProcessAccountName;

// Extract signals (binary flags)
let WithIOC =
WithProc
| extend
    HasBadString = toint(LowerData has_any (BadStrings)),
    HasBase64 = toint(LowerData matches regex Base64ChunkedRx or ProcCL matches regex Base64ChunkedRx),
    HasNet = toint(LowerData matches regex @"https?://[^\s'\""]+" or LowerData matches regex IPv4Rx or LowerData matches regex DomainRx),
    PointsToUserWritable = toint(LowerData matches regex UserWritableRx or LowerData contains "\\appdata\\" or LowerData contains "\\programdata\\" or LowerData contains "\\temp\\"),
    SuspFileRef = toint(LowerData matches regex @"(?i)\.(exe|dll|js|jse|vbs|ps1|bat|cmd|scr)\b"),
    IsIFEO = toint(RegistryKeyLower has @"\image file execution options"),
    IsCOM = toint(RegistryKeyLower has @"\clsid\" and RegistryKeyLower has @"inprocserver32"),
    IsLSA = toint(RegistryKeyLower has @"\control\lsa"),
    IsTrustedPublisher = iif(ProcSigner in (TrustedPublishers) or ProcCompany in (TrustedPublishers), 1, 0),
    InitiatorTrusted = iif(ProcFile in (TrustedInitiators), 1, 0);

// Bring in prevalence / rarity
let Enriched =
WithIOC
| join kind=leftouter (OrgPrevalence) on $left.ProcSHA == $right.SHA256
| extend DeviceCount = coalesce(DeviceCount, 0), IsRare = iif(DeviceCount <= 2, 1, 0);

// SIGNAL COUNT (human-friendly, not hidden)
Enriched
| extend SignalCount = 
    HasBadString + HasBase64 + HasNet + PointsToUserWritable + (1 - IsTrustedPublisher) + IsRare + (IsIFEO or IsCOM or IsLSA)
// Aggregate per device + registry value to reduce duplicates (hunter can expand as needed)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), 
            MaxSignals = max(SignalCount), Events = count(),
            AnyBadString = max(HasBadString), AnyBase64 = max(HasBase64), AnyNet = max(HasNet), AnyUserWritable = max(PointsToUserWritable),
            AnyIFEO = max(IsIFEO), AnyCOM = max(IsCOM), AnyLSA = max(IsLSA),
            AnyTrustedPublisher = max(IsTrustedPublisher), AnyRare = max(IsRare),
            Initiators = make_set(ProcFile,10), InitiatorSigners = make_set(ProcSigner,10), ExampleProcCL = any(ProcCL)
  by DeviceName, RegistryKey, ValueName, ValueData, ProcSHA, ProcCompany, ProcSigner, ProcUser
// Final: return human readable table for triage
| extend MITRE_Tactics = "TA0003 Persistence; TA0002 Execution; TA0005 Defense Evasion"
| extend MITRE_Techniques = strcat_array(
    pack_array(
      iif(AnyBadString==1 and ExampleProcCL has "powershell","T1059.001 PowerShell",""),
      iif(AnyBadString==1 and ExampleProcCL has "regsvr32","T1218.010 Regsvr32",""),
      iif(AnyBadString==1 and ExampleProcCL has "rundll32","T1218.011 Rundll32",""),
      iif(AnyBadString==1 and ExampleProcCL has "mshta","T1218.005 Mshta",""),
      iif(AnyNet==1,"T1105 Ingress Tool Transfer",""),
      iif(AnyIFEO==1,"T1546.012 IFEO Injection",""),
      iif(AnyCOM==1,"T1546.015 COM Hijacking",""),
      iif(AnyLSA==1,"T1547.009 LSA / SSP Hijack",""),
      iif(tolower(RegistryKey) has @"\run","T1547.001 Registry Run Keys",""),
      iif(tolower(RegistryKey) has @"\services","T1543.003 Windows Service","")
    ), "; ")
| project FirstSeen, LastSeen, DeviceName, ProcUser, ProcCompany, ProcSigner, ProcSHA, RegistryKey, ValueName, ValueData, MaxSignals, Events, AnyNet, AnyBase64, AnyBadString, AnyUserWritable, AnyIFEO, AnyCOM, AnyLSA, AnyRare, Initiators, InitiatorSigners, ExampleProcCL, MITRE_Tactics, MITRE_Techniques
| order by MaxSignals desc, LastSeen desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
