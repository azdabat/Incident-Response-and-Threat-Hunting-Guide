# NTDS.dit Replication / DCSync-like – L3 Native Detection Rule

## Threat Focus

NTDS.dit Replication / DCSync-like is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1003.006

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =============================
// DCSync / NTDS.dit Replication – Native L3 Detection
// MITRE: T1003.006 (DCSync), T1003.003 (NTDS.dit)
// Author: Ala Dabat (Alstrum)
// =============================

let lookback = 14d;

// AD Replication permissions that only DCs should hold
let replicationRights = dynamic([
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set"
]);

// Processes often used to invoke DCSync
let dcsync_tools = dynamic([
    "mimikatz.exe", "rubeus.exe", "powershell.exe",
    "sharpsec.exe", "lsadump.exe", "adexploit.exe"
]);

// 1. Permission abuse (Event 4662)
let perm_abuse =
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4662
| where ObjectName has "Domain" or ObjectName has "Directory"
| where AccessMaskName has_any (replicationRights)
| project Timestamp=TimeGenerated, AccountName, SubjectUserName, SubjectLogonId,
          ObjectName, AccessMaskName, DeviceName=Computer;

// 2. Kerberos signs of DCSync prep (krbtgt tgt/tgs)
let krb_abuse =
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4769 or EventID == 4768
| where ServiceName has_any ("krbtgt","KRBTGT")
| project Timestamp=TimeGenerated, AccountName, DeviceName=Computer,
          ServiceName, TicketOptions;

// 3. Endpoint process correlation
let proc_hits =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (dcsync_tools)
      or ProcessCommandLine has_any ("lsadump","dcsync","GetNCChanges")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine;

// 4. RPC/LDAP traffic anomalies
let rpc_ldap =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (135,389,3268,3269)
| where InitiatingProcessFileName !in ("lsass.exe","winlogon.exe","services.exe")
| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine;

// Final correlation
perm_abuse
| join kind=leftouter krb_abuse on DeviceName
| join kind=leftouter proc_hits on DeviceName
| join kind=leftouter rpc_ldap on DeviceName
| extend HasTooling = iif(isnotempty(FileName), 1, 0),
         KerberosAnomaly = iif(ServiceName has "krbtgt", 1, 0),
         LDAPAnomaly = iif(isnotempty(RemoteIP), 1, 0),
         ReplicationEvent = iif(isnotempty(AccessMaskName), 1, 0)
| extend ConfidenceScore =
    5 * ReplicationEvent +
    3 * KerberosAnomaly +
    3 * HasTooling +
    2 * LDAPAnomaly
| extend Reason = strcat(
    iif(ReplicationEvent == 1, "AD replication permissions from non-DC. ", ""),
    iif(KerberosAnomaly == 1, "Suspicious KRBTGT ticket request. ", ""),
    iif(HasTool

```

Additional Query for NTDS.dit exfiltration, Kerberos attack vectors.
```
// -------------------------------------------
// NTDS / Golden Ticket Detection with MISP TI and Correlation
// Author: Ala Dabat 2024
// -------------------------------------------

// Lookback window
let lookback = 7d;

// Suspicious NTDS / VSS commands
let suspicious_commands = dynamic(["create full","ntds","ntdsutil","ac i ntds"]);
let vssadmin_vector = dynamic(["create shadow","/for=C","delete shadows","shadowcopy"]);
let ntds_paths = dynamic(@["\\ntds.dit","\\ntds\\","\\AppData\\","\\Downloads\\","\\Desktop\\","\\Temp\\","\\Users\\Public\\","\\windows\\"]);

// Load MISP indicators from Sentinel ThreatIntelligenceIndicator table
let MISPIndicators = ThreatIntelligenceIndicator
| where IndicatorType in ("FileHash","FileName","IP","URL","Registry")
| project IndicatorType, IndicatorValue = Indicator, TI_Score = 100;



// ----------------------------
// 1️ Suspicious NTDS-related processes - MISP Integration
// ----------------------------
let SuspiciousProcesses = DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in ("ntdsutil.exe","vssadmin.exe","esentutl.exe","wbadmin.exe","python.exe","powershell.exe","mimikatz.exe","secretsdump.py")
| where ProcessCommandLine has_any (suspicious_commands)
    or InitiatingProcessCommandLine has_any(suspicious_commands)
    or ProcessCommandLine has_any(vssadmin_vector)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, InitiatingProcessAccountName, ProcessId
| extend IndicatorType="Process", Score=40;

// Enrich processes with MISP FileName / SHA1
let SuspiciousProcessesEnriched = SuspiciousProcesses
| join kind=leftouter (
    MISPIndicators
    | where IndicatorType in ("FileName","FileHash")
    | project TI_Indicator = IndicatorValue, TI_Type = IndicatorType, TI_Score
) on $left.FileName == $right.TI_Indicator
| extend TotalScore = Score + coalesce(TI_Score,0);

// ----------------------------
// 2️ Suspicious NTDS file access / copies
// ----------------------------
let SuspiciousFiles = DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FileName has_cs "ntds.dit" or FolderPath has_any (ntds_paths)
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| extend IndicatorType="File", Score=30;

// Enrich files with MISP FileName / SHA1
let SuspiciousFilesEnriched = SuspiciousFiles
| join kind=leftouter (
    MISPIndicators
    | where IndicatorType in ("FileName","FileHash")
    | project TI_Indicator = IndicatorValue, TI_Type = IndicatorType, TI_Score
) on $left.FileName == $right.TI_Indicator
| extend TotalScore = Score + coalesce(TI_Score,0);

// ----------------------------
// 3️ Suspicious network exfil events
// ---------------------------
let SuspiciousNetwork = DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessCommandLine has_any ("Invoke-NinjaCopy","secretsdump.py","secret_dump","A c i ntds","Invoke-Mimikatz")
| project Timestamp, DeviceName, RemoteIP, RemotePort, BytesSent, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| extend IndicatorType="Network", Score=25;

// Enrich network events with MISP IP / URL
let SuspiciousNetworkEnriched = SuspiciousNetwork
| join kind=leftouter (
    MISPIndicators
    | where IndicatorType in ("IP","URL")
    | project TI_Indicator = IndicatorValue, TI_Type = IndicatorType, TI_Score
) on $left.RemoteIP == $right.TI_Indicator or $left.InitiatingProcessCommandLine has $right.TI_Indicator
| extend TotalScore = Score + coalesce(TI_Score,0);

// ----------------------------
// 4️ Correlation: Boost network score if following suspicious process/file
// ----------------------------
let CorrelatedNetwork = SuspiciousNetworkEnriched
| join kind=inner (
    union(SuspiciousProcessesEnriched, SuspiciousFilesEnriched)
    | project DeviceName, IndicatorType, Timestamp, TotalScore
) on DeviceName
| where Timestamp >= Timestamp1 and Timestamp <= Timestamp1 + 15m  // network within 15m of process/file
| extend TotalScore = TotalScore + 20  // boost correlated events

// ----------------------------
// 5️ Combine all indicators
// ----------------------------
let AllIndicators = union(SuspiciousProcessesEnriched, SuspiciousFilesEnriched, CorrelatedNetwork)
| extend Time = Timestamp;

// ----------------------------
// 6️ Summarize by Device + File/Process
// ----------------------------
AllIndicators
| summarize TotalScore = sum(TotalScore),
            Indicators = make_set(IndicatorType),
            FirstSeen = min(Time),
            LastSeen = max(Time),
            Samples = make_list(pack_all())
            by DeviceName, FileName, InitiatingProcessFileName
| where TotalSco


```


The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
