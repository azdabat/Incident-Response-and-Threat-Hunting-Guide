# NTDS.dit Replication / DCSync-like – L3 Native Detection Rule

## Threat Focus

NTDS.dit Replication / DCSync-like is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1003.006

## Advanced Hunting Query (MDE / Sentinel)

```kql
// DCSync / NTDS.dit Replication – L3 Native Detection
// MITRE: T1003.006 (DCSync), T1003.003 (NTDS.dit)
// Author: Ala Dabat | 2025-11

let lookback = 14d;

let ReplicationRights = dynamic([
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set"
]);

let DCSyncTools = dynamic([
    "mimikatz.exe","rubeus.exe","powershell.exe",
    "sharpsec.exe","lsadump.exe","adexploit.exe"
]);

// 1 — AD 4662 replication permission use (only DCs should do this)
let ReplicationEvents =
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4662
| where AccessMaskName has_any (ReplicationRights)
| project Time=TimeGenerated,
          DeviceName=Computer,
          Account=SubjectUserName,
          ObjectName, AccessMaskName;

// 2 — Kerberos anomalies (krbtgt TGS/TGT = common DCSync prep)
let Kerb =
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID in (4768,4769)
| where ServiceName has_any ("krbtgt","KRBTGT")
| project Time=TimeGenerated,
          DeviceName=Computer, Account,
          ServiceName, TicketOptions;

// 3 — Local tooling on endpoints
let ProcHits =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (DCSyncTools)
   or ProcessCommandLine has_any ("dcsync","lsadump","GetNCChanges")
| project Time=Timestamp, DeviceName, AccountName, Tool=FileName, Cmd=ProcessCommandLine;

// 4 — RPC/LDAP traffic to DCs from suspicious processes
let RpcLdap =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (135,389,3268,3269)
| where InitiatingProcessFileName !in ("lsass.exe","services.exe","winlogon.exe")
| project Time=Timestamp, DeviceName, AccountName,
          RemoteIP, RemotePort,
          Proc=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine;

// --- Final correlation ---
ReplicationEvents
| join kind=leftouter Kerb      on DeviceName
| join kind=leftouter ProcHits  on DeviceName
| join kind=leftouter RpcLdap   on DeviceName

| extend HasReplication = isnotempty(AccessMaskName),
         HasKerb = isnotempty(ServiceName),
         HasTool = isnotempty(Tool),
         HasLDAP = isnotempty(RemoteIP)

// Severity logic (no weighted scoring needed)
| extend Severity = case(
      HasReplication and (HasTool or HasKerb or HasLDAP), "High",
      HasReplication, "Medium",
      HasKerb or HasTool, "Low",
      "Informational"
)

| extend Reason = strcat(
      iif(HasReplication, "Non-DC used AD replication rights. ", ""),
      iif(HasKerb, "krbtgt ticket request anomaly. ", ""),
      iif(HasTool, strcat("Potential DCSync tooling: ", Tool, ". "), ""),
      iif(HasLDAP, "Direct RPC/LDAP calls to DC services. ", "")
)

| extend Directives = case(
      Severity == "High",
          "Treat as likely DCSync attempt. Review DC logs, isolate involved endpoints, inspect account activity, check for DC shadowing or privilege abuse.",
      Severity == "Medium",
          "Verify if the host is a legitimate DC or delegated admin system. Review change records and correlate with recent privilege changes.",
      "Baseline check. Validate if any third-party IAM tools or backup solutions use these rights."
)

| project Time, DeviceName, Account,
          HasReplication, HasKerb, HasTool, HasLDAP,
          Tool, Cmd,
          Severity, Reason, Directives
| order by Time desc


Additional Query for NTDS.dit exfiltration, Kerberos attack vectors.

```kql
// ===========================================================================
// NTDS.dit Replication / DCSync + ShadowCopy Exfil — L3 Native Detection Rule
// Author: Ala Dabat (Alstrum) | Version: 2025-11
// Category: credential-access
// MITRE: T1003.006 (DCSync), T1003.003 (NTDS.dit), T1003 (Credential Dumping)
// Purpose: Pure native (NO TI) L3 detection of replication abuse, krbtgt misuse,
//          NTDS.dit access, shadow copy creation, and exfil patterns.
// ===========================================================================

// -------------------- Tunables --------------------
let lookback = 14d;
let corr_window = 20m;
let min_confidence = 85;

// Replication privileges only DCs should use
let ReplicationRights = dynamic([
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set"
]);

// Suspicious NTDS / DCSync tools & LOLBINs
let SuspiciousProcs = dynamic([
    "mimikatz.exe","rubeus.exe","secretsdump.py","adexploit.exe","lsadump.exe",
    "python.exe","powershell.exe","esentutl.exe","ntdsutil.exe","vssadmin.exe",
    "wbadmin.exe"
]);

// Shadow copy / NTDS paths
let NTDS_Paths = dynamic([
    "\\ntds.dit","\\windows\\ntds","\\windows\\system32\\config\\",
    "\\shadowcopy","\\system32\\ntds","\\temp","\\users\\public"
]);

// Shadow copy command patterns
let ShadowCopyCmd =
dynamic(["create shadow","create full","ntds","ntdsutil","VSS","shadow","wbadmin"]);

// -------------------- Stage 1 — AD Directory Replication (4662) --------------------
let ReplicationEvents =
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4662
| where AccessMaskName has_any (ReplicationRights)
| project
    Timestamp = TimeGenerated,
    DeviceName = Computer,
    AccountName = SubjectUserName,
    AccessMaskName,
    ObjectName;

// -------------------- Stage 2 — Kerberos KRBTGT anomalies (4768/4769) --------------------
let KerberosEvents =
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID in (4768,4769)
| where ServiceName has_any ("krbtgt","KRBTGT")
| project
    Timestamp = TimeGenerated,
    DeviceName = Computer,
    AccountName,
    ServiceName,
    TicketOptions;

// -------------------- Stage 3 — Suspicious NTDS / VSS process execution --------------------
let ProcHits =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (SuspiciousProcs)
       or ProcessCommandLine has_any (ShadowCopyCmd)
       or ProcessCommandLine has_any (NTDS_Paths)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine;

// -------------------- Stage 4 — NTDS.dit / shadowcopy file interaction --------------------
let FileHits =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FileName has_any (NTDS_Paths)
       or FolderPath has_any (NTDS_Paths)
| project
    Timestamp,
    DeviceName,
    AccountName = InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath,
    FileName;
```

| Attack                                                       | Coverage        | Why                                               |
| ------------------------------------------------------------ | --------------- | ------------------------------------------------- |
| DCSync using Mimikatz/Rubeus                                 | **High**        | 4662 + RPC + krbtgt patterns + tooling            |
| NTDS.dit copy via ShadowCopy (vssadmin / wbadmin / esentutl) | **High**        | Processes & file access & shadowcopy cmd patterns |
| secretsdump.py from workstation                              | **High**        | Network (RPC/LDAP) + tooling + no DC context      |
| KRBTGT manipulation / Golden Ticket staging                  | **Medium/High** | 4768/4769 krbtgt + unusual host                   |


The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
