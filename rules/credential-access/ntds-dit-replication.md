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

// -------------------- Stage 5 —
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
