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

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
