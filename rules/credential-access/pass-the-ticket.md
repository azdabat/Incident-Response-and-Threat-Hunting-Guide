# Pass-the-Ticket / Kerberos Ticket Abuse – L3 Native Detection Rule

## Threat Focus

Pass-the-Ticket / Kerberos Ticket Abuse is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1550.003, T1558.003

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================
// Pass-the-Ticket (PTT) – Native L3 Detection (Noise-Reduced)
// Author: Ala Dabat (Alstrum)
// MITRE: T1550.003 (Pass-the-Ticket), T1558.003 (Kerberos Tickets)
// Behavioural focus: Kerberos ticket replay / forging
// =====================================================

let lookback = 14d;
let min_events = 5;
let min_unique_spns = 3;

// Optional: known DCs / KDCs or Kerberos infra hosts (tune for your env)
let DomainControllers = dynamic([
    // "dc01.contoso.local",
    // "dc02.contoso.local"
]);

// Common PTT / Kerberos tooling (extend as needed)
let PTTTools = dynamic([
    "rubeus.exe", "mimikatz.exe", "kekeo.exe",
    "ticket.exe", "invoke-mimikatz.ps1", "sekurlsa.dll"
]);

// Sensitive SPNs attackers often target to elevate or move laterally
let SensitiveSPNs = dynamic([
    "cifs/", "host/", "ldap/", "mssqlsvc/",
    "krbtgt", "http/", "wsman/", "termsrv/"
]);

// High-value account patterns (tune to your naming conventions)
let HighValueAccounts = dynamic([
    "admin", "administrator", "adm", "da",
    "tier0", "svc", "service", "backup", "sql"
]);

// =====================================================
// 1. Kerberos activity (IdentityLogonEvents)
// =====================================================
let Kerb =
IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where Protocol has "Kerberos"
| where Result == "Success"
| where isnotempty(ServicePrincipalName)
| where isnotempty(AccountUpn)
| where AccountName !endswith "$"    // filter machine accounts
| extend
    SPN  = tostring(ServicePrincipalName),
    UPN  = tostring(AccountUpn),
    Host = tostring(DeviceName),
    TargetHost = tostring(TargetDeviceName),
    EncType = tostring(EncryptionType)
| where Host !in (DomainControllers) // focus away from DCs/KDCs
| project Timestamp, UPN, Host, TargetHost, SPN, EncType;

// =====================================================
// 2. Behaviour flags on individual events
// =====================================================
let KerbEval =
Kerb
| extend IsSensitiveSPN =
    iif(SPN has_any (SensitiveSPNs), 1, 0)
| extend IsHighValueAccount =
    iif(UPN has_any (HighValueAccounts), 1, 0)
| extend IsWeakEnc =
    iif(EncType in ("rc4","rc4-hmac","des","des-cbc-crc"), 1, 0)
| extend IsCrossHost =
    iif(isnotempty(TargetHost) and Host != TargetHost, 1, 0);

// =====================================================
// 3. Aggregate per account + host (behaviour clustering)
// =====================================================
let KerbAgg =
KerbEval
| summarize
    FirstSeen        = min(Timestamp),
    LastSeen         = max(Timestamp),
    Events           = count(),
    UniqueSPNs       = dcount(SPN),
    SPNSample        = take_any(SPN),
    SPNList          = make_set(SPN, 20),
    AnySensitiveSPN  = max(IsSensitiveSPN),
    AnyWeakEnc       = max(IsWeakEnc),
    AnyCrossHost     = max(IsCrossHost),
    IsHighValue      = max(IsHighValueAccount)
  by UPN, Host
| extend DurationMinutes = datetime_diff("minute", LastSeen, FirstSeen)
| where Events >= min_events
| where UniqueSPNs >= min_unique_spns;

// =====================================================
// 4. Process evidence (tooling correlation on the host)
// =====================================================
let ProcEvidence =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (PTTTools)
   or ProcessCommandLine has_any ("ptt","kirbi","asktgt","asktgs","/ptt")
| summarize
    HasTooling = 1,
    ToolSample = take_any(FileName),
    ToolCmd    = take_any(ProcessCommandLine),
    ToolFirstSeen = min(Timestamp),
    ToolLastSeen  = max(Timestamp)
  by DeviceName;

KerbAgg
| join kind=leftouter (ProcEvidence) on $left.Host == $right.DeviceName
| extend HasTooling = iif(isnotempty(HasTooling), 1, 0)

// =====================================================
// 5. Behaviour-based confidence scoring (noise-aware)
// =====================================================
| extend BaseScore = 70
| extend ConfidenceScore =
    BaseScore
    // Strong signals: tooling + high-value account + sensitive SPNs
    + iif(HasTooling == 1 and IsHighValue == 1,           10, 0)
    + iif(HasTooling == 1 and AnySensitiveSPN == 1,       8, 0)
    // High-value accounts touching sensitive SPNs
    + iif(IsHighValue == 1 and AnySensitiveSPN == 1,      6, 0)
    // Weak/legacy encryption for high-value accounts
    + iif(AnyWeakEnc == 1 and IsHighValue == 1,           4, 0)
    // Cross-host usage suggests lateral tickets, not local
    + iif(AnyCrossHost == 1 and IsHighValue == 1,         4, 0)
    // High SPN fan-out for a single account (sweep / replay)
    + iif(UniqueSPNs >= 10,                               4, 0)
    + iif(UniqueSPNs between (6 .. 9),                    2, 0);

// Reason text
| extend Reason = strcat(
    iif(HasTooling == 1,
        strcat("PTT/kerberos tooling observed on host (e.g. ", ToolSample, "). "), ""),
    iif(IsHighValue == 1,
        "High-value account involved. ", ""),
    iif(AnySensitiveSPN == 1,
        "Kerberos activity against sensitive SPNs (cifs/host/ldap/sql/http/termsrv). ", ""),
    iif(AnyWeakEnc == 1,
        "Weak/legacy Kerberos encryption (RC4/DES) used by high-value account. ", ""),
    iif(AnyCrossHost == 1,
        "Account using Kerberos tickets across multiple hosts (possible replay). ", ""),
    iif(UniqueSPNs >= 10,
        strcat("High SPN fan-out from single account (", tostring(UniqueSPNs), " SPNs). "), "")
)

// =====================================================
// 6. Severity & hunter directives
// =====================================================
| extend Severity = case(
    ConfidenceScore >= 95, "High",
    ConfidenceScore >= 85, "Medium",
    ConfidenceScore >= 80, "Low",
    "Informational"
)
| extend MITRE_Tactics    = "TA0006 (Credential Access); TA0008 (Lateral Movement)",
         MITRE_Techniques = "T1550.003 (Pass-the-Ticket), T1558.003 (Kerberos Tickets)";

| extend ThreatHunterDirectives = strcat(
    "Severity=", Severity,
    "; Host=", Host,
    "; Account=", UPN,
    "; UniqueSPNs=", tostring(UniqueSPNs),
    "; SPNSample=", SPNSample,
    "; HasTooling=", tostring(HasTooling),
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Treat as probable Pass-the-Ticket or forged ticket usage. Validate whether the observed tickets and SPNs are legitimate for this account and host. Hunt for Rubeus/Mimikatz artefacts, LSASS access, and potential KRBTGT compromise. Isolate the host and rotate affected credentials if compromise is confirmed.",
        Severity == "Medium",
            "Confirm whether this behaviour aligns with expected service or admin activity. Investigate process history on the host, check for Kerberos-related tooling, and pivot to correlated Kerberos, LSASS, and lateral movement events in the same timeframe.",
        Severity == "Low",
            "Review as potential baseline for the account/service. If benign, consider documenting as known-good behaviour; otherwise, monitor for escalation in score or additional corroborating detections.",
        "Use as a contextual hunting signal. Combine with other credential-access and lateral-movement detections before escalation."
    )
)

// =====================================================
// 7. Final filter and projection
// =====================================================
| where ConfidenceScore >= 85   // Medium+ by default; tune for hunting vs alerting
| project
    FirstSeen,
    LastSeen,
    DurationMinutes,
    Host,
    UPN,
    UniqueSPNs,
    SPNSample,
    HasTooling,
    ToolSample,
    ConfidenceScore,
    Severity,
    MITRE_Tactics,
    MITRE_Techniques,
    Reason,
    ThreatHunterDirectives
| order by ConfidenceScore desc, LastSeen desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
