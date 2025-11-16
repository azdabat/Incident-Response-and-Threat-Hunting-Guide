# Pass-the-Ticket / Kerberos Ticket Abuse – L3 Native Detection Rule

## Threat Focus

Pass-the-Ticket / Kerberos Ticket Abuse is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1550.003, T1558.003

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================
// Pass-the-Ticket (PTT) – Native L3 Detection
// Author: Ala Dabat (Alstrum)
// MITRE: T1550.003, T1558.003
// Behavioural focus: Kerberos ticket replay / forging
// =====================================================

let lookback = 14d;

// Common PTT tooling (extend as needed)
let PTTTools = dynamic([
    "rubeus.exe", "mimikatz.exe", "kekeo.exe",
    "ticket.exe", "invoke-mimikatz.ps1", "sekurlsa.dll"
]);

// Sensitive SPNs attackers target to elevate or move laterally
let SensitiveSPNs = dynamic([
    "cifs/", "host/", "ldap/", "mssqlsvc/",
    "krbtgt", "http/", "wsman/", "termsrv/"
]);

// High-value account patterns
let HighValueAccounts = dynamic([
    "admin", "administrator", "adm", "da", "tier0", 
    "svc", "service", "backup", "sql", "$"
]);

// =======================================
// 1. Suspicious Kerberos TGS/TGT Activity
// =======================================
let Kerb =
IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where Protocol has "Kerberos"
| extend SPN = tostring(ServicePrincipalName),
         UPN = tostring(AccountUpn),
         Host = tostring(DeviceName),
         TargetHost = tostring(TargetDeviceName),
         EncType = tostring(EncryptionType)
| project Timestamp, UPN, Host, TargetHost, SPN, EncType;

// =======================================
// 2. Identify anomalies based on behaviour
// =======================================
let KerbEval =
Kerb
| extend IsSensitiveSPN =
    iif(SPN has_any (SensitiveSPNs), 1, 0)
| extend IsHighValueAccount =
    iif(UPN has_any (HighValueAccounts), 1, 0)
| extend IsWeakEnc =
    iif(EncType in ("rc4","des","rc4-hmac","des-cbc-crc"), 1, 0)
| extend IsTargetMismatch =
    iif(Host != TargetHost and isnotempty(TargetHost), 1, 0);

// =======================================
// 3. Aggregate per account+host (behaviour clustering)
// =======================================
let KerbAgg =
KerbEval
| summarize
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp),
    Events = count(),
    UniqueSPNs = dcount(SPN),
    SPNSample = take_any(SPN),
    SPNList = make_set(SPN, 20),
    AnySensitiveSPN = max(IsSensitiveSPN),
    AnyWeakEnc = max(IsWeakEnc),
    AnyTargetMismatch = max(IsTargetMismatch),
    IsHighValue = max(IsHighValueAccount)
  by UPN, Host;

// =======================================
// 4. Process evidence (tooling correlation)
// =======================================
let Proc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (PTTTools)
       or ProcessCommandLine has_any ("ptt","kirbi","ticket","asktgt","asktgs")
| project DeviceName, AccountName, FileName, ProcessCommandLine, ProcTime=Timestamp;

// Join process evidence to Kerberos aggregation
KerbAgg
| join kind=leftouter Proc on $left.Host == $right.DeviceName
| extend HasTooling = iif(isnotempty(FileName), 1, 0)

// =======================================
// 5. Confidence scoring (behaviour-based)
// =======================================
| extend ConfidenceScore =
    0
    + iif(AnySensitiveSPN == 1,         4, 0)
    + iif(AnyWeakEnc == 1,             2, 0)
    + iif(AnyTargetMismatch == 1,      3, 0)
    + iif(IsHighValue == 1,            4, 0)
    + iif(HasTooling == 1,             5, 0)
    + iif(UniqueSPNs >= 10,            4, 0)
    + iif(UniqueSPNs between (5 .. 9), 2, 0)

| extend Reason = strcat(
    iif(AnySensitiveSPN == 1,      "Kerberos use against sensitive SPNs. ", ""),
    iif(AnyWeakEnc == 1,           "Weak/legacy encryption (RC4/DES) detected. ", ""),
    iif(AnyTargetMismatch == 1,    "SPN↔Host mismatch indicating replay or tampering. ", ""),
    iif(IsHighValue == 1,          "High-value account involved. ", ""),
    iif(HasTooling == 1,           strcat("PTT tooling observed: ", FileName, ". "), ""),
    iif(UniqueSPNs >= 10,          "High SPN fan-out from single account (lateral sweep). ", "")
)

// =======================================
// 6. Severity + HuntingDirectives
// =======================================
| extend Severity = case(
    ConfidenceScore >= 12, "High",
    ConfidenceScore >= 7,  "Medium",
    ConfidenceScore >= 3,  "Low",
    "Informational"
)
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Host=", Host,
    "; Account=", UPN,
    "; UniqueSPNs=", tostring(UniqueSPNs),
    "; SPNSample=", SPNSample,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Validate whether the ticket is legitimate. Check for Rubeus/Mimikatz artifacts. Review LSASS access on Host. Check for compromised KRBTGT. Investigate identity manipulation, session hijacking, and lateral movement within ±24h. If needed: isolate host.",
        Severity == "Medium",
            "Confirm operational context (scheduled tasks, admin tools, service accounts). Investigate SPN mismatch or privilege escalation intent. Pivot for related Kerberos or process anomalies.",
        Severity == "Low",
            "Validate baseline behaviour for this service/account. Consider tuning thresholds for SPN fan-out.",
        "Use as contextual signal only."
    )
)

// =======================================
// 7. Results
// =======================================
| where ConfidenceScore >= 3
| order by LastSeen desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
