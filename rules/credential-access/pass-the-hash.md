# Pass-the-Hash Pattern (NTLM) – L3 Native Detection Rule

## Threat Focus

Pass-the-Hash Pattern (NTLM) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: credential-access
- MITRE: T1550.002

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ==============================================
// Pass-the-Hash (NTLM Network Lateral) – L3 Native Detection
// Category: credential-access / lateral movement
// MITRE: T1550.002 (Pass-the-Hash), T1078 (Valid Accounts)
// Author: Ala Dabat (Alstrum)
// ==============================================

let lookback = 14d;

// High-value account patterns (tune for your environment)
let HighValueAccountPatterns = dynamic([
    "admin", "administrator", "adm", "da", "dadmin",
    "svc", "service", "sql", "oracle",
    "backup", "krbtgt", "$"
]);

// Known / expected domain controllers (OPTIONAL - tune or leave empty)
let DomainControllers = dynamic([
    // "dc01.contoso.local",
    // "dc02.contoso.local"
]);

// 1. Collect successful NTLM "Resource Access" network logons
let NtlsNetLogons =
IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where LogonType == "Resource Access"   // Logon type 3 semantics in this table
| where Protocol has "NTLM"              // Explicit NTLM usage
| where isnotempty(DeviceName) 
| where isnotempty(TargetDeviceName)
| extend ClientHost  = tostring(DeviceName),
         TargetHost  = tostring(TargetDeviceName),
         UPN         = tostring(AccountUpn),
         UName       = tostring(AccountName)
;

// 2. Aggregate per client + account (who is sweeping where?)
let PtHClusters =
NtlsNetLogons
| summarize
    FirstSeen        = min(Timestamp),
    LastSeen         = max(Timestamp),
    Events           = count(),
    UniqueTargets    = dcount(TargetHost),
    TargetSample     = take_any(TargetHost),
    TargetList       = make_set(TargetHost, 20)
  by ClientHost, UPN, UName, Protocol
| extend DurationMin = datetime_diff("minute", LastSeen, FirstSeen)
;

// 3. Heuristics: high-value accounts, many targets, non-DC client
PtHClusters
| extend IsHighValueAccount =
    iif(
        UName has_any (HighValueAccountPatterns)
        or UPN has_any (HighValueAccountPatterns),
        1, 0
    )
| extend IsDomainControllerClient =
    iif(ClientHost in (DomainControllers), 1, 0)
// If you haven’t populated DomainControllers, this just evaluates to 0s and is harmless.

// Suspicion factors
| extend Susp_ManyTargets    = iif(UniqueTargets >= 5, 1, 0)
| extend Susp_MediumTargets  = iif(UniqueTargets between (2 .. 4), 1, 0)
| extend Susp_ShortBurst     = iif(DurationMin <= 30 and Events >= 10, 1, 0)
| extend Susp_HighValueFromWS = iif(IsHighValueAccount == 1 and IsDomainControllerClient == 0, 1, 0)

// Confidence scoring – tune as needed
| extend ConfidenceScore =
    0
    + iif(Susp_ManyTargets == 1,           4, 0)
    + iif(Susp_MediumTargets == 1,         2, 0)
    + iif(Susp_ShortBurst == 1,            2, 0)
    + iif(Susp_HighValueFromWS == 1,       4, 0)
| extend Reason = strcat(
    iif(Susp_ManyTargets == 1,
        strcat("Account sweeping many targets over NTLM (", tostring(UniqueTargets), " unique servers). "), ""),
    iif(Susp_MediumTargets == 1,
        strcat("Account using NTLM network logon to multiple targets (", tostring(UniqueTargets), "). "), ""),
    iif(Susp_ShortBurst == 1,
        strcat(" NTLM activity clustered in short window (", tostring(DurationMin), " minutes, ", tostring(Events), " events). "), ""),
    iif(Susp_HighValueFromWS == 1,
        " High-value account using NTLM from non-DC workstation. ", "")
)

// Map to severity
| extend Severity = case(
    ConfidenceScore >= 8, "High",
    ConfidenceScore >= 5, "Medium",
    ConfidenceScore >= 3, "Low",
    "Informational"
)

// Inline guidance to the hunter
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; ClientHost=", ClientHost,
    "; Account=", UPN,
    "; UniqueTargets=", tostring(UniqueTargets),
    "; ExampleTarget=", TargetSample,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Treat as probable Pass-the-Hash or credential misuse. Validate whether this client host should ever perform NTLM network logons to so many servers. Immediately review this host for credential theft (LSASS access, tools, AV/EDR alerts), isolate if untrusted, and review all recent lateral movement and privilege use.",
        Severity == "Medium",
            "Confirm whether this is an admin jump host or scheduled operation. If not, investigate the client host for signs of credential theft or tool execution (PsExec/WMI/SMB tooling) and pivot 24h around this timeframe.",
        Severity == "Low",
            "Review as potential baseline or noisy admin pattern. Consider adding this host/account pair to an allowlist if benign, or monitor for escalation to High severity patterns.",
        "Use as contextual telemetry only; combine with other detections before acting."
    )
)

// Final filter – we don't want pure noise
| where ConfidenceScore >= 3
| project
    FirstSeen, LastSeen, DurationMin,
    ClientHost,
    UPN, UName,
    Protocol,
    Events, UniqueTargets,
    TargetSample, TargetList,
    ConfidenceScore, Severity,
    Reason, HuntingDirectives
| order by ConfidenceScore desc, LastSeen desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
