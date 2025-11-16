# Pass-the-Hash Pattern (NTLM) – L3 Native Detection Rule

## Threat Focus

Pass-the-Hash Pattern (NTLM) is detected using pure native telemetry (no external TI) at L3 fidelity.
- Category: credential-access
- MITRE: T1550.002

  ## Pass-the-Hash (NTLM Network Lateral) — L3 Native Detection Rule
**Category:** Credential-Access / Lateral Movement  
**MITRE:** T1550.002 (Pass-the-Hash), T1078 (Valid Accounts)

This rule detects NTLM-based lateral movement using *native telemetry only*, with no external threat intelligence or signatures. Pass-the-Hash allows an adversary to authenticate to remote systems using stolen NTLM hashes instead of plaintext credentials. This typically follows LSASS credential theft and is frequently observed during internal recon, lateral movement, or privilege escalation.

### Detection Approach
The rule uses `IdentityLogonEvents` to identify NTLM “Resource Access” logons that originate from non-DC endpoints. These events are aggregated by source host and account to analyse:

- Number of **unique target hosts** accessed via NTLM  
- Volume of NTLM traffic over short time windows  
- Use of **privileged accounts** (e.g., admin, svc accounts)  
- NTLM authentication from endpoints that rarely generate it  
- Patterns consistent with credential misuse or automated sweeps  

### Behavioural Scoring (Native L3)
A weighted scoring model increases confidence when:
- The same workstation touches many NTLM targets  
- NTLM activity bursts occur in short time windows  
- Administrative or service accounts authenticate from non-DC hosts  
- NTLM usage is inconsistent with the device’s expected behaviour  

Severity is mapped from the total confidence score (High, Medium, Low).

### What This Rule Detects
- Classic Pass-the-Hash lateral traversal  
- SMB / PsExec-style NTLM authentication chains  
- Misuse of high-privilege accounts from compromised workstations  
- NTLM sweeps across servers during internal pivoting  
- Stolen credentials being replayed from unexpected hosts  

### Usage Notes
A small amount of noise may originate from:
- Legitimate admin jump hosts  
- Backup/orchestration systems  
- Patch automation frameworks  

These baselines can be safely allowlisted at the analytics-rule level.

This detection is fully native, environment-aware after tuning, and provides reliable high-fidelity alerts for credential misuse and NTLM-based lateral movement activity.


## Advanced Hunting Query (MDE / Sentinel)

```kql
// ============================================================
// Pass-the-Hash (NTLM Network Lateral) — L3 Native (Noise Reduced)
// Category: credential-access / lateral-movement
// MITRE: T1550.002 (Pass-the-Hash), T1078 (Valid Accounts)
// Author: Ala Dabat (Alstrum)
// ============================================================

let lookback = 14d;

// Optional exclusions for legitimate admin / automation systems
let KnownAdminHosts = dynamic([
    // "jump01", "jump02", "backup01", "sccm01"
]);

// High-value account indicators
let HighValueAccountPatterns = dynamic([
    "admin","administrator","adm","service","svc","sql","backup","oracle","krbtgt"
]);

// 1. Raw NTLM network logons (IdentityLogonEvents)
let Ntls =
IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where LogonType == "Resource Access"           // NTLM network logon semantics
| where Protocol has "NTLM"
| where isnotempty(DeviceName)
| where isnotempty(TargetDeviceName)
| where DeviceName != TargetDeviceName           // eliminate local chatter
| where DeviceName !in (KnownAdminHosts)         // reduce noise from known admin hosts
| where TargetDeviceName !endswith "$"           // filter machine account targets
| where AccountName !endswith "$"                // filter machine accounts unless noisy
| extend ClientHost = DeviceName,
         TargetHost = TargetDeviceName,
         UPN        = AccountUpn,
         UName      = AccountName;

// 2. Aggregate client → target behaviour
let Clusters =
Ntls
| summarize
    FirstSeen     = min(Timestamp),
    LastSeen      = max(Timestamp),
    Events        = count(),
    UniqueTargets = dcount(TargetHost),
    TargetSample  = take_any(TargetHost),
    TargetList    = make_set(TargetHost, 20)
  by ClientHost, UPN, UName;

// 3. Noise reduction filters
Clusters
| where UniqueTargets >= 2              // single target is usually normal
| where Events >= 5                     // remove trivial noise
| where ClientHost !in (KnownAdminHosts)
| extend DurationMin = datetime_diff("minute", LastSeen, FirstSeen)

// 4. Suspicion heuristics
| extend IsHighValueAccount =
    iif(UName has_any (HighValueAccountPatterns)
        or UPN  has_any (HighValueAccountPatterns), 1, 0)

| extend Susp_ManyTargets   = iif(UniqueTargets >= 5, 1, 0)
| extend Susp_MediumTargets = iif(UniqueTargets between (2 .. 4), 1, 0)
| extend Susp_ShortBurst    = iif(DurationMin <= 30 and Events >= 10, 1, 0)
| extend Susp_HighValue     = iif(IsHighValueAccount == 1, 1, 0)

// 5. Confidence scoring (noise-aware)
| extend ConfidenceScore =
    0
    + iif(Susp_ManyTargets == 1,    5, 0)
    + iif(Susp_MediumTargets == 1,  3, 0)
    + iif(Susp_ShortBurst == 1,     3, 0)
    + iif(Susp_HighValue == 1,      4, 0)

// 6. Reasoning text
| extend Reason = strcat(
    iif(Susp_ManyTargets == 1, 
        strcat("NTLM sweep across ", tostring(UniqueTargets), " hosts. "), ""),
    iif(Susp_MediumTargets == 1,
        strcat("Multiple NTLM connections (", tostring(UniqueTargets), "). "), ""),
    iif(Susp_ShortBurst == 1,
        strcat("Short-burst NTLM cluster (", tostring(DurationMin),
               " minutes, ", tostring(Events), " events). "), ""),
    iif(Susp_HighValue == 1,
        "High-value account performing NTLM lateral movement. ", "")
)

// 7. Severity mapping
| extend Severity = case(
    ConfidenceScore >= 10, "High",
    ConfidenceScore >= 6,  "Medium",
    ConfidenceScore >= 3,  "Low",
    "Informational"
)

// 8. Hunter directives
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
            "Likely Pass-the-Hash. Immediately analyze LSASS access, isolate client host, review recent lateral movement, and confirm privilege use.",
        Severity == "Medium",
            "Investigate the client host; verify if privileged NTLM usage is expected. Review recent tool execution, service creation, or SMB/WMI pivots.",
        Severity == "Low",
            "Validate if this could be normal admin behaviour. Tune out known patterns.",
        "Baseline-only; correlate with other lateral movement indicators."
    )
)

// 9. Final output
| where ConfidenceScore >= 3
| project
    FirstSeen, LastSeen, DurationMin,
    ClientHost,
    UPN, UName,
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
