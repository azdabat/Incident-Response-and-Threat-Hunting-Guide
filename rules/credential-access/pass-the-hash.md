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
// Pass-the-Hash (NTLM Lateral Movement) — L3 Native
// MITRE: T1550.002, T1078
// Author: Ala Dabat | 2025-11

let lookback = 14d;

let KnownAdminHosts = dynamic([]);
let HighValueNames  = dynamic(["admin","administrator","adm","svc","service","sql","backup","oracle","krbtgt"]);

// 1 — Raw NTLM network logons
let Ntls =
IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where LogonType == "Resource Access"
| where Protocol has "NTLM"
| where isnotempty(DeviceName) and isnotempty(TargetDeviceName)
| where DeviceName != TargetDeviceName
| where DeviceName !in (KnownAdminHosts)
| where TargetDeviceName !endswith "$"
| where AccountName !endswith "$"
| extend Client = DeviceName,
         Target = TargetDeviceName,
         User   = AccountName,
         UPN    = AccountUpn;

// 2 — Cluster client → target behaviour
let Clusters =
Ntls
| summarize FirstSeen=min(Timestamp),
            LastSeen=max(Timestamp),
            Events=count(),
            UniqueTargets=dcount(Target),
            Targets=make_set(Target,20),
            ExampleTarget=any(Target)
  by Client, User, UPN;

// 3 — Noise reduction
Clusters
| where Events >= 5
| where UniqueTargets >= 2
| where Client !in (KnownAdminHosts)
| extend DurationMin = datetime_diff("minute", LastSeen, FirstSeen)

// 4 — Suspicious conditions
| extend HighValueUser   = User has_any (HighValueNames) or UPN has_any (HighValueNames),
         ManyTargets     = UniqueTargets >= 5,
         MediumTargets   = UniqueTargets between (2 .. 4),
         ShortBurst      = DurationMin <= 30 and Events >= 10

// 5 — Light scoring (noise-aware)
| extend Score =
      iif(ManyTargets,   4, 0) +
      iif(MediumTargets, 2, 0) +
      iif(ShortBurst,    2, 0) +
      iif(HighValueUser, 3, 0)

// 6 — Severity
| extend Severity = case(
      Score >= 8, "High",
      Score >= 5, "Medium",
      Score >= 3, "Low",
      "Informational"
)

// 7 — Analyst summary
| extend Reason = strcat(
      iif(ManyTargets,   tostring(UniqueTargets)  , ""),
      iif(ManyTargets,   " targets touched via NTLM. ", ""),
      iif(MediumTargets, "Multiple NTLM targets. ",    ""),
      iif(ShortBurst,    "Short burst of NTLM logons. ", ""),
      iif(HighValueUser, "High-value account involved. ", "")
)

// 8 — Directives
| extend Directives = case(
      Severity == "High",
        "Likely Pass-the-Hash. Review LSASS access on client host, isolate if necessary, pivot for SMB/WMI/WinRM activity, inspect recent privilege use.",
      Severity == "Medium",
        "Validate if the account normally touches multiple hosts. Check admin tools, service accounts, SCCM, scanning tools.",
      "Baseline check. Tune out known admin patterns."
)

// 9 — Output
| where Score >= 3
| project FirstSeen, LastSeen, DurationMin,
          Client, User, UPN,
          Events, UniqueTargets, ExampleTarget, Targets,
          Score, Severity, Reason, Directives
| order by Score desc, LastSeen desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
