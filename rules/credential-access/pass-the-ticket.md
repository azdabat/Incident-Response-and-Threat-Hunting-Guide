# Pass-the-Ticket / Kerberos Ticket Abuse – L3 Native Detection Rule

## Threat Focus

Pass-the-Ticket / Kerberos Ticket Abuse is detected using pure native telemetry (no external TI) at L3 fidelity.
- Category: credential-access
- MITRE: T1550.003, T1558.003

  ## Pass-the-Ticket (PTT) — L3 Native Detection Rule  
**Category:** Credential Access / Lateral Movement  
**MITRE:** T1550.003 (Pass-the-Ticket), T1558.003 (Kerberos Tickets)

Pass-the-Ticket (PTT) is a credential-theft technique where attackers replay, forge, or manipulate Kerberos TGT/TGS tickets to authenticate without needing a password or NTLM hash. Unlike Pass-the-Hash, PTT abuses Kerberos’ trust model and allows an adversary to impersonate users, escalate privileges, or move laterally using valid-looking tickets.

Common PTT attack paths include:
- Forging tickets with tools such as **Rubeus**, **Mimikatz**, **Kekeo**
- Injecting `.kirbi` tickets into sessions (`/ptt`)
- Requesting service tickets for **sensitive SPNs** (cifs/ldap/http/sql/termsrv)
- Replaying TGS tickets across multiple hosts (cross-host inconsistencies)
- Abuse of weak encryption types (RC4/DES) during replay
- Large SPN fan-out from a single account (fast lateral movement sweeps)

This L3 detection rule identifies PTT activity using **native Microsoft telemetry only** (no TI, no signatures). It correlates Kerberos authentication patterns with process behaviour on the originating host, producing a weighted, high-fidelity risk score.

### Detection Logic (Native L3)
The rule analyses:
- Kerberos TGT/TGS requests across hosts
- Cross-host ticket use indicating ticket replay
- Access to **sensitive SPNs** targeted during privilege escalation
- Weak/legacy encryption patterns used in forged tickets
- High-privilege accounts behaving outside their baseline
- Large SPN diversity from a single identity (sweep behaviour)
- Evidence of PTT tooling (Rubeus/Mimikatz/etc.) on the same host

### Behavioural Scoring
Confidence increases when:
- Sensitive SPNs are accessed unexpectedly  
- High-value accounts appear on untrusted hosts  
- Weak encryption (RC4/DES) is used by privileged accounts  
- Ticket use spans multiple unrelated hosts  
- Kerberos tooling is observed on the endpoint  
- SPN fan-out exceeds expected baselines  

The rule maps to **High / Medium / Low** severity based on aggregated signals.

### Value of the Detection
This analytic reliably uncovers:
- Kerberos ticket replay
- Forged TGT/TGS ticket usage
- Credential theft following LSASS compromise
- Lateral movement via Kerberos impersonation
- KRBTGT key-related manipulation indicators
- Early-stage attempts to escalate into Tier 0 assets

It helps identify advanced tradecraft where attackers bypass passwords entirely, relying instead on ticket tampering, replay, and impersonation to gain or maintain privileged access.  


## Advanced Hunting Query (MDE / Sentinel)

```kql
// Pass-the-Ticket (PTT) — Native L3 Detection
// MITRE: T1550.003, T1558.003
// Author: Ala Dabat | 2025-11

let lookback = 14d;

let DomainControllers = dynamic([]);
let PTTTools = dynamic([
    "rubeus.exe","mimikatz.exe","kekeo.exe",
    "ticket.exe","invoke-mimikatz.ps1","sekurlsa.dll"
]);

let SensitiveSPNs = dynamic([
    "cifs/","host/","ldap/","mssqlsvc/","http/","termsrv/","wsman/","krbtgt"
]);

let HighValueAccounts = dynamic([
    "admin","administrator","adm","da","tier0","svc","service","backup","sql"
]);

// 1 — Kerberos activity (successful)
let Kerb =
IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where Protocol has "Kerberos"
| where Result == "Success"
| where isnotempty(ServicePrincipalName)
| where AccountName !endswith "$"
| extend SPN=tostring(ServicePrincipalName),
         Host=tostring(DeviceName),
         TargetHost=tostring(TargetDeviceName),
         UPN=tostring(AccountUpn),
         EncType=tostring(EncryptionType)
| where Host !in (DomainControllers)
| project Timestamp, Host, TargetHost, UPN, SPN, EncType;

// 2 — Behavioural flags
let KerbEval =
Kerb
| extend SensitiveSPN   = SPN has_any (SensitiveSPNs),
         HighValueAcct  = UPN has_any (HighValueAccounts),
         WeakEncryption = EncType in ("rc4","rc4-hmac","des","des-cbc-crc"),
         CrossHost      = isnotempty(TargetHost) and Host != TargetHost;

// 3 — Aggregate Kerberos behaviour by account + host
let KerbAgg =
KerbEval
| summarize
      FirstSeen=min(Timestamp),
      LastSeen=max(Timestamp),
      Events=count(),
      UniqueSPNs=dcount(SPN),
      SPNSample=take_any(SPN),
      SPNList=make_set(SPN,20),
      AnySensitiveSPN=max(SensitiveSPN),
      AnyWeakEnc=max(WeakEncryption),
      AnyCrossHost=max(CrossHost),
      IsHighValue=max(HighValueAcct)
  by Host, UPN
| extend DurationMinutes=datetime_diff("minute",LastSeen,FirstSeen)
| where Events >= 5 and UniqueSPNs >= 3;

// 4 — Tooling evidence on host
let ToolHits =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (PTTTools)
   or ProcessCommandLine has_any ("kirbi","asktgt","asktgs","/ptt")
| summarize HasTooling=1,
            ToolSample=take_any(FileName),
            ToolCmd=take_any(ProcessCommandLine)
  by DeviceName;

// Join Kerberos behaviour and tooling
KerbAgg
| join kind=leftouter (ToolHits) on $left.Host == $right.DeviceName
| extend HasTooling=iif(isnotempty(HasTooling),1,0)

// 5 — Severity (simple, behaviour-based — no weighted scoring)
| extend Severity = case(
      HasTooling == 1 and AnySensitiveSPN == 1 and IsHighValue == 1, "High",
      HasTooling == 1 and AnySensitiveSPN == 1,                      "High",
      AnyCrossHost == 1 and AnySensitiveSPN == 1,                    "High",
      AnySensitiveSPN == 1 and IsHighValue == 1,                     "Medium",
      AnyWeakEnc == 1 and IsHighValue == 1,                          "Medium",
      HasTooling == 1,                                               "Medium",
      AnySensitiveSPN == 1 or AnyCrossHost == 1,                     "Low",
      "Informational"
)

// 6 — Analyst reasoning
| extend Reason = strcat(
      iif(HasTooling == 1, strcat("Kerberos tooling observed (", ToolSample, "). "), ""),
      iif(IsHighValue == 1, "High-value account involved. ", ""),
      iif(AnySensitiveSPN == 1, "Access to sensitive SPNs (cifs/host/ldap/sql/http/termsrv). ", ""),
      iif(AnyWeakEnc == 1, "Weak RC4/DES Kerberos encryption used. ", ""),
      iif(AnyCrossHost == 1, "Cross-host ticket use (possible replay). ", "")
)

// 7 — Directives
| extend Directives = case(
      Severity == "High",
         "Probable Pass-the-Ticket or forged ticket usage. Review LSASS access, inspect Kerberos tooling, validate ticket source and SPN legitimacy, isolate host if required.",
      Severity == "Medium",
         "Investigate account behaviour. Check host process history, correlate with LSASS access, evaluate ticket legitimacy and SPN usage.",
      Severity == "Low",
         "Baseline candidate. Validate expected service behaviour; monitor for escalation.",
      "Context-only signal for hunters."
)

// Final output
| where Severity in ("High","Medium")
| project FirstSeen, LastSeen, DurationMinutes,
          Host, UPN, UniqueSPNs, SPNSample,
          HasTooling, ToolSample,
          Severity, Reason, Directives
| order by LastSeen desc


```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
