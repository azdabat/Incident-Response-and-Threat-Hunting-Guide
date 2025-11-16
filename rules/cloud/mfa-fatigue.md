# MFA Fatigue / Push Spamming – L3 Native Detection Rule

## Threat Focus

MFA Fatigue / Push Spamming is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: cloud
- MITRE: Credential abuse

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================================
// MFA Fatigue / Push Spamming – L3 Native Detection
// Author: Ala Dabat
// Data source: EntraIdSignInEvents (or AADSignInEventsBeta)
// MITRE-ish: T1621-style MFA request generation / abuse
// =====================================================

let lookback = 14d;
let window = 15m;   // tuning knob for "spam window"

// --- 1. MFA PUSH FAILURES (DENIED / TIMED OUT) --------------------

// Known "failed MFA prompt" result codes for Entra sign-ins (push / app)
// 50074 – User did not respond to MFA challenge
// 500121 – MFA denied by user
let MfaFailedCodes = dynamic([50074, 500121]);

let MfaFailures =
EntraIdSignInEvents
| where Timestamp >= ago(lookback)
| where AuthenticationRequirement == "multiFactorAuthentication"
| mv-expand AuthDetails = todynamic(AuthenticationDetails)
| extend AuthMethod = tostring(AuthDetails.authenticationMethod),
         AuthResult = tostring(AuthDetails.authenticationStepResult)
| where AuthMethod has_any ("Notification","PhoneAppNotification","Push")
// focus on push style – adjust if your tenant labels differently
   or AuthMethod == ""    // some tenants populate sparsely; keep loose
| where ResultType in (MfaFailedCodes)
      or AuthResult in~ ("Denied","TimedOut","DeniedByUser","failed")
// group into windows per user+IP+device
| summarize
      FirstFail = min(Timestamp),
      LastFail  = max(Timestamp),
      FailedPrompts = count(),
      Locations = make_set(Location, 5)
  by AccountUpn, IPAddress, DeviceName, bin(Timestamp, window);

// --- 2. MFA SUCCESSES AFTER SPAM (FLIP-TO-SUCCESS) ----------------

let MfaSuccess =
EntraIdSignInEvents
| where Timestamp >= ago(lookback)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType == 0 // success
| project SuccessTime = Timestamp,
          AccountUpn,
          IPAddress,
          DeviceName,
          Location,
          RiskLevelDuringSignIn,
          RiskState;

// Join failures → optional success from same IP/device shortly after
MfaFailures
| join kind=leftouter (
    MfaSuccess
    | project SuccessTime,
              AccountUpn,
              IPAddress,
              DeviceName,
              RiskLevelDuringSignIn,
              RiskState
) on AccountUpn, IPAddress, DeviceName
| where isnull(SuccessTime)
       or SuccessTime between (LastFail .. LastFail + window)
| extend HasSuccessAfterSpam = iff(isnotnull(SuccessTime), 1, 0)
| extend DurationMinutes = datetime_diff("minute", LastFail, FirstFail)

// --- 3. Behaviour-based scoring -----------------------------------

| extend ConfidenceScore =
    0
    // volume of prompts in the window
    + iif(FailedPrompts >= 30, 6,
      iif(FailedPrompts >= 15, 4,
      iif(FailedPrompts >= 7,  2, 0)))
    // user finally "gives in" and approves
    + iif(HasSuccessAfterSpam == 1, 3, 0)
    // risk signals (if populated)
    + iif(RiskLevelDuringSignIn >= 50, 2, 0)  // medium/high
    + iif(RiskState in (4,5), 2, 0)           // at risk / confirmed compromised

// --- 4. Analyst-facing reason -------------------------------------

| extend Reason = strcat(
    "Detected ", tostring(FailedPrompts),
    " MFA push denials/timeouts for ", AccountUpn,
    " from IP ", IPAddress,
    " in ~", tostring(DurationMinutes), " minutes. ",
    iif(HasSuccessAfterSpam == 1,
        "Successful MFA sign-in from same IP/device shortly after failures. ", ""),
    iif(RiskLevelDuringSignIn >= 50,
        "Sign-in tagged with medium/high aggregated risk. ", ""),
    iif(RiskState in (4,5),
        "User marked 'at risk' / 'confirmed compromised' by Identity Protection. ", "")
)

// --- 5. Severity + Hunter directives (IDENTITY-focused) -----------

| extend Severity = case(
    ConfidenceScore >= 10, "High",
    ConfidenceScore >= 6,  "Medium",
    ConfidenceScore >= 3,  "Low",
    "Informational"
)
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; User=", AccountUpn,
    "; IP=", IPAddress,
    "; Device=", coalesce(DeviceName, ""),
    "; FailedPrompts=", tostring(FailedPrompts),
    "; CoreReason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Contact the user via a trusted channel (phone/Teams) and confirm whether they received unexpected MFA prompts. If yes, assume account compromise: force sign-out, reset password, revoke refresh tokens, require MFA re-registration, and review recent sign-ins, mailbox rules, OAuth consents and admin actions.",
        Severity == "Medium",
            "Check if the user reported suspicious MFA behaviour. Correlate with password spray, phishing alerts and risky sign-ins. Consider resetting password and enforcing step-up MFA if behaviour is unexplained.",
        Severity == "Low",
            "Monitor and baseline – some users on unstable networks or misconfigured clients can generate repeated prompts. If this pattern persists for the same user, tune thresholds or add exception notes.",
        "Use as contextual signal only; combine with higher-confidence indicators before taking action."
    )
)

// --- 6. Final output ----------------------------------------------

| where ConfidenceScore >= 3
| project
    Timestamp     = FirstFail,
    AccountUpn,
    DeviceName,
    IPAddress,
    FailedPrompts,
    DurationMinutes,
    HasSuccessAfterSpam,
    RiskLevelDuringSignIn,
    RiskState,
    ConfidenceScore,
    Severity,
    Reason,
    HuntingDirectives
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
