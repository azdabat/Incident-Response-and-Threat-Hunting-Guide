# Cloud Admin Role Drift / Escalation – L3 Native Detection Rule

## Threat Focus

Cloud Admin Role Drift / Escalation is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: cloud
- MITRE: T1098

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =======================================================
// Cloud Admin Role Drift / Escalation – L3 Native Detection
// Author: Ala Dabat
// MITRE: T1098 (Account Manipulation / Privilege Escalation)
// Data source: Microsoft Entra ID Audit Logs (AuditLogs table)
// =======================================================

let lookback = 14d;

// High-privilege roles we care most about (tune for your tenant)
let HighPrivRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "User Access Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Cloud Application Administrator",
    "Conditional Access Administrator"
]);

// Operations that indicate role assignment / elevation
let RoleOps = dynamic([
    "Add member to role",
    "Add eligible member to role",
    "Add member to role in PIM",
    "Add role assignment to role",
    "Update member in role",
    "Activate eligible role",
    "Extend role assignment"
]);

AuditLogs
| where TimeGenerated >= ago(lookback)
| where Category =~ "RoleManagement"          // Entra role management category
       or OperationName has_any (RoleOps)
| extend Activity = coalesce(ActivityDisplayName, OperationName)
// Basic helpers from AuditLogs schema
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend TargetId = tostring(TargetResources[0].id)
| extend TargetDisplayName = tostring(TargetResources[0].displayName)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorDisplayName = tostring(InitiatedBy.user.displayName)
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
// Try to pull the role name out of TargetResources / modifiedProperties where present
| extend RoleName = case(
      isnotempty(TargetResources[0].modifiedProperties[0].newValue),
          trim(@'"', tostring(TargetResources[0].modifiedProperties[0].newValue)),
      isnotempty(TargetResources[0].displayName),
          tostring(TargetResources[0].displayName),
      Activity has "role",
          Activity,
      "Unknown"
  )
| extend IsHighPrivRole = iif(RoleName in (HighPrivRoles), 1, 0)
// Permanent vs time-bound (very rough heuristic – tune to your schema)
| extend RawProps = tostring(TargetResources[0].modifiedProperties[0].newValue)
| extend IsPermanent =
    iif(RawProps has_any ("Permanent","PermanentlyAssignable","NoExpiration"), 1, 0)
// Actor elevates someone else vs self-activation
| extend IsSelfAction = iif(Actor =~ Target or ActorDisplayName =~ TargetDisplayName, 1, 0)
| extend IsElevationByOther = iif(IsSelfAction == 0, 1, 0)

// -------------------------
// Confidence scoring
// -------------------------
| extend ConfidenceScore =
    0
    + iif(IsHighPrivRole == 1,        5, 0)
    + iif(IsPermanent == 1,           3, 0)
    + iif(IsElevationByOther == 1,    3, 0)
    + iif(Activity has_any (RoleOps), 2, 0)
    + iif(Result =~ "success",        1, 0)

// -------------------------
// Reason for analyst
// -------------------------
| extend Reason = strcat(
    "Role activity: ", Activity, ". ",
    "Role=", RoleName, ". ",
    iif(IsHighPrivRole == 1, "High-privilege role. ", ""),
    iif(IsPermanent == 1, "Permanent/non-expiring assignment pattern detected. ", ""),
    iif(IsElevationByOther == 1,
        strcat("Actor (", Actor, ") elevated target (", coalesce(Target, TargetDisplayName), "). "),
        "Self-activation/elevation. "),
    iif(Result !~ "success", strcat("Result: ", Result, ". "), "")
)

// -------------------------
// Severity mapping
// -------------------------
| extend Severity = case(
    ConfidenceScore >= 10, "High",
    ConfidenceScore >= 6,  "Medium",
    ConfidenceScore >= 3,  "Low",
    "Informational"
)

// -------------------------
// L3 Hunting Directives
// -------------------------
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Actor=", Actor,
    "; ActorDisplayName=", ActorDisplayName,
    "; ActorIP=", ActorIP,
    "; Target=", coalesce(Target, TargetDisplayName),
    "; Role=", RoleName,
    "; Activity=", Activity,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Immediately validate whether this role change was requested and approved via proper process (ticket/PIM). If not expected, treat as potential tenant compromise: review Actor activity for additional changes, revoke sessions, enforce step-up auth, and consider downgrading/removing the role.",
        Severity == "Medium",
            "Confirm change request, check PIM activity and approvals. Review Actor and Target sign-in history and other admin changes in the last 24–48 hours.",
        Severity == "Low",
            "Review as part of scheduled access reviews. If benign, document as expected role lifecycle.",
        "Use as contextual signal for other cloud-identity incidents."
    )
)

// -------------------------
// Final filter / output
// -------------------------
| where ConfidenceScore >= 3
| project
    TimeGenerated,
    Severity,
    ConfidenceScore,
    Activity,
    RoleName,
    Actor, ActorDisplayName, ActorIP,
    Target, TargetDisplayName,
    Category, CorrelationId,
    Reason,
    HuntingDirectives
| order by TimeGenerated desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
