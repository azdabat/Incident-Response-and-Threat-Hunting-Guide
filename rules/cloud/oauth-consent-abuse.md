# OAuth Consent Abuse (Native Logs) – L3 Native Detection Rule

## Threat Focus

OAuth Consent Abuse (Native Logs) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: cloud
- MITRE: T1528, T1098

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =====================================
// OAuth Consent Abuse Detection Rule (Production Ready)
// Author: Ala Dabat | Version: 2025-11 | Platform: Microsoft Sentinel
// Purpose: Detect high-risk or suspicious OAuth application grants and post-consent token usage
// MITRE: TA0001 (Initial Access), TA0003 (Persistence) | T1550.001 (OAuth Token Abuse)
// =====================================

let Lookback = 30d;

let KnownSafeApps = dynamic([
    "Microsoft Teams","SharePoint Online","Outlook Web App","OneDrive","Office 365 Portal",
    "Exchange Online","Azure Portal","Microsoft Graph","Power BI","Intune","Azure AD Connect",
    "Defender for Endpoint","Defender for Identity","Defender for Office 365","Defender for Cloud",
    "Planner","Yammer","Forms","Stream","Sway","PowerApps","Power Automate",
    "Microsoft 365 Admin Center","Microsoft Purview"
]);

let KnownSafePublishers = dynamic([
    "Microsoft Corporation","Microsoft Azure","Microsoft Online Services",
    "Office 365 Exchange Online","Windows Azure Active Directory",
    "Microsoft Purview","Microsoft Teams","SharePoint Online"
]);

let SuspiciousUserAgents = dynamic([
    "python","curl","wget","http-client","go-http","okhttp","java","ruby",
    "perl","postman","insomnia","rest-client","powershell"
]);

let HighRiskExact = dynamic([
    "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","RoleManagement.ReadWrite.Directory",
    "ServicePrincipal.ReadWrite.All","Directory.ReadWrite.All","Directory.AccessAsUser.All",
    "Policy.ReadWrite.Authorization","Policy.Read.All","Domain.ReadWrite.All",
    "AuditLog.Read.All","Reports.Read.All","SecurityEvents.Read.All",
    "IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All",
    "Mail.Read","Mail.ReadWrite","Mail.Send","MailboxSettings.ReadWrite",
    "EWS.AccessAsUser.All","full_access_as_app",
    "Files.ReadWrite.All","Sites.ReadWrite.All","Sites.FullControl.All",
    "ChannelMessage.Read.All","ChannelMessage.ReadWrite.All","Channel.Read.All",
    "Chat.Read","Chat.ReadWrite",
    "Calendars.ReadWrite","Contacts.ReadWrite","Notes.ReadWrite.All","Tasks.ReadWrite",
    "Device.ReadWrite.All","Group.ReadWrite.All","User.ReadWrite.All",
    "offline_access"
]);

let HighRiskRegex = dynamic([
  @"^(Application|AppRoleAssignment|ServicePrincipal|RoleManagement|Directory|Domain|Policy)\.(ReadWrite.*|AccessAsUser\.All)$",
  @"^(AuditLog|Reports|Security|IdentityRisk(Event|yUser)|Threat|InformationProtectionPolicy)\.(Read.*|ReadWrite.*)$",
  @"^(Mail|MailboxSettings)\.(Read.*|ReadWrite.*|Send)$",
  @"^(Files|Sites)\.(Read.*|ReadWrite.*|FullControl\.All)$",
  @"^(Group|User|Device)\.(ReadWrite.*)$",
  @"^(Channel(Message)?|Chat)\.(Read.*|ReadWrite.*)$",
  @".*\.FullControl\.All$",
  @".*\.ReadWrite\.All$"
);

// ---- Consent extraction (AuditLogs) ----
let Consents =
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment grant to service principal",
    "Add service principal credentials"
  )
| where Result =~ "success"
| extend Target = iff(array_length(TargetResources) > 0, TargetResources[0], dynamic(null))
| extend AppId = tostring(Target.id),
         AppDisplayName = tostring(Target.displayName),
         ModifiedProps = tostring(Target.modifiedProperties),
         InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
         IPAddress = tostring(InitiatedBy.user.ipAddress),
         UserAgent = tostring(InitiatedBy.user.userAgent)
| extend Props = parse_json(ModifiedProps)
| mv-expand P = Props
| extend PropName = tostring(P.displayName), PropValue = tostring(P.newValue)
| summarize
    IsAppOnlyRaw      = any(iff(PropName == "ConsentContext.IsAppOnly", PropValue, "")),
    OnBehalfOfAllRaw  = any(iff(PropName == "ConsentContext.OnBehalfOfAll", PropValue, "")),
    PublisherNameRaw  = any(iff(PropName == "ConsentContext.PublisherName", PropValue, "")),
    ResourceNameRaw   = any(iff(PropName == "ConsentContext.ResourceDisplayName", PropValue, "")),
    DelegatedRaw      = any(iff(PropName == "Scope", PropValue, "")),
    AppRolesRaw       = any(iff(PropName == "AppRoles", PropValue, "")),
    CreatedTime       = min(TimeGenerated),
    Initiator         = any(InitiatorUPN),
    IPAddress         = any(IPAddress),
    UserAgent         = any(UserAgent)
  by AppId, AppDisplayName
| extend IsAppOnly     = tobool(coalesce(parse_json(IsAppOnlyRaw), false)),
         OnBehalfAll   = tobool(coalesce(parse_json(OnBehalfOfAllRaw), false)),
         PublisherName = trim(@"""", tostring(PublisherNameRaw)),
         ResourceName  = trim(@"""", tostring(ResourceNameRaw)),
         DelegatedList = split(replace_string(tostring(DelegatedRaw), "\"",""), " "),
         AppRolesJson  = parse_json(AppRolesRaw)
| mv-expand RoleElt = iif(isnull(AppRolesJson) or array_length(AppRolesJson)==0, dynamic(null), AppRolesJson) to typeof(string)
| extend AppRole = trim(" ", trim("\"", tostring(RoleElt))),
         AllPerms = array_concat(DelegatedList, pack_array(AppRole))
| mv-expand Permission in AllPerms
| extend Permission = trim(" ", trim("\"", tostring(Permission)))
| where isnotempty(Permission)
| extend IsHighExact = iif(Permission in (HighRiskExact), 1, 0),
         IsHighRegex = iif(array_length(array_filter(HighRiskRegex, (re:string) { Permission matches regex re })) > 0, 1, 0),
         IsHighRiskPermission = iif(IsHighExact == 1 or IsHighRegex == 1 or tolower(Permission) == "offline_access", 1, 0)
| summarize
    HighRiskPermissionCount = sum(IsHighRiskPermission),
    HighRiskPerms           = make_set_if(Permission, IsHighRiskPermission == 1, 200),
    Permissions             = make_set(Permission, 1000),
    IsAppOnly               = any(IsAppOnly),
    OnBehalfAll             = any(OnBehalfAll),
    PublisherName           = any(PublisherName),
    ResourceName            = any(ResourceName),
    CreatedTime             = any(CreatedTime),
    Initiator               = any(Initiator),
    IPAddress               = any(IPAddress),
    UserAgent               = any(UserAgent)
  by AppId, AppDisplayName
| extend IsKnownSafeApp = iif(AppDisplayName in~ (KnownSafeApps), "Yes", "No"),
         IsKnownSafePub = iif(PublisherName in~ (KnownSafePublishers), "Yes", "No"),
         SuspiciousUA   = iif(tolower(UserAgent) has_any (SuspiciousUserAgents), "Yes", "No"),
         ConsentType    = iif(OnBehalfAll, "Admin (tenant-wide)", "User"),
         GrantKind      = iif(IsAppOnly, "Application (client credentials)", "Delegated (user)");

// ---- Token Usage ----
let TokenUsage =
TokenIssuanceLogs
| where TimeGenerated >= ago(60m)
| project AppId = tostring(AppId),
          TokenIssuedAt = TimeGenerated,
          TokenGrantType = tostring(GrantType),
          Account = tostring(UserPrincipalName),
          TokenIPAddress = IPAddress
| summarize FirstToken = min(TokenIssuedAt),
            LastToken  = max(TokenIssuedAt),
            TokenUseCount = count()
  by AppId, Account;

// ---- Graph Sign-ins ----
let GraphSignins =
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where ResourceServicePrincipalId == "00000003-0000-0000-c000-000000000000"   // Microsoft Graph
| project AppId = tostring(AppId),
          GraphSigninAt = TimeGenerated,
          UA = tostring(UserAgent),
          SigninIP = IPAddress,
          Account = tostring(UserPrincipalName)
| summarize FirstGraph = min(GraphSigninAt),
            LastGraph  = max(GraphSigninAt),
            GraphSignins = count()
  by AppId, Account;

// ---- Service Principal Activity ----
let SPActivity =
ServicePrincipalSignInLogs
| where TimeGenerated >= ago(Lookback)
| project AppId = tostring(AppId),
          SPName = tostring(ServicePrincipalName),
          SPIP = IPAddress,
          SPTime = TimeGenerated
| summarize FirstSP = min(SPTime),
            LastSP  = max(SPTime),
            SPCalls = count(),
            SampleIPs = make_set(SPIP, 3)
  by AppId, SPName;

// ---- Correlate Consents with Usage ----
Consents
| join kind=leftouter TokenUsage on AppId
| join kind=leftouter GraphSignins on AppId
| join kind=leftouter SPActivity on AppId
| extend RiskScore =
      1 * HighRiskPermissionCount
    + 2 * iif(ConsentType == "Admin (tenant-wide)", 1, 0)
    + 2 * iif(GrantKind == "Application (client credentials)", 1, 0)
    + 1 * iif(SuspiciousUA == "Yes", 1, 0)
    + 1 * iif(IsKnownSafeApp == "No", 1, 0)
    + 1 * iif(IsKnownSafePub == "No", 1, 0)
    + 2 * iif(TokenUseCount > 0 or SPCalls > 0, 1, 0)
| extend MITRE_Tactic    = "TA0001: Initial Access; TA0003: Persistence",
         MITRE_Technique = "T1550.001: OAuth Token Abuse"
| extend HuntingDirectives = pack_array(
    strcat("1) Validate if consent was legitimate: Initiator=", Initiator, " from ", IPAddress, "."),
    strcat("2) Review app '", AppDisplayName, "' (AppId=", AppId, ") and publisher '", PublisherName, "'."),
    strcat("3) High-risk permissions (", tostring(HighRiskPermissionCount), "): ", strcat_array(HighRiskPerms, ", "), "."),
    strcat("4) Check token usage (TokenUseCount=", tostring(TokenUseCount), ", SPCalls=", tostring(SPCalls), ")."),
    "5) Pivot on IP/UserAgent in SigninLogs for suspicious patterns.",
    "6) If malicious or unapproved, revoke app consent and invalidate refresh tokens.",
    "7) Consider user password reset and Conditional Access hardening.",
    "8) Document as potential consent phishing / OAuth abuse incident (T1550.001)."
)
| project
    AppId, AppDisplayName, CreatedTime,
    ConsentType, GrantKind,
    Initiator, IPAddress, UserAgent,
    PublisherName, ResourceName,
    HighRiskPermissionCount, HighRiskPerms, Permissions,
    IsKnownSafeApp, IsKnownSafePub, SuspiciousUA,
    FirstToken, LastToken, TokenUseCount,
    FirstGraph, LastGraph, GraphSignins,
    FirstSP, LastSP, SPCalls, SampleIPs,
    RiskScore, HuntingDirectives, MITRE_Tactic, MITRE_Technique
| order by RiskScore desc, CreatedTime desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
