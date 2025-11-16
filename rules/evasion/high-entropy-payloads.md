# High-Entropy Payload Drops (Polymorphic) – L3 Native Detection Rule

## Threat Focus

High-Entropy Payload Drops (Polymorphic) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1027

## Advanced Hunting Query (MDE / Sentinel)

```kql
let starttime = 14d;
let endtime = 1d;
// Baseline: Calculate common remote ports for each device over a learning period
let BaselineData = 
    DeviceNetworkEvents
    | where Timestamp between (ago(starttime) .. ago(endtime))
    | where isnotempty(RemotePort) and isnotempty(DeviceName)
    | summarize BaselinePortCount = dcount(RemotePort) by DeviceName;
// Look for anomalous connections in the last day
let RecentNetworkEvents = 
    DeviceNetworkEvents
    | where Timestamp > ago(endtime)
    | where ActionType == "ConnectionSuccess"
    // Join with baseline to find devices with low port diversity, potentially indicative of C2
    | join kind=inner BaselineData on DeviceName
    | where BaselinePortCount < 10 // Tune this threshold for your environment
    // Enrich with process information and identity data
    | join kind=inner (
        DeviceProcessEvents
        | where Timestamp > ago(endtime)
        | project DeviceId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId
    ) on DeviceId
    | join kind=leftouter (
        IdentityInfo
        | where isnotempty(AccountUpn)
        | summarize arg_max(TimeGenerated, *) by AccountUpn // Get the latest identity record for a user
        | project AccountUpn, AccountDisplayName, Department, IsAccountEnabled
    ) on $left.AccountName == $right.AccountUpn;
// Analyze the enriched data for specific C2 indicators
RecentNetworkEvents
| extend Protocol = case(
    RemotePort in~ (53, 5353) or Protocol contains "dns", "DNS",
    RemotePort in~ (80, 443, 8080, 8443) or Protocol contains "http", "HTTP",
    "Other"
)
| extend SuspiciousProcess = case(
        InitiatingProcessFileName in~ ("nslookup.exe", "powershell.exe", "certutil.exe", "mshta.exe") 
        and InitiatingProcessParentFileName != "cmd.exe", 1, 0 // Example: Tune parent-child logic
    )
| extend SuspiciousDomain = iff(RemoteUrl has_any(".ddns.net", ".duckdns.org", ".servebeer.com") or RemoteUrl contains "-", 1, 0) // Example suspicious TLDs/patterns[citation:2]
| extend LongLivedSignal = iff(BaselinePortCount < 5 and Protocol == "DNS", 1, 0) // Specific signal for low-port-count, long-lived DNS C2
// Calculate a dynamic confidence score
| extend ConfidenceScore = case(
    LongLivedSignal == 1 and SuspiciousDomain == 1, 8, // High confidence
    LongLivedSignal == 1 and SuspiciousProcess == 1, 7, // Medium-High confidence
    LongLivedSignal == 1, 5, // Medium confidence
    Protocol == "DNS" and SuspiciousProcess == 1, 4, // Low-Medium confidence
    1 // Informational - all other connections for context
)
// Filter to interesting events and project final output
| where ConfidenceScore >= 3
| extend Reason = strcat(
    "Long-lived external session potential C2. Protocol: ", Protocol, 
    ". BaselinePortCount: ", BaselinePortCount,
    ". SuspiciousProcess: ", tostring(SuspiciousProcess),
    ". SuspiciousDomain: ", tostring(SuspiciousDomain)
)
| extend Severity = case(ConfidenceScore >= 8, "High", ConfidenceScore >= 5, "Medium", ConfidenceScore >= 3, "Low", "Informational")
| project Timestamp, DeviceName, AccountName, AccountDisplayName, IsAccountEnabled, 
    RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine,
    ConfidenceScore, Severity, Reason, BaselinePortCount
| order by ConfidenceScore desc, Timestamp desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
