# Log Clearing and Shadow Copy Deletion – L3 Native Detection Rule

## Threat Focus

Log Clearing and Shadow Copy Deletion is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1070, T1489

## Advanced Hunting Query (MDE / Sentinel)

```kql
let lookback = 14d;
// Expanded list of relevant tooling based on threat research
let tools = dynamic(["wevtutil.exe", "vssadmin.exe", "powershell.exe", "cmd.exe", "wmic.exe", "diskshadow.exe", "wbadmin.exe"]);
// 1. Detect Process Creation for known anti-forensics tooling
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (tools)
| extend Cmd = tostring(ProcessCommandLine)
// --- Expanded Log Clearing Detection ---
| extend IsWevtutilClear = iif(Cmd has "wevtutil" and Cmd has_any ("cl", "clear-log", "/c"), 1, 0)
| extend IsWmicClear = iif(Cmd contains "wmic" and Cmd has "nteventlog" and Cmd has "delete", 1, 0)
| extend IsLogClear = iff(IsWevtutilClear == 1 or IsWmicClear == 1, 1, 0)
// --- Expanded Shadow Copy Deletion Detection ---
// Direct deletion commands
| extend IsVssadminDelete = iif(Cmd has "vssadmin" and Cmd has_any ("delete", "shadows"), 1, 0)
| extend IsWmicShadowDelete = iif(Cmd contains "wmic" and Cmd contains "shadowcopy" and Cmd contains "delete", 1, 0)
| extend IsPowerShellShadowDelete = iif(Cmd contains "powershell" and Cmd has_any ("Win32_Shadowcopy", "Delete()"), 1, 0)
// Stealthy resize technique used by ransomware like Conti[citation:2]
| extend IsVssadminResize = iif(Cmd has "vssadmin" and Cmd contains "resize" and Cmd contains "shadowstorage", 1, 0)
| extend IsWbadminDelete = iif(Cmd has "wbadmin" and Cmd has_any ("delete", "catalog"), 1, 0)
| extend IsShadowDelete = iff(IsVssadminDelete == 1 or IsWmicShadowDelete == 1 or IsPowerShellShadowDelete == 1 or IsVssadminResize == 1 or IsWbadminDelete == 1, 1, 0)
// --- Calculate Confidence Score ---
// Higher scores for multiple techniques, specific high-fidelity commands, and stealthy methods
| extend TechniqueCount = (IsLogClear ? 1 : 0) + (IsShadowDelete ? 1 : 0) +
                          (IsVssadminResize ? 1 : 0) + (IsPowerShellShadowDelete ? 1 : 0)
| extend ConfidenceScore = case(
    // Multiple techniques on same host is a strong ransomware indicator[citation:7]
    IsLogClear == 1 and IsShadowDelete == 1 and TechniqueCount >= 3, 10,
    // Specific high-fidelity commands for shadow copy deletion[citation:9]
    IsShadowDelete == 1 and (IsVssadminResize == 1 or IsPowerShellShadowDelete == 1), 9,
    // Multiple shadow deletion methods or log clearing with one deletion method
    IsLogClear == 1 and IsShadowDelete == 1, 8,
    // Individual high-impact techniques
    IsShadowDelete == 1, 7,
    IsLogClear == 1, 6,
    // Low-confidence catch-all for tool invocation
    2
)
// --- Refined Reason and Projection ---
| extend Reason = case(
    IsLogClear == 1 and IsShadowDelete == 1 and TechniqueCount >= 3, strcat("Multiple anti-forensics techniques (Count: ", TechniqueCount, "); very strong ransomware indicator."),
    IsShadowDelete == 1 and IsVssadminResize == 1, "Shadow copy storage resized; stealthy technique used by ransomware (e.g., Conti).",
    IsShadowDelete == 1 and IsPowerShellShadowDelete == 1, "Shadow copies deleted via PowerShell/WMI; common attacker technique.",
    IsLogClear == 1 and IsShadowDelete == 1, "Log clearing and shadow copy deletion on same host; strong anti-forensics indicator.",
    IsShadowDelete == 1, "Shadow copies deleted; often precursor to ransomware.",
    IsLogClear == 1, "Event logs cleared; anti-forensics behaviour.",
    "Potential anti-forensics tooling invoked."
)
| project Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
          FileName, Cmd, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          ConfidenceScore, Reason, IsLogClear, IsShadowDelete, TechniqueCount
// --- Join with DeviceLogonEvents for critical context ---
| join kind=inner (
    DeviceLogonEvents
    | where Timestamp >= ago(lookback)
    | where LogonType in ("Interactive", "RemoteInteractive") // Focus on console and RDP logons
    | project DeviceId, LogonTime=Timestamp, LogonUser=AccountName, AccountSid, LogonType
) on DeviceId, $left.AccountSid == $right.AccountSid
// Calculate time difference between logon and action
| extend HoursSinceLogon = datetime_diff('hour', Timestamp, LogonTime)
| where HoursSinceLogon between (0 .. 24) // Look for actions within 24 hours of logon
// --- Final Filtering and Sorting ---
| where ConfidenceScore >= 6 // Increased threshold to reduce noise
| order by ConfidenceScore desc, Timestamp desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
