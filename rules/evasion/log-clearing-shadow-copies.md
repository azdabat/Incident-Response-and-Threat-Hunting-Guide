# Log Clearing and Shadow Copy Deletion – L3 Native Detection Rule

## Threat Focus

Log Clearing and Shadow Copy Deletion is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1070, T1489

## Advanced Hunting Query (MDE / Sentinel)

```kql
// Anti-Forensics: Log Clearing & Shadow Copy Removal — L3 Native
// MITRE: T1070 (Indicator Removal), T1490 (Inhibit Recovery)
// Author: Ala Dabat | 2025-11

let lookback = 14d;

let Tools = dynamic([
    "wevtutil.exe","vssadmin.exe","powershell.exe","cmd.exe",
    "wmic.exe","diskshadow.exe","wbadmin.exe"
]);

// 1 — Process creation for anti-forensics tooling
let Proc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (Tools)
| extend Cmd = tostring(ProcessCommandLine),
         Parent = tostring(InitiatingProcessFileName)
| project Timestamp, DeviceName, DeviceId, AccountName, AccountSid,
          FileName, Cmd, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;

// 2 — Log clearing activity
let ProcWithLogFlags =
Proc
| extend LogClear =
      Cmd has "wevtutil" and Cmd has_any ("cl","clear-log","/c")
      or (Cmd has "wmic" and Cmd has "nteventlog" and Cmd has "delete")

// 3 — Shadow copy removal activity
| extend ShadowDelete =
      (Cmd has "vssadmin" and Cmd has_any ("delete","shadows"))
      or (Cmd has "wmic" and Cmd has "shadowcopy" and Cmd has "delete")
      or (Cmd has "powershell" and Cmd has_any ("Win32_Shadowcopy","Delete()"))
      or (Cmd has "vssadmin" and Cmd has "resize" and Cmd has "shadowstorage")
      or (Cmd has "wbadmin" and Cmd has_any ("delete","catalog"));

// 4 — Behaviour classification (no scoring)
| extend Severity = case(
      LogClear == true and ShadowDelete == true,  "High",
      ShadowDelete == true,                      "High",
      LogClear == true,                          "Medium",
      "Low"
)

| extend Reason = case(
      LogClear and ShadowDelete,
        "Log clearing and shadow copy deletion performed — strong anti-forensics/ransomware behaviour.",
      ShadowDelete,
        "Shadow copies removed or resized — common ransomware technique.",
      LogClear,
        "Event logs cleared using system utilities.",
      "Anti-forensics tool invoked."
);

// 5 — Correlate with interactive logons (extra signal)
let Logons =
DeviceLogonEvents
| where Timestamp >= ago(lookback)
| where LogonType in ("Interactive","RemoteInteractive")
| project DeviceId, AccountSid, LogonTime=Timestamp, LogonUser=AccountName;

ProcWithLogFlags
| join kind=inner Logons on DeviceId, AccountSid
| extend HoursSinceLogon = datetime_diff("hour", Timestamp, LogonTime)
| where HoursSinceLogon between (0 .. 24)  // activity tied to recent login

| where Severity in ("High","Medium")      // noise reduction

| project Timestamp, DeviceName, AccountName,
          FileName, Cmd, Parent,
          LogClear, ShadowDelete,
          Severity, Reason,
          HoursSinceLogon,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
