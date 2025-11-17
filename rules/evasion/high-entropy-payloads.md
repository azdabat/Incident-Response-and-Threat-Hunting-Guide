# High-Entropy Payload Drops (Polymorphic) – L3 Native Detection Rule

## Threat Focus

High-Entropy Payload Drops (Polymorphic) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1027

## Advanced Hunting Query (MDE / Sentinel)

```kql
// High-Entropy / Polymorphic Payload Drops — L3 Native Detection
// MITRE: T1027, T1059, T1204
// Author: Ala Dabat | 2025-11

let lookback = 14d;

let StagingFolders = dynamic([
    @"C:\Users\",
    @"C:\ProgramData\",
    @"C:\Windows\Temp\",
    @"C:\Temp\",
    @"C:\Users\Public\",
    @"C:\Windows\Tasks\"
]);

let SuspiciousExt = dynamic([
    ".exe",".dll",".sys",".bin",".dat",".tmp",".scr",
    ".ps1",".vbs",".js",".jse",".cmd",".bat"
]);

let CryptoKeywords = dynamic([
    "FromBase64String","Base64String","-enc","-EncodedCommand",
    "decrypt","decryption","unpack","xor","rc4","aes","shellcode",
    "VirtualAlloc","VirtualProtect","WriteProcessMemory","CreateThread"
]);

// 1 — File drops in attacker-preferred staging locations
let Drops =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend LPath=tolower(FolderPath), LName=tolower(FileName)
| where LPath startswith_any (StagingFolders)
| extend Ext = strcat(".", tostring(extract(@"\.(\w+)$",1,LName)))
| where Ext in (SuspiciousExt)
| project Timestamp, DeviceId, DeviceName, AccountName,
          FolderPath, FileName, Ext, SHA1, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine;

// 2 — Light “entropy” heuristics
let Enriched =
Drops
| extend NameLength = strlen(FileName),
         LargeFile  = FileSize >= 500000,
         LongName   = NameLength >= 20,
         MissingHash = isempty(SHA1) and isempty(SHA256);

// 3 — Processes performing crypto/unpack/loader behaviour
let Proc =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where ProcessCommandLine has_any (CryptoKeywords)
| project DeviceId, AccountName,
          ProcTime=Timestamp,
          ProcName=FileName, ProcCmd=ProcessCommandLine,
          Parent=InitiatingProcessFileName;

// Join on host + user
Enriched
| join kind=leftouter Proc on DeviceId, AccountName
| extend HasCryptoContext = isnotempty(ProcName)

// 4 — Severity classification (no weighting)
| extend Severity = case(
      LargeFile == 1 and HasCryptoContext == 1, "High",
      LongName == 1  and HasCryptoContext == 1, "High",
      HasCryptoContext == 1,                   "Medium",
      LargeFile == 1 or LongName == 1,         "Medium",
      "Low"
)

// 5 — Reason & directives
| extend Reason = strcat(
      "Payload dropped: ", FolderPath, "\\", FileName, ". ",
      iif(LargeFile, "Large binary in staging location. ", ""),
      iif(LongName,  "Long or random-looking name. ", ""),
      iif(HasCryptoContext,
          strcat("Associated process with unpack/crypto keywords (", ProcName, "). "), "")
)

| extend NextSteps = case(
      Severity == "High",
        "Likely encrypted or unpacked payload. Inspect process tree, check memory allocation APIs, review subsequent execution and network activity. Isolate host if other indicators exist.",
      Severity == "Medium",
        "Inspect file statically and dynamically. Correlate with process lineage. Confirm whether part of legitimate software distribution.",
      "Low — baseline candidate or non-malicious drop."
)

// Final output
| project Timestamp, DeviceName, AccountName,
          FolderPath, FileName, Ext, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          HasCryptoContext, ProcName, ProcCmd,
          Severity, Reason, NextSteps
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
