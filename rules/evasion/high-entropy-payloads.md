# High-Entropy Payload Drops (Polymorphic) – L3 Native Detection Rule

## Threat Focus

High-Entropy Payload Drops (Polymorphic) is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: evasion
- MITRE: T1027

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ======================================================
// High-Entropy / Polymorphic Payload Drops – L3 Detection
// Category: defense-evasion / execution
// MITRE: T1027 (Obfuscated/Encrypted), T1204, T1059
// Author: Ala Dabat 
// ======================================================

let lookback = 14d;

// Staging locations attackers love
let StagingFolders = dynamic([
    @"C:\Users\",
    @"C:\ProgramData\",
    @"C:\Windows\Temp\",
    @"C:\Temp\",
    @"C:\Users\Public\",
    @"C:\Windows\Tasks\"
]);

// Suspicious payload extensions (tune for environment)
let SuspiciousExt = dynamic([
    ".exe",".dll",".sys",".bin",".dat",".tmp",".scr",
    ".ps1",".vbs",".js",".jse",".cmd",".bat"
]);

// Keywords hinting at crypto/encoding/unpacking
let CryptoKeywords = dynamic([
    "FromBase64String","Base64String","-enc","-EncodedCommand",
    "decrypt","decryption","unpack","xor","rc4","aes","shellcode",
    "VirtualAlloc","VirtualProtect","WriteProcessMemory","CreateThread"
]);

// 1. File drops in staging locations that look like payloads
let StagedPayloads =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend LPath = tolower(FolderPath), LName = tolower(FileName)
| where LPath startswith_any (StagingFolders)
| extend Ext = tostring(extract(@"\.(\w+)$", 1, LName))
| extend ExtFull = strcat(".", Ext)
| where ExtFull in (SuspiciousExt)
| project Timestamp, DeviceId, DeviceName, AccountName,
          FolderPath, FileName, SHA1, SHA256, FileSize, InitiatingProcessFileName,
          InitiatingProcessCommandLine;

// 2. Try to derive basic "entropy" heuristics without true entropy column
//    - long, random-looking file names
//    - large binaries in odd places
let EnrichedPayloads =
StagedPayloads
| extend NameLength = strlen(FileName)
| extend IsLongName = iif(NameLength >= 20, 1, 0)
| extend IsBigFile = iif(FileSize >= 500000, 1, 0)  // > ~500KB
| extend HasNoHash = iif(isempty(SHA1) and isempty(SHA256), 1, 0);

// 3. Correlate with process command lines for signs of decoding/unpacking
let ProcContext =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where ProcessCommandLine has_any (CryptoKeywords)
| project ProcTime = Timestamp, DeviceId, DeviceName, AccountName,
          ProcName = FileName, ProcCmd = ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine;

// Join file drops to suspicious process context on same device and user
EnrichedPayloads
| join kind=leftouter ProcContext on DeviceId, AccountName
| extend HasCryptoContext = iif(isnotempty(ProcName), 1, 0)

// 4. Behaviour-based scoring (pseudo-entropy via multiple weak indicators)
| extend ConfidenceScore =
    0
    + iif(IsBigFile == 1,                           3, 0)   // large binary payload
    + iif(IsLongName == 1,                          2, 0)   // random-looking name
    + iif(HasCryptoContext == 1,                    4, 0)   // unpack/crypto tooling nearby
    + iif(ExtFull in (dynamic([".dll",".sys",".bin",".dat",".tmp"])), 3, 0)
    + iif(ExtFull in (dynamic([".ps1",".js",".jse",".vbs"])),          2, 0)
    + iif(HasNoHash == 1,                           1, 0)   // some older schemas or odd telemetry

// 5. Analyst-facing explanation
| extend Reason = strcat(
    "Payload dropped in staging path: ", FolderPath, "\\", FileName, ". ",
    iif(IsBigFile == 1, "Large binary in non-standard location. ", ""),
    iif(IsLongName == 1, "File name appears long/random. ", ""),
    iif(HasCryptoContext == 1, strcat("Nearby process using crypto/encode keywords: ", ProcName, ". "), ""),
    iif(ExtFull in (dynamic([".dll",".sys",".bin",".dat",".tmp"])), "Binary-like extension. ", ""),
    iif(ExtFull in (dynamic([".ps1",".js",".jse",".vbs"])), "Script extension commonly used as loader. ", "")
)

// 6. Severity mapping
| extend Severity = case(
    ConfidenceScore >= 10, "High",
    ConfidenceScore >= 6,  "Medium",
    ConfidenceScore >= 3,  "Low",
    "Informational"
)

// 7. Hunter directives
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; User=", AccountName,
    "; Path=", FolderPath, "\\", FileName,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Treat as likely packed or encrypted payload. Examine InitiatingProcessCommandLine for decoding/unpacking logic. Check for follow-on execution from this path, memory injection, or abnormal network traffic. Isolate host if other malicious indicators exist.",
        Severity == "Medium",
            "Manually inspect the file (static + detonation in controlled environment). Correlate with process tree. Review whether this is part of legitimate software deployment or a suspicious drop.",
        Severity == "Low",
            "Baseline behaviour for this endpoint. Consider adding known-good software drop patterns to exclusions.",
        "Use as contextual indicator. Combine with other detections."
    )
)

// 8. Final filter
| where ConfidenceScore >= 3
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
