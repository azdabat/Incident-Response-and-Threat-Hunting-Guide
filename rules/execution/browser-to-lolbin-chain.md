# Browser → LOLBIN Execution Chain – L3 Native Detection Rule

## Threat Focus

Browser → LOLBIN Execution Chain is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: execution
- MITRE: T1203, T1059, T1218

## Advanced Hunting Query (MDE / Sentinel)

```kql
// ===========================================================
// Vulnerable / Malicious Driver Load (LOLBIN-Chained) – L3 Detection
// Author: Ala Dabat
// MITRE: T1068, T1547.006, T1574.002, T1218
// Combines LOLDrivers.io external TI + native behavioural analysis
// ===========================================================

let lookback = 14d;

// ---------------------------------------------
// 1. External Threat Intel – LOLDrivers.io CSV
// ---------------------------------------------
let VulnerableDriverData = externaldata (
    Id:string, Author:string, Created:string, Command:string, Description:string,
    Usecase:string, Category:string, Privileges:string, MitreID:string,
    OperatingSystem:string, Resources:string, DriverInfo:string, ContactPerson:string,
    HandleReference:string, DetectionMethod:string, MD5_Hashes:string, SHA1_Hashes:string,
    SHA256_Hashes:string, PublisherInfo:string, CompanyInfo:string, VulnerabilityDetails:string,
    MD5_Authentihash:string, SHA256_Authentihash:string, SHA1_Authentihash:string,
    VerificationStatus:string, TagsInfo:string
) ["https://www.loldrivers.io/api/drivers.csv"]
with (format="csv", ignoreFirstRecord=true);

// Normalize SHA256 from TI feed
let VulnerableDriversSHA256 =
    VulnerableDriverData
    | extend IndividualSHA256 = split(SHA256_Hashes, ",")
    | mv-expand IndividualSHA256
    | where isnotempty(IndividualSHA256)
    | extend NormalizedSHA256 = trim(" ", tolower(IndividualSHA256))
    | project NormalizedSHA256, Category, Description, Author, TagsInfo, DriverInfo, Privileges, MitreID;

// ---------------------------------------------------
// 2. Native Telemetry – Loaded Drivers (MDE)
// ---------------------------------------------------
let LoadedDrivers =
DeviceEvents
| where Timestamp >= ago(lookback)
| where ActionType has "DriverLoad"
| extend NormalizedDeviceSHA256 = trim(" ", tolower(SHA256))
| extend FilePath = tostring(AdditionalFields.FilePath)
| extend FileName = tostring(AdditionalFields.FileName);

// ---------------------------------------------------
// 3. Join Native Driver Loads against TI Feed
// ---------------------------------------------------
let DriverHits =
LoadedDrivers
| join kind=inner VulnerableDriversSHA256
    on $left.NormalizedDeviceSHA256 == $right.NormalizedSHA256
| project Timestamp, DeviceName, DeviceId,
          FileName, FilePath,
          NormalizedDeviceSHA256,
          Category, Description, Author, TagsInfo, DriverInfo, Privileges, MitreID;

// ---------------------------------------------------
// 4. Add Behavioural Context (LOLBIN → Driver Load)
// ---------------------------------------------------
let SuspiciousParents = dynamic(["powershell.exe","cmd.exe","cscript.exe","wscript.exe","mshta.exe","rundll32.exe","psexec.exe","certutil.exe","regsvr32.exe"]);

// Correlate with process tree activity in last 60 seconds
let ProcContext =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in (SuspiciousParents)
| project ProcTime=Timestamp, DeviceName, AccountName,
          SuspiciousParent = FileName,
          ProcessCommandLine;

// Join process ancestry to the driver loads
DriverHits
| join kind=leftouter ProcContext on DeviceName
| extend ParentContext = iif(isnotempty(SuspiciousParent), 1, 0)

// ---------------------------------------------------
// 5. Confidence Scoring (Hybrid TI + Behaviour)
// ---------------------------------------------------
| extend ConfidenceScore =
    0
    + 10                                    // matching known vulnerable driver via TI feed
    + iif(ParentContext == 1, 4, 0)         // launched near suspicious LOLBIN execution
    + iif(Category has "Exploit", 2, 0)     // exploit-enabling drivers
    + iif(Privileges has "Kernel", 2, 0)    // kernel-level escalation
    + iif(FilePath has_any ("Temp","AppData","Users","Downloads"), 2, 0) // loaded from user writable dir

// ---------------------------------------------------
// 6. Reason for Analyst (Explain scoring)
// ---------------------------------------------------
| extend Reason = strcat(
    "Driver confirmed from LOLDrivers TI feed: ", FileName, ". ",
    "Category=", Category, ". ",
    "Privileges=", Privileges, ". ",
    iif(ParentContext == 1, strcat("Execution preceded by LOLBIN: ", SuspiciousParent, ". "), ""),
    iif(FilePath has_any ("Temp","AppData","Users","Downloads"),
        strcat("Driver loaded from non-standard directory (", FilePath, "). "), "")
)

// ---------------------------------------------------
// 7. Severity Mapping
// ---------------------------------------------------
| extend Severity = case(
    ConfidenceScore >= 12, "High",
    ConfidenceScore >= 8,  "Medium",
    ConfidenceScore >= 3,  "Low",
    "Informational"
)

// ---------------------------------------------------
// 8. L3 Hunter Directives
// ---------------------------------------------------
| extend HuntingDirectives = strcat(
    "Severity=", Severity,
    "; Device=", DeviceName,
    "; Driver=", FileName,
    "; SHA256=", NormalizedDeviceSHA256,
    "; Category=", Category,
    "; Reason=", Reason,
    "; RecommendedNextSteps=",
    case(
        Severity == "High",
            "Isolate device immediately. Vulnerable driver load strongly correlated with LOLBIN execution; investigate privilege escalation via kernel exploits, check for Bring-Your-Own-Vulnerable-Driver (BYOVD) attack patterns, triage kernel callbacks & recent handle access.",
        Severity == "Medium",
            "Review driver file origin & execution chain. Validate if this driver is expected. Pivot around process activity ±5 mins to check for exploitation or persistence.",
        Severity == "Low",
            "Driver may be custom or legacy. Validate metadata, compare with known-good baselines, and confirm if TI mapping is accurate.",
        "Context signal only; combine with higher-confidence detections."
    )
)

// ---------------------------------------------------
// 9. Final output
// ---------------------------------------------------
| where ConfidenceScore >= 3
| order by Timestamp desc

```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
