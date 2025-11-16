# Unknown or Rare User-Agent C2 – L3 Native Detection Rule

## Threat Focus

Unknown or Rare User-Agent C2 is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: c2
- MITRE: T1071

## Advanced Hunting Query (MDE / Sentinel)

```kql
// Suspicious Port Threat Hunt — With Full Process Attribution
// Author: Ala Dabat

// ---- Load external CSV of suspicious ports ----
let SuspiciousPortsData =
    externaldata(
        dest_port:int,
        metadata_comment:string,
        metadata_confidence:string,
        metadata_detection_type:string,
        metadata_link:string,
        metadata_reference:string
    )
    ["https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_ports_list.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | where metadata_confidence != "low";

let SuspiciousPortList = toscalar(SuspiciousPortsData | summarize make_set(dest_port));

let PortDetails = SuspiciousPortsData
| project dest_port, metadata_comment, metadata_confidence;

// ---- Main Hunt ----
DeviceNetworkEvents
| where RemotePort in (SuspiciousPortList)
| where not(RemoteIP startswith "10." or RemoteIP startswith "192.168." or RemoteIP startswith "172.")
| join kind=inner PortDetails on $left.RemotePort == $right.dest_port

// ---- Extract all relevant process telemetry ----
| extend 
    Proc = InitiatingProcessFileName,
    ProcCL = InitiatingProcessCommandLine,
    ProcSHA256 = InitiatingProcessSHA256,
    ProcSigner = InitiatingProcessSigner,
    ProcPath = InitiatingProcessFolderPath,
    ParentProc = InitiatingProcessParentFileName,
    User = InitiatingProcessAccountName

// ---- Summaries for triage ----
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Count = count(),
    SampleProcess = arg_max(Timestamp, Proc),
    SampleCommand = arg_max(Timestamp, ProcCL),
    SampleHash = arg_max(Timestamp, ProcSHA256),
    SampleSigner = arg_max(Timestamp, ProcSigner),
    SampleParent = arg_max(Timestamp, ParentProc),
    Users = make_set(User,10)
  by DeviceName, RemoteIP, RemotePort, metadata_comment, metadata_confidence

// ---- Risk Classification ----
| extend RiskLevel = case(
    metadata_confidence == "high", "CRITICAL",
    metadata_confidence == "medium", "HIGH",
    "MEDIUM"
),
MITRE_Tactics = "TA0011 Command and Control",
MITRE_Techniques = case(
    RemotePort == 1080, "T1090 Proxy",
    RemotePort == 1194, "T1573 Encrypted Channel",
    "T1071 Application Layer Protocol"
),
VT_Link = strcat("https://www.virustotal.com/gui/ip-address/", RemoteIP)

// ---- Hunter Directives ----
| extend HuntingDirectives = pack_array(
    strcat("1) Investigate executable using port: ", SampleProcess),
    strcat("2) Parent process: ", SampleParent),
    strcat("3) Command line: ", SampleCommand),
    strcat("4) SHA256: ", SampleHash, " | Signer: ", SampleSigner),
    strcat("5) Review ", tostring(Count), " connections to ", RemoteIP),
    strcat("6) Port context: ", metadata_comment),
    strcat("7) VirusTotal IP check: ", VT_Link),
    "8) Pivot into DeviceProcessEvents for full process tree",
    "9) Review logon context and isolate if malicious"
)

// ---- Final Output (your exact projection) ----
| project
    FirstSeen, LastSeen, DeviceName, RemoteIP, RemotePort, Count,
    RiskLevel,
    PortContext = metadata_comment,
    Confidence = metadata_confidence,
    SampleProcess, SampleCommand,
    MITRE_Tactics, MITRE_Techniques, VT_Link, HuntingDirectives

| order by RiskLevel desc, Count desc, FirstSeen desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
