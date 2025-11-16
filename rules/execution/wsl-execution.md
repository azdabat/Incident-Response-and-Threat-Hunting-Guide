# WSL-based Execution and Scripting – L3 Native Detection Rule

## Threat Focus

WSL-based Execution and Scripting is detected using pure native telemetry (no external TI) at L3 fidelity.

- Category: execution
- MITRE: T1204, T1059

## Advanced Hunting Query (MDE / Sentinel)

```kql
// =============================================================================
// WSL Privilege Escalation & Persistence Detection
// Author: Ala Dabat
// Description: High-fidelity detection for WSL abuse patterns focusing on 
//              privilege escalation, persistence, and container escape
// MITRE ATT&CK: T1611 - Escape to Host, T1068 - Exploitation for Privilege Escalation,
//               T1078 - Valid Accounts, T1055 - Process Injection
// =============================================================================

let WslExecutables = dynamic(["wsl.exe","wslhost.exe","bash.exe","ubuntu.exe","kali.exe","debian.exe"]);
let CriticalMaliciousFlags = dynamic([
    "--debug-shell", "--system", "-u root", "--user root",
    "/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa", "/var/run/docker.sock"
]);
let HighRiskParents = dynamic([
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", 
    "rundll32.exe", "installutil.exe"
]);
let NetworkExecPattern = @"\s(-e|--exec)\s+(""|')?(nc\s|curl\s+http|wget\s+http|python\s+-c\s+""import|perl\s+-e\s+""system)";
let SuspiciousMountPattern = @"(--mount|--unmount).*(/mnt/c/Windows|/mnt/c/ProgramData|/mnt/c/Users)";

let ProcessSuspicious =
DeviceProcessEvents
| where FileName in~ (WslExecutables)
| extend
    f = tolower(FileName),
    cli = tolower(ProcessCommandLine),
    p = tolower(InitiatingProcessFileName)
| where (
        (cli has_any (CriticalMaliciousFlags) and p in~ (HighRiskParents))
        or
        (cli matches regex NetworkExecPattern and p in~ (HighRiskParents))
        or
        (cli matches regex SuspiciousMountPattern)
        or
        (p in~ ("mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"))
    )
    and not (
        cli has_all ("--install", "ubuntu") or 
        cli has_all ("--update", "kernel") or
        cli has_all ("--list", "--verbose") or
        cli contains " --help" or
        cli contains " --version"
    )
// THREAT HUNTER DIRECTIVES - RISK & THREAT BASED
| extend HuntingDirectives = case(
    // THREAT-BASED: High confidence malicious activity
    p in~ ("mshta.exe", "wscript.exe", "cscript.exe") and cli has_any ("--debug-shell", "/etc/shadow", "/etc/sudoers"),
    "IMMEDIATE INVESTIGATION: Script engine spawning WSL with critical system access - Check for embedded scripts and parent process chain",
    
    // THREAT-BASED: Container escape attempt
    cli matches regex SuspiciousMountPattern,
    "CONTAINER ESCAPE ATTEMPT: WSL mounting Windows directories - Review mount targets and file access patterns",
    
    // RISK-BASED: Network tool execution
    cli matches regex NetworkExecPattern,
    "SUSPICIOUS EXECUTION: Network tools via WSL exec - Correlate with network connections and outbound traffic",
    
    // THREAT-BASED: Privilege escalation evidence
    cli has_any ("--user root", "-u root", "--system") and p in~ (HighRiskParents),
    "PRIVILEGE ESCALATION: Suspicious parent obtaining root access via WSL - Audit user account and group membership changes",
    
    // RISK-BASED: General suspicious execution
    true,
    "INVESTIGATE: Suspicious WSL execution pattern - Review command line arguments and initiating process context"
    ),
    MitreTactics = "T1611,T1068,T1078,T1055",
    InvestigationPriority = case(
        p in~ ("mshta.exe", "wscript.exe") and cli has_any ("--debug-shell", "/etc/shadow"), "CRITICAL",
        cli matches regex NetworkExecPattern, "HIGH", 
        cli matches regex SuspiciousMountPattern, "HIGH",
        true, "MEDIUM"
    )
| project
    Timestamp,
    DeviceName,
    Detection = "WSL-Privilege-Escalation-Persistence",
    ParentProcess = p,
    ParentCmdLine = InitiatingProcessCommandLine,
    FileName = f,
    ProcessCommandLine = cli,
    HuntingDirectives,
    InvestigationPriority,
    MitreTactics,
    InitiatingProcessAccountName,
    FolderPath,
    SHA256;

let CriticalSensitivePaths = dynamic([
    "/etc/shadow", "/etc/sudoers", "/etc/gshadow", 
    "/root/.ssh/authorized_keys", "/var/run/docker.sock"
]);
let CriticalPermissionRegex = @"\b(666|777|6[0-9][0-9]6|7[0-9][0-9]7)\b";

let FilePermsCritical =
DeviceFileEvents
| where ActionType in~ ("FileCreated", "FileModified", "PermissionsModified")
| where tolower(FolderPath) has_any (CriticalSensitivePaths)
| extend af = tostring(AdditionalFields)
| where af matches regex CriticalPermissionRegex
| where not (InitiatingProcessFileName in~ ("apt", "dpkg", "yum", "systemd", "init", "cron"))
// THREAT HUNTER DIRECTIVES - RISK & THREAT BASED
| extend HuntingDirectives = case(
    // THREAT-BASED: Critical system file permission weakening
    FolderPath contains "/etc/shadow" and af matches regex @"\b(666|777)\b",
    "CRITICAL THREAT: /etc/shadow permissions weakened - Immediate system compromise possible - Check for unauthorized account creation",
    
    // THREAT-BASED: SSH key exposure
    FolderPath contains "/root/.ssh/authorized_keys" and af matches regex @"\b(666|777)\b",
    "PERSISTENCE THREAT: SSH authorized_keys exposed - Attacker may have added backdoor keys - Audit SSH key changes",
    
    // RISK-BASED: Docker socket exposure
    FolderPath contains "/var/run/docker.sock" and af matches regex @"\b(666|777)\b",
    "CONTAINER ESCAPE RISK: Docker socket permissions weakened - Review container security context and privilege levels",
    
    // RISK-BASED: Sudoers file modification
    FolderPath contains "/etc/sudoers" and af matches regex @"\b(666|777)\b",
    "PRIVILEGE ESCALATION RISK: Sudoers file exposed - Check for unauthorized privilege grants",
    
    true,
    "INVESTIGATE: Critical file permission change - Review file integrity and process lineage"
    ),
    MitreTactics = "T1222.002,T1068,T1078",
    InvestigationPriority = case(
        FolderPath contains "/etc/shadow", "CRITICAL",
        FolderPath contains "/root/.ssh", "HIGH",
        FolderPath contains "/var/run/docker.sock", "HIGH",
        true, "MEDIUM"
    )
| project
    Timestamp,
    DeviceName,
    Detection = "Critical-File-Permission-Weakness",
    FileName,
    FolderPath,
    ActionType,
    AdditionalFields,
    HuntingDirectives,
    InvestigationPriority,
    MitreTactics,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName;

union ProcessSuspicious, FilePermsCritical
| order by Timestamp desc
```

The query exposes:

- `ConfidenceScore` – behaviour-based strength of the signal.
- `Severity` – derived from `ConfidenceScore`.
- `HuntingDirectives` – inline analyst guidance (L3-level) on what to do next.
