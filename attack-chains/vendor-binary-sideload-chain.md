# SOC Investigation Spine: Vendor Binary → DLL Sideloading (Native) – T1574.001

**Explanation:** This playbook analyzes the **DLL Sideloading** technique, a highly effective defense evasion method where an attacker places a malicious DLL in a directory that is prioritized by the Windows loader when resolving dependencies for a legitimate, often signed, **Vendor Binary**. When the victim executes the trusted binary, the operating system's DLL search order causes it to load the malicious DLL first, executing the attacker's code with the trust context of the legitimate application. The most reliable **Anchor Point** is the **detection of a legitimate, signed executable loading an unexpected DLL** from a non-standard, user-writable directory.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1105 (Ingress Transfer) | **Endpoint/File:** User executes a dropper or installer that writes the malicious DLL and the signed vendor binary to the same directory. | **File Creation Event:** Dropping of two files (e.g., `legit.exe` and `malicious.dll`) into a temporary path (e.g., `C:\Users\Public\`). |
| **Execution / Foothold** | T1574.001 (DLL Search Order Hijacking) | **Process:** The user executes the benign vendor binary, which triggers the loading of the malicious DLL. | **Process Event:** Execution of a **signed binary** (e.g., `UpdateService.exe`) that is *not* located in its default installation path (`Program Files`). |
| **Sideloading (ANCHOR)**| **T1574.001 (DLL Side-Loading)** | **Module/Process:** A legitimate process loads a DLL that has an **unusual path, invalid signature, or unknown publisher**. | **Module Load Event:** **`legit.exe` Parent** attempts to load **`malicious.dll`** from a user-writable path (`\temp\`) instead of `System32`. |
| **Lateral Movement / Persistence** | T1543.003 (Service Creation) / T1083 (File Recon) | **Registry/Process:** The malicious DLL's payload executes, performing reconnaissance or establishing SYSTEM-level persistence. | **Service Event ID 7045:** Creation of a new Windows service initiated by the **`legit.exe`** process. |
| **Impact / Data Exfil** | T1041 (Exfiltration Over C2) | **Network:** The malicious code within the signed binary establishes an outbound C2 connection. | **Network Flow:** Outbound connection from the **`legit.exe`** process to an external C2 IP or domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Process & Module IOCs

1.  **Module Load Anomaly (The Sideloading Tell):** The most critical IOC is the **Module Load Event** captured by EDR/Process monitoring tools. Focus on these criteria:
    * **Host Process (Parent):** A **digitally signed, legitimate vendor executable** (the binary being abused).
    * **Loaded Module (Child):** A DLL being loaded with a **suspicious file path** (e.g., `C:\Users\Public`, `C:\Windows\Temp`) when the operating system expected to load it from a system directory (`C:\Windows\System32`).
    * **Signature Mismatch:** The host process has a valid signature, but the loaded DLL has **no signature or an invalid/expired signature**.
2.  **Process Context Misplacement:** Analyze the execution path of the signed vendor binary. Legitimate system services or applications usually run from a protected path (`Program Files`, `System32`). Execution of a known, signed binary from an **unprotected, user-writable directory** is highly suspicious and a prerequisite for successful sideloading.
3.  **Process Command Line:** Check the command-line arguments used to launch the vendor binary. Attackers sometimes use specific arguments to ensure the binary executes in a way that triggers the targeted DLL load path.

### File, Network, and Identity IOCs

1.  **File System Dropping:** The files involved (the vendor binary and the malicious DLL) are often dropped simultaneously. Look for the **File Creation Events** of both files occurring near-simultaneously in the same non-standard directory, confirming the staging operation.
2.  **Network Activity from Trusted Process:** After successful sideloading, the malicious code initiates C2 activity. Check network logs for an **outbound connection** originating from the process name of the **legitimate vendor binary**. Since the binary itself is trusted, this network activity is anomalous for that specific process.
3.  **DLL Analysis:** The malicious DLL itself must be analyzed. Its **export table** (functions made available) may mimic the legitimate DLL it is replacing, but its **import table** (dependencies) will reveal its true malicious function (e.g., network APIs, process injection APIs).

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Remove the malicious files and prevent further execution of the vulnerable binary from the staging location. | **Quarantine both the malicious DLL and the signed vendor binary** from the compromised directory. **Block the hashes** of both files across the network. |
| **Configuration Control** | **Prevent Loading from Unprotected Paths:** Modify environment settings to restrict search paths. | Enable the **`DoNotLoad`** registry value (or similar controls) for specific vulnerable vendor binaries to restrict their search order to system-protected directories. |
| **Application Control** | **Restrict Execution/Module Loading:** Prevent the execution of the signed binary from non-standard locations. | Use **Windows Defender Application Control (WDAC)** or **AppLocker** to restrict execution of known vulnerable vendor binaries only when they are located in their **expected installation paths** (`Program Files`, `System32`). |
| **System Integrity Monitoring** | **Baseline Module Loading:** Baseline and monitor the expected DLLs loaded by high-value, signed processes. | Configure EDR to alert on **Module Load Events** where the module file path is **not a system path** and the module is **not digitally signed**, especially when loaded by a signed parent process. |
