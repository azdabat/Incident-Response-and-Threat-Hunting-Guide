# SOC Investigation Spine: WSL Cron-based Persistence – T1546.004

**Explanation:** This playbook analyzes the abuse of the **Windows Subsystem for Linux (WSL)** and the native Linux scheduler **cron** to establish persistence. The attacker gains initial access, deploys a payload within the Linux environment, and then uses a cron job (`crontab`) to schedule the payload's execution at regular intervals or system events. This technique is highly evasive because the persistence mechanism and execution occur primarily within the WSL virtualized environment, making standard Windows security logs (`System`, `Security`, `Application`) less effective for direct detection. The most reliable **Anchor Point** is the **modification of the cron configuration file** or the **WSL background service spawning the initial Linux shell (`bash`/`sh`)** that executes the malicious job.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566 (Phishing) / T1059 (Execution) | **Windows Host:** Dropper executes to stage the WSL payload and initiate the WSL environment. | **Process Event:** Initial execution of `wsl.exe` or `bash.exe` on the Windows host. |
| **Execution / Foothold** | T1036.004 (Masquerading) / T1059.004 (Unix Shell) | **WSL/File:** Payload is dropped into the Linux filesystem, and cron is configured. | **Linux File System Change:** Modification of the user's crontab file (`/var/spool/cron/crontabs/<user>`) or system crontab (`/etc/cron.d/`). |
| **Persistence (ANCHOR)**| **T1546.004 (Cron)** | **WSL/Log:** The cron daemon runs the malicious job based on the scheduled time/event. | **Linux Audit Log/EDR Event:** **Cron daemon process (`cron` or `crond`)** spawns an anomalous child process (e.g., `bash`, `sh`) that executes the payload. |
| **Execution on Windows** | T1548.003 (Bypass User Account Control) | **Process:** The WSL payload executes a command that interacts with the Windows host, often via `wsl.exe` or by accessing the Windows file system (`/mnt/c/`). | **Process Anomaly (Windows):** **`wsl.exe` Parent** → **`cmd.exe` or `powershell.exe` Child** on the Windows host. |
| **Impact / Data Staging** | T1041 (Exfiltration Over C2) | **Network:** The payload initiates C2 communication, often disguised as Linux traffic. | **Network Log:** Outbound connection from a WSL process to an external C2 IP/domain. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence WSL/Linux IOCs

1.  **Crontab Modification (The Cron Tell):** The most direct evidence resides within the WSL filesystem:
    * **File System Change:** Look for recent modifications to the user's crontab file (usually `/var/spool/cron/crontabs/<user>`) or system-wide configuration files (`/etc/crontab`, `/etc/cron.d/`). The modification time (MAC time) of these files should be checked against known activity.
    * **Crontab Entry Analysis:** The entry will contain the full payload command, often a short, obfuscated script that runs at frequent intervals (e.g., `* * * * * /tmp/.payload.sh`).
2.  **WSL Execution Chain:** When the job executes, the process chain within the WSL instance will be:
    * **Parent Process:** **`cron` or `crond` daemon**.
    * **Child Process:** **`bash` or `sh`** running the payload script.
    * **Context:** The execution context is under the user account tied to the crontab, or root for system-wide crontabs. This event must be captured by an EDR or auditd (Linux Auditing System) running within the WSL instance.
3.  **WSL Network Activity:** WSL processes (e.g., `bash`, `python`) may initiate C2 traffic. Network logs must be checked for outbound connections where the source process is a WSL executable, often using non-standard libraries or connections.

### Windows Host Artifacts

1.  **WSL Process Spawning (Windows EDR):** On the Windows host, the execution of the cron job that interacts with the Windows environment will be visible in the EDR logs:
    * **Parent Process:** **`wsl.exe`** or **`init`** (for WSL2).
    * **Child Process:** A Windows binary executed from within WSL (e.g., `/mnt/c/Windows/System32/cmd.exe` or `C:\...powershell.exe`). This confirms the payload has breached the WSL boundary.
2.  **WSL Event Logs:** Review the **Microsoft-Windows-Subsystem-Linux/Operational log** for unusual commands being passed to the Linux environment, or unexpected starts/stops of the distribution.
3.  **File Staging:** Look for files created in the shared Windows drive mount (`/mnt/c/Users/<user>/...`) by a WSL process, often used to stage stolen data or drop the final Windows payload.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Remove the cron job and the payload; isolate the WSL environment. | **Remove the malicious entry** from the user's crontab (`crontab -r -u <user>`). **Terminate the WSL service/instance**. **Quarantine the payload file** within the Linux filesystem. |
| **WSL Visibility** | **EDR/Auditd on WSL:** Extend security monitoring into the Linux environment. | **Deploy an EDR agent or configure `auditd`** within the WSL distribution to specifically monitor file writes to `/var/spool/cron/crontabs/` and process spawns from the `cron` daemon. |
| **Process Control** | **Restrict WSL Interactivity:** Block the most abused cross-environment interaction paths. | Configure EDR rules to **block `wsl.exe` from spawning Windows command interpreters** (`cmd.exe`, `powershell.exe`) outside of a small, whitelisted set of administrative users. |
| **Configuration** | **Disable or Restrict WSL:** Minimize the attack surface provided by the Linux environment. | **Disable the Windows Subsystem for Linux feature** globally if not required, or strictly limit its usage and ensure all user-defined WSL environments are managed and monitored. |
