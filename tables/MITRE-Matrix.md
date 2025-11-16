# Native Detection Bible – MITRE Mapping

| Category | Key | Title | MITRE Techniques |
|----------|-----|-------|------------------|
| execution | phishing-macro-lolbin-chain | Phishing → Office Macro → LOLBIN Chain | T1566, T1204, T1059, T1218 |
| execution | browser-to-lolbin-chain | Browser → LOLBIN Execution Chain | T1203, T1059, T1218 |
| execution | powershell-script-abuse | Suspicious PowerShell Script Abuse | T1059.001 |
| execution | wsl-execution | WSL-based Execution and Scripting | T1204, T1059 |
| execution | winget-lolbin-abuse | Modern LOLBIN – Winget Package Abuse | T1218, T1059 |
| credential-access | lsass-credential-dump | LSASS Credential Dumping Behaviour | T1003.001, T1055 |
| credential-access | sam-security-hive-export | SAM/SECURITY Hive Export | T1003.002 |
| credential-access | ntds-dit-replication | NTDS.dit Replication / DCSync-like | T1003.006 |
| credential-access | pass-the-hash | Pass-the-Hash Pattern (NTLM) | T1550.002 |
| credential-access | pass-the-ticket | Pass-the-Ticket / Kerberos Ticket Abuse | T1550.003, T1558.003 |
| lateral-movement | smb-psexec-adminshare | SMB / PsExec-style ADMIN$ Lateral Movement | T1021.002, T1077 |
| lateral-movement | wmi-lateral-execution | WMI-based Lateral Execution | T1047 |
| lateral-movement | winrm-lateral-execution | WinRM-based Lateral Execution | T1021.006 |
| lateral-movement | rdp-lateral | RDP Lateral Movement | T1021.001 |
| lateral-movement | sql-xpcmdshell-lateral | SQL Server xp_cmdshell / Agent Lateral Movement | T1505.001, T1059 |
| persistence | registry-run-startup | Registry Run / Startup Folder Persistence | T1060, T1547.001 |
| persistence | scheduled-task-persistence | Scheduled Task Persistence | T1053.002 |
| persistence | service-creation-persistence | Malicious Service Creation Persistence | T1543.003 |
| persistence | wmi-event-subscription | WMI Event Subscription Persistence | T1546.003 |
| persistence | wsl-cron-persistence | WSL Cron-based Persistence | T1053 |
| evasion | log-clearing-shadow-copies | Log Clearing and Shadow Copy Deletion | T1070, T1489 |
| evasion | etw-amsi-tamper | ETW / AMSI Tampering Behaviour | T1562 |
| evasion | timestomping | File Timestomping Behaviour | T1070.006 |
| evasion | process-hollowing | Process Hollowing / PE-swap | T1055.012 |
| evasion | high-entropy-payloads | High-Entropy Payload Drops (Polymorphic) | T1027 |
| c2 | suspicious-443-beacons | Suspicious 443 Beacon Patterns | T1071.001 |
| c2 | unknown-useragent-c2 | Unknown or Rare User-Agent C2 | T1071 |
| c2 | long-lived-sessions | Long-Lived External Sessions (Implant-like) | T1071 |
| exfiltration | archive-data-staging | Archive-based Data Staging (7z/rar/zip) | T1074, T1560 |
| exfiltration | https-volume-exfil | Data Exfiltration over HTTPS (Volume Anomaly) | T1041, T1048.002 |
| cloud | oauth-consent-abuse | OAuth Consent Abuse (Native Logs) | T1528, T1098 |
| cloud | mfa-fatigue | MFA Fatigue / Push Spamming | Credential abuse |
| cloud | cloud-admin-drift | Cloud Admin Role Drift / Escalation | T1098 |
| supply-chain | signed-installer-post-compromise | Signed Installer Post-Install C2 Behaviour | T1195, T1105 |
| supply-chain | vendor-binary-sideload | Vendor Binary → DLL Sideloading (Native) | T1574.002 |