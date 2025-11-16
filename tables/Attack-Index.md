# Native Detection Bible – Attack Index

| Category | Key | Title |
|----------|-----|-------|
| execution | phishing-macro-lolbin-chain | Phishing → Office Macro → LOLBIN Chain |
| execution | browser-to-lolbin-chain | Browser → LOLBIN Execution Chain |
| execution | powershell-script-abuse | Suspicious PowerShell Script Abuse |
| execution | wsl-execution | WSL-based Execution and Scripting |
| execution | winget-lolbin-abuse | Modern LOLBIN – Winget Package Abuse |
| credential-access | lsass-credential-dump | LSASS Credential Dumping Behaviour |
| credential-access | sam-security-hive-export | SAM/SECURITY Hive Export |
| credential-access | ntds-dit-replication | NTDS.dit Replication / DCSync-like |
| credential-access | pass-the-hash | Pass-the-Hash Pattern (NTLM) |
| credential-access | pass-the-ticket | Pass-the-Ticket / Kerberos Ticket Abuse |
| lateral-movement | smb-psexec-adminshare | SMB / PsExec-style ADMIN$ Lateral Movement |
| lateral-movement | wmi-lateral-execution | WMI-based Lateral Execution |
| lateral-movement | winrm-lateral-execution | WinRM-based Lateral Execution |
| lateral-movement | rdp-lateral | RDP Lateral Movement |
| lateral-movement | sql-xpcmdshell-lateral | SQL Server xp_cmdshell / Agent Lateral Movement |
| persistence | registry-run-startup | Registry Run / Startup Folder Persistence |
| persistence | scheduled-task-persistence | Scheduled Task Persistence |
| persistence | service-creation-persistence | Malicious Service Creation Persistence |
| persistence | wmi-event-subscription | WMI Event Subscription Persistence |
| persistence | wsl-cron-persistence | WSL Cron-based Persistence |
| evasion | log-clearing-shadow-copies | Log Clearing and Shadow Copy Deletion |
| evasion | etw-amsi-tamper | ETW / AMSI Tampering Behaviour |
| evasion | timestomping | File Timestomping Behaviour |
| evasion | process-hollowing | Process Hollowing / PE-swap |
| evasion | high-entropy-payloads | High-Entropy Payload Drops (Polymorphic) |
| c2 | suspicious-443-beacons | Suspicious 443 Beacon Patterns |
| c2 | unknown-useragent-c2 | Unknown or Rare User-Agent C2 |
| c2 | long-lived-sessions | Long-Lived External Sessions (Implant-like) |
| exfiltration | archive-data-staging | Archive-based Data Staging (7z/rar/zip) |
| exfiltration | https-volume-exfil | Data Exfiltration over HTTPS (Volume Anomaly) |
| cloud | oauth-consent-abuse | OAuth Consent Abuse (Native Logs) |
| cloud | mfa-fatigue | MFA Fatigue / Push Spamming |
| cloud | cloud-admin-drift | Cloud Admin Role Drift / Escalation |
| supply-chain | signed-installer-post-compromise | Signed Installer Post-Install C2 Behaviour |
| supply-chain | vendor-binary-sideload | Vendor Binary → DLL Sideloading (Native) |