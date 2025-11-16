# Archive-based Data Staging (7z/rar/zip) – Attack Chain Context

```text
Initial Access
    ↓
Execution / foothold
    ↓
Archive-based Data Staging (7z/rar/zip)
    ↓
Lateral movement / persistence / staging
    ↓
Impact (exfiltration, ransomware, account takeover)
```

Use this as an investigation spine: anchor on the detection, then walk backwards
to the initial access and forwards to impact using process, file, network and identity data.
