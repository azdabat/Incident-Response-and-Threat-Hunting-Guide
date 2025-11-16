# SAM/SECURITY Hive Export – Attack Chain Context

```text
Initial Access
    ↓
Execution / foothold
    ↓
SAM/SECURITY Hive Export
    ↓
Lateral movement / persistence / staging
    ↓
Impact (exfiltration, ransomware, account takeover)
```

Use this as an investigation spine: anchor on the detection, then walk backwards
to the initial access and forwards to impact using process, file, network and identity data.
