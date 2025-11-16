# WSL-based Execution and Scripting – Attack Chain Context

```text
Initial Access
    ↓
Execution / foothold
    ↓
WSL-based Execution and Scripting
    ↓
Lateral movement / persistence / staging
    ↓
Impact (exfiltration, ransomware, account takeover)
```

Use this as an investigation spine: anchor on the detection, then walk backwards
to the initial access and forwards to impact using process, file, network and identity data.
