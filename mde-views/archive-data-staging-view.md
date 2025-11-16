# Archive-based Data Staging (7z/rar/zip) – MDE / Sentinel Analyst View

## What you see

- Key columns: `DeviceName`, `AccountName`, `FileName`, command line (`Cmd`),
  `ConfidenceScore`, `Severity`, `Reason`, `HuntingDirectives`.

## L3 Analyst Actions

- Start from the most recent `Timestamp` for a given `DeviceName` + `AccountName`.
- Follow the `HuntingDirectives` field as the first decision aid:
  - It encodes whether to contain, baseline, or deepen the hunt.
- Pivot out:
  - `DeviceProcessEvents` for full parent/child tree.
  - `DeviceFileEvents` for payloads, configs and tools.
  - `DeviceNetworkEvents` for C2 and lateral movement.
  - Identity / AAD logs where applicable.
