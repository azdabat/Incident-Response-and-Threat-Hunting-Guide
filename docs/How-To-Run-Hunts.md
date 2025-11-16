## How to Run These Hunts (Native Only)

All rules in this project are 100% native hunts using Microsoft 365 Defender
and Microsoft Sentinel. No external Threat Intelligence is required.

### Run in MDE Advanced Hunting

1. Open Microsoft 365 Defender → Hunting → Advanced Hunting.
2. Paste the KQL from `rules/<category>/<rule>.md`.
3. Use a suitable lookback (for most rules: `14d` if retention allows).
4. Inspect:
   - `ConfidenceScore`
   - `Severity`
   - `HuntingDirectives`

These fields indicate:
- How strong the behaviour signal is.
- How suspicious the activity is.
- What the analyst should do next.

### Run in Sentinel

1. Go to Logs in the Sentinel workspace connected to MDE.
2. Paste the same KQL.
3. Run and triage based on `Severity` and `HuntingDirectives`.

### Turn into Analytic Rules

Each rule has a stub in `sentinel-rules/`. Replace the `query` block with the
KQL from the corresponding `.md` file to promote the hunt into a scheduled
analytic rule.
