# Security Log Investigation (Task 4)

Analysis of a **synthetic** authentication log (documentation-range IPs, fictional
accounts) to find suspicious behavior and rebuild a likely incident timeline.
No real systems or personal data are involved.

## Start here
| File | What it is |
|---|---|
| `incident-report.pdf` | Incident report: summary, findings, timeline, evidence vs assumptions, recommendations |
| `investigation.xlsx` | Investigation workbook: Summary (live formulas), Normalized Log, Detection Rules, Findings, Timeline, Evidence vs Assumptions, Recommendations |
| `investigate.py` | Normalizes the log and runs the 3 detection rules |
| `build_report.py` | Builds the workbook and PDF from the results |
| `data/` | Original supplied CSV |
| `output/` | `normalized_log.csv`, `detections.json` |

## Passing checklist
- [x] **Normalize** timestamps (UTC), IPs (validated, tagged by RFC 5737 range), accounts, actions, and results. System actions (`account_lock`, `rate_limit`) are separated from logins.
- [x] **Detection rules** for brute force (R1), password spraying (R2), and unusual access (R3).
- [x] **Timeline** with evidence kept separate from assumptions.
- [x] **One link**: everything is in this repository.
- [x] **Optional upgrade**: containment and improved-logging recommendations.

## Key findings
1. **Password spraying (High):** `203.0.113.42` tried 4 accounts in 12 s, one attempt each. All failed.
2. **Needs verification (Medium):** `stu-311` was sprayed, then logged in 146 min later from a new IP/device (`192.0.2.99`, ios). The log cannot prove it is malicious.
3. **Likely user mistake (Low):** `stu-117` had 3 failures about 17 s apart, then the lock worked.
4. **Control gap:** only `stu-209` shows a rate-limit block.

## Reproduce
```bash
pip install openpyxl reportlab pypdf
python investigate.py
python build_report.py
```

## Limitations
12 events over about 3 hours: no long-term baseline, thresholds are illustrative, and the log lacks failure reason, MFA result, and user agent, so some conclusions are assumptions (clearly labeled).
