"""Security Log Investigation - step 3/4: build the spreadsheet and the PDF report.
Run AFTER investigate.py:   python build_report.py
Needs: openpyxl, reportlab
"""
import csv
import json
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).parent
OUT = ROOT / "output"
rows = list(csv.DictReader(open(OUT / "normalized_log.csv")))
det = json.load(open(OUT / "detections.json"))

# ------------------------------------------------------------ content
FINDINGS = [
    dict(id="F1", rule="R2 Password spraying", sev="High", conf="High",
         subject="203.0.113.42 -> stu-209, stu-311, stu-415, stu-502",
         window="09:21:10 - 09:21:22 (12 s)", rows="7-10",
         call="Suspicious",
         why="One IP tried four different accounts in 12 seconds, one attempt each, from an "
             "'unknown' device. One try per account stays under per-account lockout limits, "
             "which is the typical spraying pattern."),
    dict(id="F2", rule="R3 Unusual access after targeting", sev="Medium", conf="Low",
         subject="stu-311 from 192.0.2.99 (ios)",
         window="Targeted 09:21:13; success 11:47:09 (146 min later)", rows="8, 13",
         call="Needs verification",
         why="stu-311 was sprayed, then logged in successfully from an IP and device not seen "
             "for this account elsewhere in the log. But the spray attempt FAILED and came "
             "from a different IP, so the log alone does not link the two."),
    dict(id="F3", rule="R1 Brute force (threshold hit)", sev="Low", conf="Medium",
         subject="198.51.100.27 -> stu-117",
         window="09:03:44 - 09:04:18 (34 s), lock at 09:05:03", rows="3-6",
         call="Likely user mistake",
         why="Three failures about 17 s apart, one account, one IP, one consistent device "
             "('windows'), no other accounts touched, and no attempts after the lock. This "
             "looks like a person retyping a forgotten password, though the log has no "
             "failure reason to prove it. The lock control worked."),
    dict(id="F4", rule="Control gap (observation)", sev="Medium", conf="Medium",
         subject="rate_limit event covers stu-209 only",
         window="09:22:01", rows="11",
         call="Control weakness",
         why="Only one rate_limit/blocked event exists, for stu-209, 39 s after the last "
             "spray attempt. Nothing in the log shows the IP itself being blocked or the "
             "other three accounts being protected."),
    dict(id="F5", rule="Baseline (normal)", sev="Info", conf="High",
         subject="stu-104 from 192.0.2.18 (android)",
         window="09:00:12 and 10:15:32", rows="2, 12",
         call="Benign",
         why="Password login then a refresh token about 75 min later, same IP and device. "
             "Consistent, healthy pattern."),
]

TIMELINE = [  # time, what the log shows (evidence), interpretation (assumption), rows
    ("09:00:12", "stu-104 password_login success, 192.0.2.18, android", "Normal start-of-day login (baseline).", "2"),
    ("09:03:44", "stu-117 password_login failure, 198.51.100.27, windows", "Possibly a mistyped password.", "3"),
    ("09:04:01", "stu-117 password_login failure (same IP/device)", "Same as above.", "4"),
    ("09:04:18", "stu-117 password_login failure (3rd in 34 s)", "Crosses the R1 threshold.", "5"),
    ("09:05:03", "account_lock on stu-117 by server (lock applied)", "Control worked; no further stu-117 events logged.", "6"),
    ("09:21:10", "stu-209 failure from 203.0.113.42, device unknown", "Start of spray run.", "7"),
    ("09:21:13", "stu-311 failure from 203.0.113.42", "Second account in 3 s.", "8"),
    ("09:21:17", "stu-415 failure from 203.0.113.42", "Third account.", "9"),
    ("09:21:22", "stu-502 failure from 203.0.113.42", "Fourth account; run likely automated.", "10"),
    ("09:22:01", "rate_limit blocked on stu-209 by server", "Scope of the block is unknown (account or IP).", "11"),
    ("10:15:32", "stu-104 refresh_token success, 192.0.2.18, android", "Normal session continuation.", "12"),
    ("11:47:09", "stu-311 password_login success, 192.0.2.99, ios", "Could be the real student on a new phone OR an attacker with a credential from elsewhere.", "13"),
]

EVIDENCE = [  # claim, evidence (in log), assumption (not proven), how to verify
    ("One IP attacked four accounts", "Rows 7-10: 203.0.113.42, 4 users, 12 s.", "That it was a single actor / script.", "Check web-server request logs for user agent and request IDs."),
    ("Spray did not succeed", "All four attempts are 'failure'; no success from 203.0.113.42.", "That there were no attempts outside this log.", "Review the full log window before and after 09:21."),
    ("stu-117 is probably a user mistake", "3 failures at human pace, same device, then lock.", "That a person typed them.", "Ask the student; check failure reason (bad password) and prior logins."),
    ("stu-311 login may be compromised", "Success from 192.0.2.99/ios 146 min after being targeted.", "That the login is linked to the spray, or that it is not the real user.", "Contact the student out of band; check MFA result, session activity and device history."),
    ("Rate limit was partial", "Only one rate_limit event, for stu-209.", "That the other accounts were not limited by some other control.", "Check rate-limit configuration and whether it is per-IP or per-account."),
    ("All activity is fictional / safe", "All IPs fall in RFC 5737 documentation ranges.", "None - this is a synthetic lab dataset.", "n/a"),
]

RECS_CONTAIN = [
    "Verify stu-311 with the student out of band. If not confirmed, force a password reset and revoke active sessions and refresh tokens.",
    "Block or challenge 203.0.113.42 at the edge (lab note: documentation range, fictional) and add it to a watchlist.",
    "Watch stu-209, stu-415 and stu-502 for successful logins from new IPs or devices for the next 24-72 hours.",
    "Follow up with stu-117 so the locked account is recovered by identity-checked reset, not by bypassing the lock.",
    "Require MFA for all student accounts, or at least when a login comes from a new IP/device.",
]
RECS_LOG = [
    "Add a failure_reason field (bad password, unknown user, locked) so user mistakes can be told apart from attacks.",
    "Log user agent, auth method, MFA result, session ID and a request ID on every event.",
    "Record the scope and duration of rate_limit and account_lock actions (per-IP or per-account, minutes).",
    "Add geo/ASN enrichment and a 'first seen' flag per account for new IP/device combinations.",
    "Alert on: 3+ accounts failing from one IP in 60 s; 3+ failures for one account in 2 min; success from a new IP shortly after the account was targeted.",
    "Ship logs to central storage with synchronized clocks and protect them from tampering.",
]
RULES = [
    ("R1", "Brute force", "3+ failed password_login for the SAME account from the SAME IP within 120 s.",
     "Catches repeated guessing at one account.", "Users who forgot their password (see F3)."),
    ("R2", "Password spraying", "3+ DIFFERENT accounts failing from the SAME IP within 60 s.",
     "Catches one-guess-per-account attacks that avoid per-account lockouts.", "Shared campus/NAT IPs at class start."),
    ("R3", "Unusual access after targeting", "Successful login for an account that was targeted by a flagged spray IP in the last 24 h, from a different IP and a device not previously seen for that account.",
     "Surfaces possible account takeover following a spray.", "Student legitimately logging in on a new phone."),
]

# ================================================================== XLSX
wb = Workbook()
F = "Arial"
HDR = PatternFill("solid", fgColor="1F3864")
thin = Side(style="thin", color="BBBBBB")
BOX = Border(left=thin, right=thin, top=thin, bottom=thin)


def style_header(ws, ncols, row=1):
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.font = Font(name=F, bold=True, color="FFFFFF", size=10)
        cell.fill = HDR
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        cell.border = BOX


def style_body(ws, r0, r1, ncols):
    for r in range(r0, r1 + 1):
        for c in range(1, ncols + 1):
            cell = ws.cell(row=r, column=c)
            cell.font = cell.font.copy(name=F, size=10) if cell.font and cell.font.bold else Font(name=F, size=10)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = BOX


def widths(ws, ws_widths):
    for i, w in enumerate(ws_widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ---- Summary (formulas over Normalized Log)
s = wb.active
s.title = "Summary"
N = len(rows)
last = N + 1
L = "'Normalized Log'!"
rng = lambda col: f"{L}${col}$2:${col}${last}"
s["A1"] = "Security Log Investigation - Summary"; s["A1"].font = Font(name=F, bold=True, size=14)
s["A2"] = "All numbers below are formulas over the 'Normalized Log' sheet. Synthetic data; documentation-range IPs."
s["A2"].font = Font(name=F, italic=True, size=9)
s["A4"], s["B4"] = "Metric", "Value"
metrics = [
    ("Total events", f"=COUNTA({rng('A')})"),
    ("Password login failures", f'=COUNTIFS({rng("F")},"password_login",{rng("H")},"failure")'),
    ("Password login successes", f'=COUNTIFS({rng("F")},"password_login",{rng("H")},"success")'),
    ("Password login failure rate", "=IFERROR(B6/(B6+B7),0)"),
    ("System control events (lock / rate limit)", f'=COUNTIF({rng("G")},"system_control")'),
    ("Distinct accounts", f"=SUMPRODUCT(1/COUNTIF({rng('C')},{rng('C')}))"),
    ("Distinct source IPs", f"=SUMPRODUCT(1/COUNTIF({rng('D')},{rng('D')}))"),
]
for i, (k, v) in enumerate(metrics, start=5):
    s.cell(row=i, column=1, value=k); s.cell(row=i, column=2, value=v)
s["B8"].number_format = "0.0%"
style_header(s, 2, 4); style_body(s, 5, 4 + len(metrics), 2)

r0 = 14
s.cell(row=r0 - 1, column=1, value="Per-IP view (this is what separates spraying from one user's mistakes)").font = Font(name=F, bold=True, size=11)
for c, h in enumerate(["Source IP", "Login failures", "Distinct accounts failed", "Login successes", "Reading"], start=1):
    s.cell(row=r0, column=c, value=h)
style_header(s, 5, r0)
ips = [("192.0.2.18", "Normal user"), ("198.51.100.27", "One account retried (R1 hit)"),
       ("203.0.113.42", "Many accounts, 1 try each (spray, R2)"), ("192.0.2.99", "Single success after targeting (R3)")]
for i, (ip, note) in enumerate(ips, start=r0 + 1):
    s.cell(row=i, column=1, value=ip)
    s.cell(row=i, column=2, value=f'=COUNTIFS({rng("D")},A{i},{rng("F")},"password_login",{rng("H")},"failure")')
    s.cell(row=i, column=3, value=(
        f'=SUMPRODUCT(({rng("D")}=A{i})*({rng("F")}="password_login")*({rng("H")}="failure")'
        f'/COUNTIFS({rng("D")},{rng("D")},{rng("C")},{rng("C")},{rng("F")},{rng("F")},{rng("H")},{rng("H")}))'))
    s.cell(row=i, column=4, value=f'=COUNTIFS({rng("D")},A{i},{rng("F")},"password_login",{rng("H")},"success")')
    s.cell(row=i, column=5, value=note)
style_body(s, r0 + 1, r0 + len(ips), 5)
nr = r0 + len(ips) + 2
s.cell(row=nr, column=1, value="Note: 'account_lock / success' is the SYSTEM locking an account, not a login success, so it is excluded from login counts.").font = Font(name=F, italic=True, size=9)
widths(s, [44, 16, 24, 16, 40])

# ---- Normalized Log
ws = wb.create_sheet("Normalized Log")
cols = ["row", "timestamp_utc", "user_id", "source_ip", "ip_range", "event", "event_category", "result", "login_outcome", "device"]
ws.append(["Source row", "Timestamp (UTC)", "Account", "Source IP", "IP range (RFC 5737)", "Event", "Category", "Result", "Login outcome", "Device"])
for r in rows:
    ws.append([int(r["row"]), datetime.strptime(r["timestamp_utc"], "%Y-%m-%dT%H:%M:%SZ"),
               r["user_id"], r["source_ip"], r["ip_range"], r["event"], r["event_category"],
               r["result"], r["login_outcome"], r["device"]])
style_header(ws, 10); style_body(ws, 2, last, 10)
for r in range(2, last + 1):
    ws.cell(row=r, column=2).number_format = "yyyy-mm-dd hh:mm:ss"
widths(ws, [11, 20, 11, 15, 18, 15, 16, 10, 14, 10]); ws.freeze_panes = "A2"

# ---- Detection Rules
dr = wb.create_sheet("Detection Rules")
dr.append(["ID", "Rule", "Logic (thresholds)", "What it catches", "Known false positives", "Hits in this log"])
hits = {"R1": len(det["R1"]), "R2": len(det["R2"]), "R3": len(det["R3"])}
for rid, name, logic, catch, fp in RULES:
    dr.append([rid, name, logic, catch, fp, hits[rid]])
style_header(dr, 6); style_body(dr, 2, 1 + len(RULES), 6)
widths(dr, [6, 26, 52, 40, 34, 14])
dr.cell(row=len(RULES) + 3, column=1, value="Thresholds are starting points for a small lab dataset; tune them against real baseline traffic.").font = Font(name=F, italic=True, size=9)

# ---- Findings
fs = wb.create_sheet("Findings")
fs.append(["ID", "Rule", "Subject", "Time window (UTC, 2026-08-01)", "Source rows", "Severity", "Confidence", "Assessment", "Reasoning"])
for f in FINDINGS:
    fs.append([f["id"], f["rule"], f["subject"], f["window"], f["rows"], f["sev"], f["conf"], f["call"], f["why"]])
style_header(fs, 9); style_body(fs, 2, 1 + len(FINDINGS), 9)
widths(fs, [6, 28, 30, 30, 11, 10, 11, 20, 70])
colors = {"High": "F8CBAD", "Medium": "FFE699", "Low": "C6E0B4", "Info": "DDEBF7"}
for r in range(2, 2 + len(FINDINGS)):
    fs.cell(row=r, column=6).fill = PatternFill("solid", fgColor=colors[fs.cell(row=r, column=6).value])
fs.freeze_panes = "A2"

# ---- Timeline
tl = wb.create_sheet("Timeline")
tl.append(["Time (UTC)", "What the log shows (EVIDENCE)", "Interpretation (ASSUMPTION)", "Source row"])
for t_ in TIMELINE:
    tl.append(list(t_))
style_header(tl, 4); style_body(tl, 2, 1 + len(TIMELINE), 4)
widths(tl, [12, 58, 60, 11]); tl.freeze_panes = "A2"
tl.cell(row=len(TIMELINE) + 3, column=1, value="Date for all rows: 2026-08-01 (synthetic).").font = Font(name=F, italic=True, size=9)

# ---- Evidence vs Assumptions
ev = wb.create_sheet("Evidence vs Assumptions")
ev.append(["Claim", "Evidence in the log", "Assumption (not proven)", "How to verify"])
for e in EVIDENCE:
    ev.append(list(e))
style_header(ev, 4); style_body(ev, 2, 1 + len(EVIDENCE), 4)
widths(ev, [34, 50, 46, 56])

# ---- Recommendations
rc = wb.create_sheet("Recommendations")
rc.append(["Type", "Recommendation"])
for x in RECS_CONTAIN:
    rc.append(["Containment", x])
for x in RECS_LOG:
    rc.append(["Logging / detection", x])
style_header(rc, 2); style_body(rc, 2, 1 + len(RECS_CONTAIN) + len(RECS_LOG), 2)
widths(rc, [22, 120])

wb.save(ROOT / "investigation.xlsx")

# ================================================================== PDF
from reportlab.lib import colors as rl
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (ListFlowable, ListItem, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

ss = getSampleStyleSheet()
body = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica", fontSize=9.5, leading=13)
small = ParagraphStyle("s", parent=body, fontSize=8, leading=10.5)
smallb = ParagraphStyle("sb", parent=small, fontName="Helvetica-Bold", textColor=rl.white)
h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=18, alignment=TA_LEFT, spaceAfter=4)
h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=12, textColor=rl.HexColor("#1F3864"), spaceBefore=10, spaceAfter=4)
NAVY = rl.HexColor("#1F3864")


def table(header, data, widths_mm):
    data_p = [[Paragraph(h, smallb) for h in header]] + [[Paragraph(str(c), small) for c in r] for r in data]
    t = Table(data_p, colWidths=[w * mm for w in widths_mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.4, rl.HexColor("#BBBBBB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl.white, rl.HexColor("#F5F7FB")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def bullets(items):
    return ListFlowable([ListItem(Paragraph(i, body), leftIndent=12) for i in items],
                        bulletType="bullet", start="-", leftIndent=12)


b = det["baseline"]
story = [
    Paragraph("Incident Report: Authentication Log Investigation", h1),
    Paragraph("Cyber Security Task 4 | Synthetic log, documentation-range IPs, fictional accounts | Log date 2026-08-01 (UTC)", small),
    Spacer(1, 6),
    Paragraph("1. Executive summary", h2),
    Paragraph(
        f"The log holds {b['total_events']} events across {b['distinct_accounts']} accounts and {b['distinct_ips']} IP addresses. "
        f"Of {b['password_logins']} password logins, {b['login_failures']} failed and {b['login_successes']} succeeded. "
        "One clear attack pattern was found: a <b>password-spraying run</b> from 203.0.113.42 against four accounts in 12 seconds (High). "
        "The spray itself did not succeed. One account it touched, stu-311, later had a successful login from a new IP and device; "
        "the log cannot show whether that is the real student or an attacker, so it is flagged <b>needs verification</b> (Medium severity, Low confidence). "
        "A cluster of three failures on stu-117 is most likely an ordinary user mistake, and the lockout worked. "
        "The rate limit only covered stu-209, which is a control gap.", body),
    Paragraph("2. Scope and method", h2),
    Paragraph("Data: the supplied synthetic authentication log (12 rows). All IPs were confirmed to be RFC 5737 documentation ranges, so nothing here refers to real systems. "
              "Work was done offline on the CSV only; no external systems were scanned.", body),
    Spacer(1, 3),
    Paragraph("<b>Step 1 - Normalization.</b> Timestamps parsed and converted to UTC; IPs validated and tagged by documentation range; account IDs, events, results and devices trimmed and lower-cased; "
              "events split into <i>authentication</i> vs <i>system_control</i>. Important detail: 'account_lock / success' means the system locked an account, so it is not counted as a login success.", body),
    Spacer(1, 3),
    Paragraph("<b>Step 2 - Baseline.</b> stu-104 logs in from 192.0.2.18 (android) and refreshes a token 75 minutes later from the same IP and device. That is the normal pattern used for comparison.", body),
    Paragraph("3. Detection rules", h2),
    table(["ID", "Rule", "Logic", "Possible false positive", "Hits"],
          [[r[0], r[1], r[2], r[4], hits[r[0]]] for r in RULES], [10, 30, 80, 45, 12]),
    Paragraph("4. Findings", h2),
    table(["ID", "Subject", "Assessment", "Sev / Conf", "Reasoning"],
          [[f["id"], f["subject"] + "<br/>" + f["window"], f["call"], f"{f['sev']} / {f['conf']}", f["why"]] for f in FINDINGS],
          [8, 42, 24, 20, 86]),
    Paragraph("5. Timeline (2026-08-01, UTC) - evidence kept separate from assumptions", h2),
    table(["Time", "Evidence (what the log shows)", "Assumption / interpretation", "Row"],
          list(TIMELINE), [16, 72, 80, 10]),
    Paragraph("6. Evidence vs assumptions", h2),
    table(["Claim", "Evidence", "Assumption (not proven)", "How to verify"], EVIDENCE, [32, 50, 46, 48]),
    Paragraph("7. Recommended containment", h2),
    bullets(RECS_CONTAIN),
    Paragraph("8. Recommended logging and detection improvements", h2),
    bullets(RECS_LOG),
    Paragraph("9. Limitations", h2),
    Paragraph("The sample is tiny (12 events, about 3 hours), so there is no long-term baseline per account and thresholds are illustrative. "
              "The log has no failure reason, user agent, MFA result or rate-limit scope, so several conclusions stay assumptions. "
              "Severity and confidence are analyst judgments and should be revisited if more data becomes available.", body),
]


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(rl.grey)
    canvas.drawString(15 * mm, 8 * mm, "Synthetic data - no real systems or personal data - Task 4 Security Log Investigation")
    canvas.drawRightString(195 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


doc = SimpleDocTemplate(str(ROOT / "incident-report.pdf"), pagesize=A4,
                        leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
                        title="Incident Report - Authentication Log Investigation", author="Security Log Investigation")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("built investigation.xlsx and incident-report.pdf")
