"""Security Log Investigation - step 1 (normalize) and step 2 (detect).

Input : data/authentication-log-sample.csv  (synthetic, documentation-range IPs)
Output: output/normalized_log.csv, output/detections.json

Run: python investigate.py
"""
import csv
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "data" / "authentication-log-sample.csv"
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

# ----------------------------------------------------------- thresholds
BRUTE_MIN_FAILS, BRUTE_WINDOW_S = 3, 120      # same account + same IP
SPRAY_MIN_ACCOUNTS, SPRAY_WINDOW_S = 3, 60    # same IP, different accounts
TARGETED_LOOKBACK_H = 24                      # unusual-access context window

DOC_RANGES = {                                 # RFC 5737 documentation ranges
    "192.0.2.0/24": "TEST-NET-1",
    "198.51.100.0/24": "TEST-NET-2",
    "203.0.113.0/24": "TEST-NET-3",
}
AUTH_EVENTS = {"password_login", "refresh_token"}
CONTROL_EVENTS = {"account_lock", "rate_limit"}   # actions taken BY the system


# ------------------------------------------------------- 1. normalization
def doc_range(ip):
    addr = ipaddress.ip_address(ip)
    for net, name in DOC_RANGES.items():
        if addr in ipaddress.ip_network(net):
            return name
    return "NOT-DOCUMENTATION"


def normalize(raw, line_no):
    ts = datetime.fromisoformat(raw["timestamp"].strip().replace("Z", "+00:00"))
    ts = ts.astimezone(timezone.utc)                      # everything in UTC
    ip = str(ipaddress.ip_address(raw["source_ip"].strip()))  # validates + canonical
    event = raw["event"].strip().lower()
    result = raw["result"].strip().lower()
    return {
        "row": line_no,
        "timestamp_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_id": raw["user_id"].strip().lower(),
        "source_ip": ip,
        "ip_range": doc_range(ip),
        "event": event,
        "event_category": "authentication" if event in AUTH_EVENTS else "system_control",
        "result": result,
        # 'account_lock/success' means the lock WORKED, not that someone logged in
        "login_outcome": result if event in AUTH_EVENTS else "n/a",
        "device": raw["device"].strip().lower(),
    }


def load():
    with open(SRC, newline="") as f:
        rows = [normalize(r, i) for i, r in enumerate(csv.DictReader(f), start=2)]
    return sorted(rows, key=lambda r: r["timestamp_utc"])


def t(row):
    return datetime.strptime(row["timestamp_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# --------------------------------------------------------- 2. detections
def detect_bruteforce(rows):
    groups = defaultdict(list)
    for r in rows:
        if r["event"] == "password_login" and r["result"] == "failure":
            groups[(r["user_id"], r["source_ip"])].append(r)
    hits = []
    for (user, ip), evs in groups.items():
        for i in range(len(evs)):
            win = [e for e in evs[i:] if (t(e) - t(evs[i])).total_seconds() <= BRUTE_WINDOW_S]
            if len(win) >= BRUTE_MIN_FAILS:
                hits.append({"rule": "R1 Brute force", "user": user, "ip": ip,
                             "count": len(win), "start": win[0]["timestamp_utc"],
                             "end": win[-1]["timestamp_utc"], "rows": [e["row"] for e in win]})
                break
    return hits


def detect_spray(rows):
    by_ip = defaultdict(list)
    for r in rows:
        if r["event"] == "password_login" and r["result"] == "failure":
            by_ip[r["source_ip"]].append(r)
    hits = []
    for ip, evs in by_ip.items():
        for i in range(len(evs)):
            win = [e for e in evs[i:] if (t(e) - t(evs[i])).total_seconds() <= SPRAY_WINDOW_S]
            users = sorted({e["user_id"] for e in win})
            if len(users) >= SPRAY_MIN_ACCOUNTS:
                hits.append({"rule": "R2 Password spraying", "ip": ip, "accounts": users,
                             "count": len(win), "start": win[0]["timestamp_utc"],
                             "end": win[-1]["timestamp_utc"], "rows": [e["row"] for e in win]})
                break
    return hits


def detect_unusual_access(rows, spray_hits):
    spray_ips = {h["ip"]: h for h in spray_hits}
    hits = []
    for r in rows:
        if not (r["event"] == "password_login" and r["result"] == "success"):
            continue
        prior = [p for p in rows
                 if p["user_id"] == r["user_id"] and p["source_ip"] in spray_ips
                 and p["result"] == "failure" and t(p) < t(r)
                 and t(r) - t(p) <= timedelta(hours=TARGETED_LOOKBACK_H)]
        seen_before = any(p["user_id"] == r["user_id"] and p["source_ip"] == r["source_ip"]
                          and p["device"] == r["device"] and t(p) < t(r) for p in rows)
        if prior and r["source_ip"] not in spray_ips and not seen_before:
            gap = t(r) - t(prior[-1])
            hits.append({"rule": "R3 Unusual access after targeting", "user": r["user_id"],
                         "ip": r["source_ip"], "device": r["device"],
                         "success_at": r["timestamp_utc"],
                         "targeted_by": prior[-1]["source_ip"],
                         "targeted_at": prior[-1]["timestamp_utc"],
                         "gap_minutes": round(gap.total_seconds() / 60),
                         "rows": [prior[-1]["row"], r["row"]]})
    return hits


def baseline(rows):
    auth = [r for r in rows if r["event_category"] == "authentication"]
    logins = [r for r in auth if r["event"] == "password_login"]
    return {
        "total_events": len(rows),
        "first_event": rows[0]["timestamp_utc"], "last_event": rows[-1]["timestamp_utc"],
        "distinct_accounts": len({r["user_id"] for r in rows}),
        "distinct_ips": len({r["source_ip"] for r in rows}),
        "password_logins": len(logins),
        "login_failures": sum(r["result"] == "failure" for r in logins),
        "login_successes": sum(r["result"] == "success" for r in logins),
        "control_events": sum(r["event_category"] == "system_control" for r in rows),
        "all_ips_documentation_range": all(r["ip_range"] != "NOT-DOCUMENTATION" for r in rows),
    }


def main():
    rows = load()
    with open(OUT / "normalized_log.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    brute = detect_bruteforce(rows)
    spray = detect_spray(rows)
    unusual = detect_unusual_access(rows, spray)
    result = {"baseline": baseline(rows), "R1": brute, "R2": spray, "R3": unusual}
    (OUT / "detections.json").write_text(json.dumps(result, indent=2))

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
