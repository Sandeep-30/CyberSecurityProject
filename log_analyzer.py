#!/usr/bin/env python3
"""
Cybersecurity Log Analyzer

Parses realistic SSH/auth logs and Apache access logs, flags suspicious IPs,
and generates CSV plus optional HTML reports.
"""

import argparse
import csv
import html
import json
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SYSLOG_TS_PATTERN = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
ISO_TS_PATTERN = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
APACHE_TS_PATTERN = re.compile(r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})(?: [+-]\d{4})?\]")
APACHE_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+)? (?P<path>[^"]*?)(?: HTTP/\d(?:\.\d)?)?" '
    r"(?P<status>\d{3}|-) (?P<size>\S+)"
)

SSH_FAILED_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+user=(?P<user>\S+))?"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
]

SUSPICIOUS_KEYWORDS = [
    "admin",
    "attack",
    "cmd.exe",
    "denied",
    "error",
    "forbidden",
    "invalid",
    "nmap",
    "passwd",
    "phpmyadmin",
    "select ",
    "shadow",
    "sqlmap",
    "union ",
    "wp-admin",
    "wp-login",
    "../",
]


@dataclass
class IPStats:
    ip_address: str
    total_requests: int = 0
    failed_logins: int = 0
    apache_errors: int = 0
    unusual_access_count: int = 0
    keyword_hits: Counter = field(default_factory=Counter)
    usernames: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    abuse_confidence_score: str = "not checked"
    abuse_total_reports: str = "not checked"
    country: str = "not checked"
    isp: str = "not checked"


def parse_log_line(line):
    apache_match = APACHE_LOG_PATTERN.search(line)
    if apache_match:
        status = apache_match.group("status")
        return {
            "ip": apache_match.group("ip"),
            "hour": extract_hour(line),
            "log_type": "apache",
            "path": apache_match.group("path"),
            "status": int(status) if status.isdigit() else None,
            "failed_login": False,
            "username": "",
            "keywords": find_keywords(line),
        }

    ip = extract_ssh_ip(line) or extract_ip(line)
    if not ip:
        return None

    failed_login, username = parse_failed_ssh_login(line)
    return {
        "ip": ip,
        "hour": extract_hour(line),
        "log_type": "ssh",
        "path": "",
        "status": None,
        "failed_login": failed_login,
        "username": username,
        "keywords": find_keywords(line),
    }


def extract_ip(line):
    match = IP_PATTERN.search(line)
    return match.group(0) if match else ""


def extract_ssh_ip(line):
    for pattern in SSH_FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group("ip")
    return ""


def parse_failed_ssh_login(line):
    for pattern in SSH_FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            return True, match.groupdict().get("user") or ""
    return False, ""


def extract_hour(line):
    apache_match = APACHE_TS_PATTERN.search(line)
    if apache_match:
        return parse_hour(apache_match.group("ts"), "%d/%b/%Y:%H:%M:%S")

    iso_match = ISO_TS_PATTERN.search(line)
    if iso_match:
        return parse_hour(iso_match.group("ts").replace("T", " "), "%Y-%m-%d %H:%M:%S")

    syslog_match = SYSLOG_TS_PATTERN.search(line)
    if syslog_match:
        current_year = datetime.now().year
        return parse_hour(f"{current_year} {syslog_match.group('ts')}", "%Y %b %d %H:%M:%S")

    return None


def parse_hour(raw_timestamp, fmt):
    try:
        return datetime.strptime(raw_timestamp, fmt).hour
    except ValueError:
        return None


def find_keywords(line):
    text = line.lower()
    return [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in text]


def is_unusual_hour(hour, unusual_start, unusual_end):
    if hour is None or unusual_start == unusual_end:
        return False
    if unusual_start < unusual_end:
        return unusual_start <= hour < unusual_end
    return hour >= unusual_start or hour < unusual_end


def analyze_log(input_file, failed_limit, request_limit, unusual_start, unusual_end):
    stats_by_ip = {}
    total_lines = 0
    parsed_lines = 0

    with open(input_file, "r", encoding="utf-8", errors="ignore") as log_file:
        for line in log_file:
            total_lines += 1
            event = parse_log_line(line)
            if not event:
                continue

            parsed_lines += 1
            ip = event["ip"]
            stats = stats_by_ip.setdefault(ip, IPStats(ip_address=ip))
            stats.total_requests += 1

            if event["failed_login"]:
                stats.failed_logins += 1
            if event["username"]:
                stats.usernames[event["username"]] += 1
            if event["path"]:
                stats.paths[event["path"]] += 1
            if event["status"] and event["status"] >= 400:
                stats.apache_errors += 1
            if is_unusual_hour(event["hour"], unusual_start, unusual_end):
                stats.unusual_access_count += 1

            for keyword in event["keywords"]:
                stats.keyword_hits[keyword] += 1

    rows = build_suspicious_rows(stats_by_ip.values(), failed_limit, request_limit)
    summary = build_summary(total_lines, parsed_lines, stats_by_ip, rows)
    return summary, rows


def build_suspicious_rows(ip_stats, failed_limit, request_limit):
    rows = []

    for stats in ip_stats:
        reasons = []
        if stats.failed_logins >= failed_limit:
            reasons.append("possible brute force")
        if stats.total_requests >= request_limit:
            reasons.append("high request volume")
        if stats.keyword_hits:
            reasons.append("suspicious keywords")
        if stats.apache_errors >= 5:
            reasons.append("many HTTP errors")
        if stats.unusual_access_count:
            reasons.append("unusual access time")

        if not reasons:
            continue

        risk_score = calculate_risk_score(stats)
        rows.append(
            {
                "ip_address": stats.ip_address,
                "total_requests": stats.total_requests,
                "failed_logins": stats.failed_logins,
                "apache_errors": stats.apache_errors,
                "suspicious_keywords": format_counter(stats.keyword_hits),
                "targeted_usernames": format_counter(stats.usernames),
                "top_paths": format_counter(stats.paths, limit=3),
                "unusual_access_count": stats.unusual_access_count,
                "risk_score": risk_score,
                "severity": severity_for_score(risk_score),
                "abuse_confidence_score": stats.abuse_confidence_score,
                "abuse_total_reports": stats.abuse_total_reports,
                "country": stats.country,
                "isp": stats.isp,
                "reasons": "; ".join(reasons),
            }
        )

    rows.sort(key=lambda row: row["risk_score"], reverse=True)
    return rows


def format_counter(counter, limit=None):
    items = counter.most_common(limit)
    return "; ".join(f"{key}:{count}" for key, count in items)


def calculate_risk_score(stats):
    return (
        (stats.failed_logins * 5)
        + (stats.total_requests // 10)
        + (stats.apache_errors * 2)
        + (sum(stats.keyword_hits.values()) * 3)
        + (stats.unusual_access_count * 2)
    )


def severity_for_score(score):
    if score >= 75:
        return "Critical"
    if score >= 35:
        return "High"
    if score >= 15:
        return "Medium"
    return "Low"


def build_summary(total_lines, parsed_lines, stats_by_ip, rows):
    brute_force_count = sum(1 for row in rows if row["failed_logins"] > 0 and "brute force" in row["reasons"])
    top_threat = rows[0] if rows else None
    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "total_ips": len(stats_by_ip),
        "suspicious_ips": len(rows),
        "brute_force_attempts": brute_force_count,
        "top_threat_ip": top_threat["ip_address"] if top_threat else "None",
        "top_threat_attempts": top_threat["failed_logins"] if top_threat else 0,
    }


def enrich_rows(rows, abuse_api_key, include_geo):
    for row in rows:
        if abuse_api_key:
            abuse_result = lookup_abuseipdb(row["ip_address"], abuse_api_key)
            row["abuse_confidence_score"] = abuse_result.get("abuseConfidenceScore", "error")
            row["abuse_total_reports"] = abuse_result.get("totalReports", "error")

        if include_geo:
            geo_result = lookup_geo(row["ip_address"])
            row["country"] = geo_result.get("country", "error")
            row["isp"] = geo_result.get("isp", "error")


def lookup_abuseipdb(ip_address, api_key):
    params = urlencode({"ipAddress": ip_address, "maxAgeInDays": 90})
    request = Request(
        f"https://api.abuseipdb.com/api/v2/check?{params}",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return payload.get("data", {})
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return {}


def lookup_geo(ip_address):
    fields = "status,country,isp,query"
    url = f"http://ip-api.com/json/{ip_address}?fields={fields}"
    try:
        with urlopen(url, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
            if payload.get("status") == "success":
                return payload
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        pass
    return {}


def write_csv(output_file, rows):
    fieldnames = [
        "ip_address",
        "severity",
        "risk_score",
        "total_requests",
        "failed_logins",
        "apache_errors",
        "suspicious_keywords",
        "targeted_usernames",
        "top_paths",
        "unusual_access_count",
        "abuse_confidence_score",
        "abuse_total_reports",
        "country",
        "isp",
        "reasons",
    ]

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_html_report(output_file, summary, rows):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    body_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(row['ip_address'])}</td>"
        f"<td><span class='badge {row['severity'].lower()}'>{html.escape(row['severity'])}</span></td>"
        f"<td>{row['risk_score']}</td>"
        f"<td>{row['failed_logins']}</td>"
        f"<td>{row['total_requests']}</td>"
        f"<td>{html.escape(row['country'])}</td>"
        f"<td>{html.escape(str(row['abuse_confidence_score']))}</td>"
        f"<td>{html.escape(row['reasons'])}</td>"
        f"<td>{html.escape(row['suspicious_keywords'])}</td>"
        "</tr>"
        for row in rows
    )
    if not body_rows:
        body_rows = "<tr><td colspan='9'>No suspicious IPs were flagged.</td></tr>"

    content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cybersecurity Log Analysis Report</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; background: #f6f8fb; color: #172033; }}
    header {{ background: #172033; color: white; padding: 28px 36px; }}
    main {{ padding: 28px 36px; }}
    h1 {{ margin: 0; font-size: 28px; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px; }}
    .metric {{ background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 16px; }}
    .metric strong {{ display: block; font-size: 26px; margin-top: 8px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9e1ec; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #e5ebf3; text-align: left; font-size: 14px; vertical-align: top; }}
    th {{ background: #eef3f8; }}
    .badge {{ border-radius: 999px; color: white; display: inline-block; font-size: 12px; font-weight: bold; padding: 4px 9px; }}
    .critical {{ background: #8f1d1d; }}
    .high {{ background: #c2410c; }}
    .medium {{ background: #b7791f; }}
    .low {{ background: #2f855a; }}
  </style>
</head>
<body>
  <header>
    <h1>Cybersecurity Log Analysis Report</h1>
  </header>
  <main>
    <section class="summary">
      <div class="metric">Total IPs Analyzed<strong>{summary['total_ips']}</strong></div>
      <div class="metric">Suspicious IPs Flagged<strong>{summary['suspicious_ips']}</strong></div>
      <div class="metric">Brute Force Attempts<strong>{summary['brute_force_attempts']}</strong></div>
      <div class="metric">Top Threat<strong>{html.escape(summary['top_threat_ip'])}</strong></div>
    </section>
    <table>
      <thead>
        <tr>
          <th>IP Address</th>
          <th>Severity</th>
          <th>Risk</th>
          <th>Failed Logins</th>
          <th>Requests</th>
          <th>Country</th>
          <th>AbuseIPDB</th>
          <th>Reasons</th>
          <th>Keywords</th>
        </tr>
      </thead>
      <tbody>{body_rows}</tbody>
    </table>
  </main>
</body>
</html>
"""
    output_file.write_text(content, encoding="utf-8")


def print_terminal_report(summary):
    print("=" * 48)
    print("  CYBERSECURITY LOG ANALYSIS REPORT")
    print("=" * 48)
    print(f"  Total Lines Read:        {summary['total_lines']:>6}")
    print(f"  Parsed Log Events:       {summary['parsed_lines']:>6}")
    print(f"  Total IPs Analyzed:      {summary['total_ips']:>6}")
    print(f"  Suspicious IPs Flagged:  {summary['suspicious_ips']:>6}")
    print(f"  Brute Force Attempts:    {summary['brute_force_attempts']:>6}")
    print(f"  Top Threat:              {summary['top_threat_ip']} ({summary['top_threat_attempts']} attempts)")
    print("=" * 48)


def watch_log(args):
    input_file = Path(args.input_file)
    print(f"Watching {input_file} for new log entries. Press Ctrl+C to stop.")
    with open(input_file, "r", encoding="utf-8", errors="ignore") as log_file:
        log_file.seek(0, os.SEEK_END)
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(args.interval)
                continue

            event = parse_log_line(line)
            if not event:
                continue

            reasons = []
            if event["failed_login"]:
                reasons.append("failed SSH login")
            if event["keywords"]:
                reasons.append("keyword: " + ", ".join(event["keywords"]))
            if event["status"] and event["status"] >= 400:
                reasons.append(f"HTTP {event['status']}")
            if is_unusual_hour(event["hour"], args.unusual_start, args.unusual_end):
                reasons.append("unusual access time")

            if reasons:
                print(f"[ALERT] {event['ip']} - {'; '.join(reasons)}")


def parse_args():
    parser = argparse.ArgumentParser(description="Detect suspicious activity in SSH and Apache logs.")
    parser.add_argument("input_file", help="Path to the log file to analyze")
    parser.add_argument("-o", "--output", default="reports/suspicious_activity.csv", help="CSV report path")
    parser.add_argument("--html-report", default="reports/suspicious_activity.html", help="HTML report path")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--failed-limit", type=int, default=5, help="Failed-login threshold per IP")
    parser.add_argument("--request-limit", type=int, default=20, help="Request threshold per IP")
    parser.add_argument("--unusual-start", type=int, default=0, help="Start hour for unusual access window")
    parser.add_argument("--unusual-end", type=int, default=5, help="End hour for unusual access window")
    parser.add_argument("--abuseipdb-key", default=os.getenv("ABUSEIPDB_API_KEY"), help="AbuseIPDB API key")
    parser.add_argument("--geo", action="store_true", help="Add country and ISP lookup using ip-api.com")
    parser.add_argument("--watch", action="store_true", help="Tail the file and print real-time alerts")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval for --watch mode")
    return parser.parse_args()


def main():
    args = parse_args()
    input_file = Path(args.input_file)
    output_file = Path(args.output)
    html_file = Path(args.html_report)

    if not input_file.exists():
        raise SystemExit(f"Input file not found: {input_file}")

    if args.watch:
        watch_log(args)
        return

    summary, suspicious_rows = analyze_log(
        input_file,
        args.failed_limit,
        args.request_limit,
        args.unusual_start,
        args.unusual_end,
    )

    enrich_rows(suspicious_rows, args.abuseipdb_key, args.geo)
    write_csv(output_file, suspicious_rows)
    if not args.no_html:
        write_html_report(html_file, summary, suspicious_rows)

    print_terminal_report(summary)
    print(f"CSV report saved to: {output_file}")
    if not args.no_html:
        print(f"HTML report saved to: {html_file}")


if __name__ == "__main__":
    main()
