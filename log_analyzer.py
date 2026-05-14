#!/usr/bin/env python3
"""
Cybersecurity Log Analyzer

Reads a log file, detects suspicious activity, and writes CSV reports.
The parser supports common web/auth log patterns and is intentionally
beginner-friendly so you can explain it in an interview.
"""

import argparse
import csv
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIMESTAMP_PATTERNS = [
    re.compile(r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})"),
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
]

SUSPICIOUS_KEYWORDS = [
    "failed",
    "failure",
    "invalid",
    "unauthorized",
    "forbidden",
    "denied",
    "error",
    "attack",
    "sqlmap",
    "nmap",
    "admin",
    "wp-login",
    "passwd",
    "shadow",
    "../",
    "select ",
    "union ",
    "drop ",
]


def extract_ip(line):
    match = IP_PATTERN.search(line)
    return match.group(0) if match else "UNKNOWN"


def extract_hour(line):
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue

        raw_timestamp = match.group("ts")
        for fmt in ("%d/%b/%Y:%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw_timestamp, fmt).hour
            except ValueError:
                pass

    return None


def has_failed_login(line):
    text = line.lower()
    failed_words = ("failed", "failure", "invalid password", "authentication failure")
    login_words = ("login", "logon", "ssh", "auth", "password", "user")
    return any(word in text for word in failed_words) and any(word in text for word in login_words)


def find_keywords(line):
    text = line.lower()
    return [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in text]


def analyze_log(input_file, failed_limit, request_limit, unusual_start, unusual_end):
    failed_logins = Counter()
    total_requests = Counter()
    keyword_hits = defaultdict(Counter)
    unusual_access = Counter()
    total_lines = 0

    with open(input_file, "r", encoding="utf-8", errors="ignore") as log_file:
        for line in log_file:
            total_lines += 1
            ip = extract_ip(line)
            hour = extract_hour(line)

            total_requests[ip] += 1

            if has_failed_login(line):
                failed_logins[ip] += 1

            for keyword in find_keywords(line):
                keyword_hits[ip][keyword] += 1

            if hour is not None and is_unusual_hour(hour, unusual_start, unusual_end):
                unusual_access[ip] += 1

    suspicious_ips = []
    all_ips = set(total_requests) | set(failed_logins) | set(keyword_hits) | set(unusual_access)

    for ip in sorted(all_ips):
        reasons = []

        if failed_logins[ip] >= failed_limit:
            reasons.append("possible brute force")
        if total_requests[ip] >= request_limit:
            reasons.append("high request volume")
        if keyword_hits[ip]:
            reasons.append("suspicious keywords")
        if unusual_access[ip]:
            reasons.append("unusual access time")

        if reasons:
            suspicious_ips.append(
                {
                    "ip_address": ip,
                    "total_requests": total_requests[ip],
                    "failed_logins": failed_logins[ip],
                    "suspicious_keywords": "; ".join(
                        f"{keyword}:{count}" for keyword, count in keyword_hits[ip].items()
                    ),
                    "unusual_access_count": unusual_access[ip],
                    "risk_score": calculate_risk_score(
                        failed_logins[ip], total_requests[ip], keyword_hits[ip], unusual_access[ip]
                    ),
                    "reasons": "; ".join(reasons),
                }
            )

    suspicious_ips.sort(key=lambda row: row["risk_score"], reverse=True)
    return total_lines, suspicious_ips


def is_unusual_hour(hour, unusual_start, unusual_end):
    if unusual_start == unusual_end:
        return False
    if unusual_start < unusual_end:
        return unusual_start <= hour < unusual_end
    return hour >= unusual_start or hour < unusual_end


def calculate_risk_score(failed_count, request_count, keywords, unusual_count):
    return (failed_count * 5) + (request_count // 10) + (sum(keywords.values()) * 3) + (unusual_count * 2)


def write_csv(output_file, rows):
    fieldnames = [
        "ip_address",
        "total_requests",
        "failed_logins",
        "suspicious_keywords",
        "unusual_access_count",
        "risk_score",
        "reasons",
    ]

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Detect suspicious activity in log files.")
    parser.add_argument("input_file", help="Path to the log file to analyze")
    parser.add_argument("-o", "--output", default="reports/suspicious_activity.csv", help="CSV report path")
    parser.add_argument("--failed-limit", type=int, default=5, help="Failed-login threshold per IP")
    parser.add_argument("--request-limit", type=int, default=20, help="Request threshold per IP")
    parser.add_argument("--unusual-start", type=int, default=0, help="Start hour for unusual access window")
    parser.add_argument("--unusual-end", type=int, default=5, help="End hour for unusual access window")
    args = parser.parse_args()

    input_file = Path(args.input_file)
    output_file = Path(args.output)

    if not input_file.exists():
        raise SystemExit(f"Input file not found: {input_file}")

    total_lines, suspicious_ips = analyze_log(
        input_file,
        args.failed_limit,
        args.request_limit,
        args.unusual_start,
        args.unusual_end,
    )
    write_csv(output_file, suspicious_ips)

    print(f"Analyzed {total_lines} log lines.")
    print(f"Found {len(suspicious_ips)} suspicious IP addresses.")
    print(f"CSV report saved to: {output_file}")

    if suspicious_ips:
        print("\nTop suspicious IPs:")
        for row in suspicious_ips[:5]:
            print(f"- {row['ip_address']} | score={row['risk_score']} | {row['reasons']}")


if __name__ == "__main__":
    main()
