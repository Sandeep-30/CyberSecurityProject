# Cybersecurity Log Analyzer

A beginner-friendly Python project that reads log files, detects suspicious activity, and generates a CSV report. It simulates a basic SOC analyst workflow by flagging failed login spikes, repeated requests, suspicious keywords, possible brute-force activity, and unusual access times.

## What This Project Detects

- Too many failed login attempts from one IP address
- Repeated requests from the same IP address
- Suspicious keywords such as `admin`, `wp-login`, `passwd`, `select`, and `forbidden`
- Possible brute-force attempts
- Activity during unusual hours, defaulting to midnight through 5 AM

## Project Files

- `log_analyzer.py`: Main Python program
- `sample_logs/auth.log`: Sample log file for testing
- `reports/suspicious_activity.csv`: Generated CSV report after running the program

## Step-by-Step Instructions

### 1. Open the project folder

```bash
cd /Users/sandeepvenigandla/Documents/Codex/2026-05-14/project-1-cybersecurity-log-analyzer-this
```

### 2. Run the analyzer on the sample log file

```bash
python3 log_analyzer.py sample_logs/auth.log
```

### 3. Open the generated CSV report

The report will be created here:

```text
reports/suspicious_activity.csv
```

You can open it with Excel, Google Sheets, Numbers, or VS Code.

### 4. Try different thresholds

Lower the failed-login threshold:

```bash
python3 log_analyzer.py sample_logs/auth.log --failed-limit 3
```

Lower the repeated-request threshold:

```bash
python3 log_analyzer.py sample_logs/auth.log --request-limit 10
```

Save to a custom CSV file:

```bash
python3 log_analyzer.py sample_logs/auth.log -o reports/my_report.csv
```

### 5. Analyze your own log file

Replace `sample_logs/auth.log` with the path to another log file:

```bash
python3 log_analyzer.py path/to/your/logfile.log
```

## How It Works

The program reads the log file line by line. For each line, it:

1. Extracts the IP address using regex
2. Extracts the hour from the timestamp when possible
3. Counts total requests per IP address
4. Counts failed login attempts per IP address
5. Searches for suspicious security-related keywords
6. Flags activity during unusual hours
7. Calculates a simple risk score
8. Writes suspicious IPs to a CSV report

## Resume Bullet

Built a Python-based cybersecurity log analyzer that parses authentication and web logs, detects suspicious IP addresses using regex and frequency-based rules, and generates CSV reports for failed logins, brute-force indicators, suspicious keywords, and unusual access times.

## Interview Explanation

This project is similar to work done by security analysts because logs are one of the main sources used to investigate suspicious activity. The analyzer uses Python dictionaries and counters to track IP behavior, regex to extract IP addresses and timestamps, and CSV output to create a report that can be reviewed like a basic SOC alert summary.
