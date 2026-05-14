# Cybersecurity Log Analyzer

This is a simple Python project I made to practice basic cybersecurity log analysis. The program reads a log file, checks for suspicious activity, and creates a CSV report with the results.

I wanted to build this project because log files are important in cybersecurity. Security analysts often look through logs to find failed logins, repeated requests, strange IP activity, and possible attacks. This project is a small version of that idea.

## What the Project Does

This program looks for:

- Too many failed login attempts from the same IP address
- Too many requests from one IP address
- Suspicious words in the logs, such as `admin`, `wp-login`, `passwd`, `select`, and `forbidden`
- Possible brute-force login attempts
- Activity happening late at night or early in the morning

After checking the log file, the program creates a CSV report showing the IP addresses that looked suspicious.

## Files in This Project

- `log_analyzer.py` - the main Python file
- `sample_logs/auth.log` - a sample log file used for testing
- `reports/suspicious_activity.csv` - the report created by the program
- `reports/my_report.csv` - another example report

## How to Run It

First, open the project folder in the terminal:

```bash
cd /Users/sandeepvenigandla/Documents/Codex/2026-05-14/project-1-cybersecurity-log-analyzer-this
```

Then run the program using the sample log file:

```bash
python3 log_analyzer.py sample_logs/auth.log
```

After running it, the report will be saved here:

```text
reports/suspicious_activity.csv
```

You can open the CSV file in Excel, Google Sheets, Numbers, or VS Code.

## Changing the Settings

You can change the limits if you want the program to flag activity faster.

For example, this makes the program flag an IP after 3 failed login attempts:

```bash
python3 log_analyzer.py sample_logs/auth.log --failed-limit 3
```

This changes the request limit:

```bash
python3 log_analyzer.py sample_logs/auth.log --request-limit 10
```

You can also choose a different output file:

```bash
python3 log_analyzer.py sample_logs/auth.log -o reports/my_report.csv
```

## Using a Different Log File

You can also test the program with your own log file. Just replace the sample file path with your own file path:

```bash
python3 log_analyzer.py path/to/your/logfile.log
```

## How It Works

The program reads the log file one line at a time.

For each line, it tries to find:

- The IP address
- The time of the activity
- Failed login messages
- Suspicious words
- Repeated activity from the same IP

It uses regular expressions to find IP addresses and timestamps. It also uses Python dictionaries and counters to keep track of how many times each IP address appears.

If an IP address looks suspicious, the program adds it to the CSV report with the reason it was flagged.
