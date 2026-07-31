# SOC Log Analyzer

A Python-based Security Operations Center (SOC) log analyzer that parses Linux authentication logs and detects suspicious login activity such as brute-force attacks and password spraying.

---

## Features

- Parse Linux authentication logs
- Count failed login attempts per IP
- Detect brute-force attacks
- Detect password spraying attacks
- Calculate attack duration
- Calculate attempts per minute
- Assign risk scores
- Classify attack severity
- Export reports to JSON
- Export reports to CSV
- Identify the most suspicious IP address

---

## Technologies Used

- Python 3
- datetime
- json
- csv
- ipaddress

---

## Project Structure

```
SOC-Log-Analyzer/
│
├── logs/
│   └── sample_auth.log
│
├── report.json
├── report.csv
│
├── soc_log_analyzer.py
│
└── README.md
```

---

## How It Works

1. Reads authentication logs.
2. Extracts failed login attempts.
3. Groups attempts by IP address.
4. Detects suspicious attack patterns.
5. Calculates severity and risk score.
6. Generates reports.

---

## Attack Detection

### Brute Force

Detects multiple failed login attempts against the same account within a short period.

### Password Spraying

Detects attempts against multiple usernames from the same IP within a short period.

---

## Risk Scoring

Risk scores are calculated using:

- Brute-force detection
- Password spray detection
- High number of attempts
- High attempts-per-minute rate

Severity Levels:

- Low
- Medium
- High
- Critical

---

## Output

Console Report

- Failed attempts
- Attempts per minute
- Attack duration
- Risk score
- Severity
- Brute-force detection
- Password spraying detection
- First and last attempt timestamps

Exported Files

- report.json
- report.csv

---

## Skills Demonstrated

- Python programming
- File handling
- Dictionaries and lists
- Datetime manipulation
- Data analysis
- Cybersecurity fundamentals
- Attack detection logic
- JSON and CSV serialization
- Modular programming
- Documentation

---

## Author

Alyan Bhutta
BS Computer Science
Bahria University Islamabad
