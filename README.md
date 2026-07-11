# SOC Log Analyzer

A Python-based Security Operations Center (SOC) log analyzer designed to detect suspicious authentication activity from Linux log files.

**Status:** In Development

---

## Overview

This project simulates the type of log analysis performed by Security Operations Center analysts. It parses authentication logs, identifies failed login attempts, detects suspicious IP addresses, and generates security focused reports.

The goal is not only to build a working log analyzer, but also to apply professional software engineering practices such as modular design, documentation, error handling, type hints, and version control.

---

## Current Features

* Parse Linux authentication logs
* Count failed login attempts per IP address
* Generate failed login reports
* Detect IPs exceeding a configurable threshold
* Identify the most suspicious IP address
* Handle missing log files gracefully
* Type hints and Google-style docstrings

---

## Planned Features

* Timestamp parsing
* Brute-force attack detection within configurable time windows
* Username based analysis
* CSV and JSON report generation
* Command-line interface (CLI)
* Unit testing
* Logging
* Configuration files
* Modular architecture

---

## Technologies

* Python 3
* Git
* GitHub

---

## Project Structure

```text
soc-log-analyzer/
├── logs/
├── reports/
├── src/
│   └── soc_log_analyzer.py
├── README.md
└── .gitignore
```

---

## Purpose

This project is being developed as part of my cybersecurity and Python learning journey with an emphasis on writing production-quality code rather than simply producing a working script.
