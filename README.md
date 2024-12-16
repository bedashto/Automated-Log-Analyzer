# Automated Log Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://github.com/bedashto/automated-log-analyzer/actions/workflows/python-tests.yml/badge.svg)

## Description
The Automated Log Analyzer is a Python-based tool for parsing and analyzing server logs. It identifies suspicious activities such as:
- **Failed login attempts**.
- **High-frequency requests** from specific IPs.
- **Brute force attacks**.

The tool generates insightful visualizations to help administrators detect and mitigate potential security threats.

---

## Features
- **Parse server logs** (e.g., Apache or Nginx).
- **Analyze anomalies**:
  - Detect failed login attempts.
  - Identify IPs with unusually high request frequencies.
  - Flag potential brute force attacks.
- **Visualize findings**:
  - Failed login attempts.
  - High request IPs.
  - Brute force attack sources.

---

## Requirements
- Python 3.13.1
- Install dependencies:
  ```bash
  pip install pandas matplotlib
