# Automated Server Authentication Log Analyzer (Python)

A lightweight, zero-dependency Python tool that parses Linux SSH authentication logs (`auth.log`), detects brute-force attacks and suspicious post-failure logins, and exports structured **CSV** and **JSON** incident response reports.

## Key Features
- **Regex Log Parsing:** Extracts timestamps, targeted usernames, authentication outcomes (`Failed` vs. `Accepted`), and source IP addresses from raw unstructured server logs.
- **Automated Threat Classification:**
  - **`HIGH` Severity:** Flags source IPs exceeding the configurable failed-login threshold (default: `5` attempts).
  - **`CRITICAL` Severity:** Escalates IPs that successfully authenticate after multiple failed attempts (indicative of potential account compromise).
- **Actionable Incident Exports:** Generates both `security_report.csv` (for SOC analysts) and `flagged_ips.json` (for SIEM or firewall automation).
- **Zero External Dependencies:** Built entirely with Python's standard library (`re`, `csv`, `json`, `collections`, `datetime`).

## Project Structure
- `log_analyzer.py` — Main Python parsing and threat detection script.
- `sample_auth.log` — Simulated Linux SSH authentication log containing benign traffic, brute-force attempts, and a simulated compromise.
- `security_report.csv` — Tabular summary of flagged malicious IPs and recommended actions.
- `flagged_ips.json` — Structured JSON alert feed with metadata and IOCs.

## How to Run
```bash
python log_analyzer.py
