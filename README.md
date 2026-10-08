# LogShield

> A lightweight security monitoring tool for turning raw events into triaged alerts.

LogShield is a beginner-friendly defensive cybersecurity project that analyzes structured security logs and highlights possible indicators of compromise. It is intentionally built with Python's standard library so the detection logic is easy to understand, test, and explain in an interview.

## What it detects

- **Brute-force login activity:** 3 or more failed logins from one IP within 5 minutes.
- **Password spraying:** repeated failures against one user from multiple source IPs within 10 minutes.
- **Port scanning:** rejected connections to 5 or more different ports from one IP within 1 minute.
- **Sensitive resource access:** requests for `/admin`, `/.env`, or `/backup.zip`.
- **Web attack indicators:** simple path-traversal, SQL injection, and cross-site scripting probes.

Each alert includes severity, a time window, a recommended defensive action, and a MITRE ATT&CK tactic/technique reference.

## Demo

Run the analyzer and save a shareable JSON report:

```powershell
python LogShield.py sample_logs.csv --json-out report.json
```

The terminal report includes an overall risk rating, severity breakdown, time window, and a recommended defensive action for every alert. The JSON file is useful as evidence of structured output for a portfolio or GitHub repository.

## Run it

```powershell
python LogShield.py sample_logs.csv
```

Example output includes `HIGH`, `MEDIUM`, and `LOW` severity alerts. Thresholds can be changed for experiments:

```powershell
python LogShield.py sample_logs.csv --failed-threshold 4 --port-threshold 6
```

## Run tests

```powershell
python -m unittest discover -s tests -v
```

The test suite covers brute-force detection, password spraying, port scans, web attack indicators, sensitive-resource detection, normal activity, and JSON report generation.

## Log format

The analyzer accepts CSV files with these columns:

```text
timestamp,ip,event,user,resource,status
```

Supported event examples are `LOGIN`, `CONNECTION`, and `HTTP`. The sample file is synthetic and uses documentation-only IP ranges.

## Project structure

```text
LogShield.py       # parser, detection rules, report formatter, CLI
sample_logs.csv    # safe demo data
tests/             # automated unit tests
report.json        # generated demo report (after running the command above)
```

## Skills demonstrated

Python, CSV parsing, datetime windows, correlation rules, data classes, defensive security monitoring, alert triage, MITRE ATT&CK mapping, JSON serialization, command-line interfaces, unit testing, and technical documentation.
