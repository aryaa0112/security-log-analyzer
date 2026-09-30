"""LogShield: a small defensive security log analyzer."""

from __future__ import annotations

import argparse
import csv
import json
from urllib.parse import unquote_plus
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable


TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    ip: str
    event: str
    user: str
    resource: str
    status: str


@dataclass(frozen=True)
class Alert:
    severity: str
    alert_type: str
    ip: str
    message: str
    first_seen: datetime
    last_seen: datetime


RECOMMENDATIONS = {
    "BRUTE_FORCE": "Review authentication logs and consider rate limiting or account lockout.",
    "PASSWORD_SPRAY": "Review the targeted accounts and enforce MFA or adaptive login controls.",
    "PORT_SCAN": "Review firewall events and restrict unnecessary exposed services.",
    "SENSITIVE_RESOURCE": "Verify the request and keep secrets outside publicly served paths.",
    "WEB_ATTACK": "Inspect the request and application logs, then validate input handling and WAF rules.",
}

TACTICS = {
    "BRUTE_FORCE": ("Credential Access", "T1110"),
    "PASSWORD_SPRAY": ("Credential Access", "T1110.003"),
    "PORT_SCAN": ("Discovery", "T1046"),
    "SENSITIVE_RESOURCE": ("Discovery", "T1083"),
    "WEB_ATTACK": ("Initial Access", "T1190"),
}


def load_events(log_path: Path) -> list[Event]:
    """Load the intentionally simple CSV format used by the demo."""
    with log_path.open(newline="", encoding="utf-8") as log_file:
        reader = csv.DictReader(log_file)
        required_columns = {"timestamp", "ip", "event", "user", "resource", "status"}
        if not required_columns.issubset(reader.fieldnames or set()):
            raise ValueError("Log must include: timestamp, ip, event, user, resource, status")

        events = []
        for row in reader:
            events.append(
                Event(
                    timestamp=datetime.strptime(row["timestamp"], TIME_FORMAT),
                    ip=row["ip"],
                    event=row["event"],
                    user=row["user"],
                    resource=row["resource"],
                    status=row["status"],
                )
            )
    return sorted(events, key=lambda event: event.timestamp)


def analyze_events(
    events: Iterable[Event],
    failed_login_threshold: int = 3,
    port_scan_threshold: int = 5,
) -> list[Alert]:
    """Detect common beginner-friendly indicators of compromise."""
    sorted_events = sorted(events, key=lambda event: event.timestamp)
    alerts: list[Alert] = []
    alerts.extend(_detect_brute_force(sorted_events, failed_login_threshold))
    alerts.extend(_detect_password_spraying(sorted_events))
    alerts.extend(_detect_port_scans(sorted_events, port_scan_threshold))
    alerts.extend(_detect_sensitive_access(sorted_events))
    alerts.extend(_detect_web_attacks(sorted_events))
    return sorted(alerts, key=lambda alert: (alert.first_seen, alert.ip, alert.alert_type))


def _detect_brute_force(events: list[Event], threshold: int) -> list[Alert]:
    failed_logins = defaultdict(list)
    for event in events:
        if event.event == "LOGIN" and event.status == "FAIL":
            failed_logins[event.ip].append(event)

    alerts = []
    for ip, attempts in failed_logins.items():
        for start_index in range(len(attempts)):
            window_end = attempts[start_index].timestamp + timedelta(minutes=5)
            window = [event for event in attempts[start_index:] if event.timestamp <= window_end]
            if len(window) >= threshold:
                alerts.append(
                    Alert(
                        "HIGH",
                        "BRUTE_FORCE",
                        ip,
                        f"{len(window)} failed logins in 5 minutes",
                        window[0].timestamp,
                        window[-1].timestamp,
                    )
                )
                break
    return alerts


def _detect_password_spraying(events: list[Event]) -> list[Alert]:
    failed_by_user = defaultdict(list)
    for event in events:
        if event.event == "LOGIN" and event.status == "FAIL" and event.user != "-":
            failed_by_user[event.user].append(event)

    alerts = []
    for user, attempts in failed_by_user.items():
        for start_index, start_event in enumerate(attempts):
            window_end = start_event.timestamp + timedelta(minutes=10)
            window = [event for event in attempts[start_index:] if event.timestamp <= window_end]
            source_ips = {event.ip for event in window}
            if len(source_ips) >= 2 and len(window) >= 3:
                alerts.append(
                    Alert(
                        "HIGH",
                        "PASSWORD_SPRAY",
                        ", ".join(sorted(source_ips)),
                        f"{len(window)} failed logins against user {user} from {len(source_ips)} IPs",
                        window[0].timestamp,
                        window[-1].timestamp,
                    )
                )
                break
    return alerts


def _detect_port_scans(events: list[Event], threshold: int) -> list[Alert]:
    connections = defaultdict(list)
    for event in events:
        if event.event == "CONNECTION" and event.status == "REJECTED":
            connections[event.ip].append(event)

    alerts = []
    for ip, attempts in connections.items():
        for start_index, start_event in enumerate(attempts):
            window_end = start_event.timestamp + timedelta(minutes=1)
            window = [event for event in attempts[start_index:] if event.timestamp <= window_end]
            ports = {event.resource for event in window}
            if len(ports) >= threshold:
                alerts.append(
                    Alert(
                        "MEDIUM",
                        "PORT_SCAN",
                        ip,
                        f"Rejected connections to {len(ports)} ports in 1 minute",
                        window[0].timestamp,
                        window[-1].timestamp,
                    )
                )
                break
    return alerts


def _detect_sensitive_access(events: list[Event]) -> list[Alert]:
    alerts = []
    for event in events:
        if event.event == "HTTP" and event.resource in {"/admin", "/.env", "/backup.zip"}:
            alerts.append(
                Alert(
                    "LOW" if event.status == "BLOCKED" else "MEDIUM",
                    "SENSITIVE_RESOURCE",
                    event.ip,
                    f"Request for {event.resource} ({event.status})",
                    event.timestamp,
                    event.timestamp,
                )
            )
    return alerts


def _detect_web_attacks(events: list[Event]) -> list[Alert]:
    attack_markers = {
        "../": "path traversal",
        "union select": "SQL injection probe",
        "<script": "cross-site scripting probe",
    }
    alerts = []
    for event in events:
        resource = unquote_plus(event.resource).lower()
        marker = next((marker for marker in attack_markers if marker in resource), None)
        if marker:
            alerts.append(
                Alert(
                    "HIGH",
                    "WEB_ATTACK",
                    event.ip,
                    f"Possible {attack_markers[marker]} in request for {event.resource}",
                    event.timestamp,
                    event.timestamp,
                )
            )
    return alerts


def format_report(events: list[Event], alerts: list[Alert]) -> str:
    severity_counts = {severity: sum(alert.severity == severity for alert in alerts) for severity in ("HIGH", "MEDIUM", "LOW")}
    risk_level = "HIGH" if severity_counts["HIGH"] else "MEDIUM" if severity_counts["MEDIUM"] else "LOW" if alerts else "CLEAR"
    lines = [
        "LOGSHIELD | SECURITY ANALYST REPORT",
        "=" * 36,
        f"Events analyzed: {len(events)}",
        f"Alerts generated: {len(alerts)}",
        f"Overall risk: {risk_level}",
        f"Severity breakdown: HIGH={severity_counts['HIGH']} | MEDIUM={severity_counts['MEDIUM']} | LOW={severity_counts['LOW']}",
        "",
    ]
    if not alerts:
        lines.append("No suspicious activity detected.")
        return "\n".join(lines)

    for alert in alerts:
        lines.append(f"[{alert.severity}] {alert.alert_type} | {alert.ip}")
        lines.append(f"  {alert.message}")
        lines.append(f"  Window: {alert.first_seen} -> {alert.last_seen}")
        tactic, technique = TACTICS[alert.alert_type]
        lines.append(f"  ATT&CK context: {tactic} ({technique})")
        lines.append(f"  Recommended action: {RECOMMENDATIONS[alert.alert_type]}")
    return "\n".join(lines)


def export_json(log_path: Path, events: list[Event], alerts: list[Alert], output_path: Path) -> None:
    """Write a portable report that can be attached to a portfolio demo."""
    report = {
        "source": log_path.name,
        "events_analyzed": len(events),
        "alerts_generated": len(alerts),
        "alerts": [
            {
                "severity": alert.severity,
                "type": alert.alert_type,
                "ip": alert.ip,
                "message": alert.message,
                "first_seen": alert.first_seen.strftime(TIME_FORMAT),
                "last_seen": alert.last_seen.strftime(TIME_FORMAT),
                "attack_tactic": TACTICS[alert.alert_type][0],
                "attack_technique": TACTICS[alert.alert_type][1],
                "recommended_action": RECOMMENDATIONS[alert.alert_type],
            }
            for alert in alerts
        ],
    }
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze CSV security logs for suspicious activity.")
    parser.add_argument("log_file", type=Path, help="Path to a LogShield CSV log file")
    parser.add_argument("--failed-threshold", type=int, default=3, help="Failed logins needed for an alert")
    parser.add_argument("--port-threshold", type=int, default=5, help="Rejected ports needed for an alert")
    parser.add_argument("--json-out", type=Path, help="Also save the report as JSON")
    args = parser.parse_args()

    try:
        events = load_events(args.log_file)
        alerts = analyze_events(events, args.failed_threshold, args.port_threshold)
        if args.json_out:
            export_json(args.log_file, events, alerts, args.json_out)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(format_report(events, alerts))


if __name__ == "__main__":
    main()
