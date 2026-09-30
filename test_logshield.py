import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from LogShield import Event, analyze_events, export_json


class LogShieldTests(unittest.TestCase):
    def event(self, minute, ip, event, status, resource="-"):
        return Event(datetime(2026, 9, 30, 9, 0, minute), ip, event, "demo", resource, status)

    def test_detects_brute_force_login_attempts(self):
        events = [self.event(index, "10.0.0.1", "LOGIN", "FAIL") for index in range(3)]
        alerts = analyze_events(events)
        self.assertEqual(alerts[0].alert_type, "BRUTE_FORCE")
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_detects_rejected_connections_to_many_ports(self):
        events = [
            self.event(index, "10.0.0.2", "CONNECTION", "REJECTED", str(port))
            for index, port in enumerate([22, 23, 80, 443, 3389])
        ]
        alerts = analyze_events(events)
        self.assertEqual(alerts[0].alert_type, "PORT_SCAN")

    def test_detects_sensitive_resource_request(self):
        alerts = analyze_events([self.event(0, "10.0.0.3", "HTTP", "BLOCKED", "/.env")])
        self.assertEqual(alerts[0].alert_type, "SENSITIVE_RESOURCE")
        self.assertEqual(alerts[0].severity, "LOW")

    def test_detects_password_spraying_across_source_ips(self):
        events = [
            Event(datetime(2026, 9, 30, 9, 0, index), ip, "LOGIN", "analyst", "-", "FAIL")
            for index, ip in enumerate(["10.0.0.6", "10.0.0.7", "10.0.0.6"])
        ]
        alerts = analyze_events(events)
        self.assertEqual(alerts[0].alert_type, "PASSWORD_SPRAY")

    def test_detects_web_attack_marker(self):
        alerts = analyze_events([self.event(0, "10.0.0.8", "HTTP", "BLOCKED", "/search?q=union+select")])
        self.assertEqual(alerts[0].alert_type, "WEB_ATTACK")
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_ignores_normal_activity(self):
        events = [self.event(0, "10.0.0.4", "LOGIN", "SUCCESS")]
        self.assertEqual(analyze_events(events), [])

    def test_exports_portable_json_report(self):
        events = [self.event(0, "10.0.0.5", "HTTP", "BLOCKED", "/.env")]
        alerts = analyze_events(events)
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.json"
            export_json(Path("sample_logs.csv"), events, alerts, output_path)
            report = output_path.read_text(encoding="utf-8")
            self.assertIn('"alerts_generated": 1', report)
            self.assertIn('"recommended_action"', report)


if __name__ == "__main__":
    unittest.main()
