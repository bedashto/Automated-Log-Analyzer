import unittest
from log_analyzer import parse_log, detect_failed_logins, detect_high_request_ips, detect_brute_force
import pandas as pd

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        data = [
            {"ip": "192.168.1.1", "date": "10/Dec/2024:13:55:42 +0000", "status": "200", "request": "GET /index.html", "size": "4523"},
            {"ip": "192.168.1.2", "date": "10/Dec/2024:14:12:05 +0000", "status": "401", "request": "POST /login", "size": "34"},
            {"ip": "192.168.1.2", "date": "10/Dec/2024:14:12:06 +0000", "status": "401", "request": "POST /login", "size": "34"},
            {"ip": "192.168.1.3", "date": "10/Dec/2024:14:15:00 +0000", "status": "200", "request": "GET /dashboard", "size": "1234"},
            {"ip": "192.168.1.3", "date": "10/Dec/2024:14:16:00 +0000", "status": "200", "request": "GET /dashboard", "size": "1234"},
        ]
        self.logs_df = pd.DataFrame(data)

    def test_failed_logins(self):
        failed_logins = detect_failed_logins(self.logs_df)
        self.assertEqual(failed_logins['192.168.1.2'], 2)

    def test_high_request_ips(self):
        high_request_ips = detect_high_request_ips(self.logs_df, threshold=1)
        self.assertTrue("192.168.1.3" in high_request_ips.index)

    def test_brute_force_detection(self):
        brute_force_ips = detect_brute_force(self.logs_df, failed_attempt_threshold=1)
        self.assertTrue("192.168.1.2" in brute_force_ips.index)

if __name__ == "__main__":
    unittest.main()
