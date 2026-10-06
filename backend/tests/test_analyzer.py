import unittest

from backend.app.analyzer import analyze_event


class AnalyzerTests(unittest.TestCase):
    def test_phishing_message_is_explained_and_recommends_containment(self):
        result = analyze_event({
            "source": "email",
            "content": "Urgent: verify your account password immediately",
            "url": "https://bit.ly/payroll-login",
            "sender": "payroll@gmail.com",
        })
        self.assertEqual(result["category"], "Credential phishing")
        self.assertIn(result["severity"], {"High", "Critical"})
        self.assertGreaterEqual(result["score"], 65)
        self.assertTrue(result["indicators"])
        self.assertIn("Quarantine the message", result["recommendations"])

    def test_identity_report_does_not_claim_to_detect_a_deepfake(self):
        result = analyze_event({
            "source": "identity",
            "content": "A voice note from the finance director asks for an urgent wire transfer",
        })
        self.assertEqual(result["category"], "Impersonation / deepfake concern")
        self.assertTrue(any("does not detect deepfakes" in action for action in result["recommendations"]))
        self.assertGreater(result["score"], 0)

    def test_authentication_anomaly_is_classified_as_account_takeover(self):
        result = analyze_event({
            "source": "auth",
            "failed_attempts": 12,
            "new_device": True,
            "unusual_location": True,
        })
        self.assertEqual(result["category"], "Account takeover")
        self.assertEqual(result["severity"], "Critical")
        self.assertIn("Revoke active sessions", result["recommendations"])

    def test_empty_signals_are_not_misrepresented_as_safe(self):
        result = analyze_event({"source": "email", "content": "Hello, see you tomorrow"})
        self.assertEqual(result["severity"], "Safe")
        self.assertIn("not a guarantee", result["summary"])

    def test_risk_is_capped(self):
        result = analyze_event({
            "source": "auth",
            "failed_attempts": 100_000,
            "new_device": True,
            "unusual_location": True,
        })
        self.assertEqual(result["score"], 95)

    def test_network_spike_is_scored_with_measurement_evidence_and_actions(self):
        result = analyze_event({
            "source": "network",
            "requests_per_minute": 1200,
            "baseline_requests_per_minute": 100,
            "bytes_out_mb": 120,
            "baseline_bytes_out_mb": 10,
            "error_rate_percent": 55,
        })

        self.assertEqual(result["category"], "Network / API anomaly")
        self.assertEqual(result["severity"], "Critical")
        self.assertEqual(result["score"], 100)
        self.assertTrue(any("12.0x" in item for item in result["indicators"]))
        self.assertIn(
            "Review outbound data destinations and investigate possible exfiltration",
            result["recommendations"],
        )

    def test_normal_network_measurements_are_not_flagged_as_anomalous(self):
        result = analyze_event({
            "source": "network",
            "requests_per_minute": 110,
            "baseline_requests_per_minute": 100,
            "bytes_out_mb": 12,
            "baseline_bytes_out_mb": 10,
            "error_rate_percent": 2,
        })

        self.assertEqual(result["category"], "Network / API anomaly")
        self.assertEqual(result["severity"], "Safe")
        self.assertIn("did not cross", result["indicators"][0])
        self.assertIn("not a guarantee", result["summary"])


if __name__ == "__main__":
    unittest.main()
