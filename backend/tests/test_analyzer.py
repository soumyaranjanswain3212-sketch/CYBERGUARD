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


if __name__ == "__main__":
    unittest.main()
