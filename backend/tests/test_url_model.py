import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from backend.app.url_model import (
    DEFAULT_MODEL_PATH,
    FEATURE_NAMES,
    MODEL_VERSION,
    _load_artifact,
    extract_url_features,
    get_url_model_status,
    score_url,
)
from backend.scripts.train_url_model import _select_threshold


class URLModelTests(unittest.TestCase):
    def test_threshold_respects_minimum_and_validation_false_positive_limit(self):
        labels = np.asarray([0, 0, 0, 0, 1, 1, 1, 1])
        scores = np.asarray([0.1, 0.2, 0.3, 0.55, 0.52, 0.6, 0.8, 0.9])

        self.assertEqual(_select_threshold(labels, scores), 0.6)

    def test_url_features_are_local_and_have_a_stable_schema(self):
        values = dict(zip(
            FEATURE_NAMES,
            extract_url_features("https://192.0.2.4:8443/secure-login?token=abc"),
        ))

        self.assertEqual(len(values), 24)
        self.assertEqual(values["is_ip_host"], 1.0)
        self.assertEqual(values["uses_https"], 1.0)
        self.assertEqual(values["has_nonstandard_port"], 1.0)
        self.assertEqual(values["has_login_path"], 1.0)
        self.assertEqual(values["has_auth_query"], 1.0)

    def test_trained_artifact_exposes_held_out_metrics_and_threshold(self):
        status = get_url_model_status()

        self.assertTrue(status["available"])
        self.assertEqual(status["model"], MODEL_VERSION)
        self.assertGreater(status["test_metrics"]["rows"], 10_000)
        self.assertGreater(status["test_metrics"]["precision"], 0)
        self.assertGreater(status["test_metrics"]["recall"], 0)
        self.assertGreater(status["test_metrics"]["false_positive_rate"], 0)
        self.assertLessEqual(status["validation_metrics"]["false_positive_rate"], 0.001)
        self.assertGreaterEqual(status["threshold"], 0.5)
        self.assertGreater(status["threshold"], 0)
        self.assertLess(status["threshold"], 1)

    def test_common_benign_domains_are_not_flagged_by_the_smoke_check(self):
        benign_urls = (
            "https://example.com/",
            "https://www.google.com/",
            "https://github.com/",
            "https://www.microsoft.com/",
            "https://www.wikipedia.org/",
        )

        for url in benign_urls:
            with self.subTest(url=url):
                assessment = score_url(url)
                self.assertIsNotNone(assessment)
                assert assessment is not None
                self.assertFalse(assessment["flagged"])

    def test_runtime_artifact_is_json_and_validates_model_parameters(self):
        artifact = _load_artifact(str(DEFAULT_MODEL_PATH))
        self.assertIsNotNone(artifact)
        assert artifact is not None
        self.assertEqual(artifact["model_version"], MODEL_VERSION)
        self.assertEqual(len(artifact["classifier"]["coefficients"]), len(FEATURE_NAMES))

        with tempfile.TemporaryDirectory() as directory:
            malformed_path = Path(directory) / "invalid-model.json"
            malformed_path.write_text(json.dumps({
                "model_version": MODEL_VERSION,
                "feature_names": list(FEATURE_NAMES),
                "threshold": 0.5,
                "scaler": {"mean": [], "scale": []},
                "classifier": {"classes": [0, 1], "coefficients": [], "intercept": 0},
            }), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "invalid model parameters"):
                _load_artifact(str(malformed_path))

    def test_suspicious_url_is_scored_without_fetching_the_destination(self):
        assessment = score_url("http://192.0.2.10/secure-login/verify?account=password")

        self.assertIsNotNone(assessment)
        assert assessment is not None
        self.assertTrue(assessment["flagged"])
        self.assertGreaterEqual(assessment["phishing_score"], assessment["threshold"])
        self.assertEqual(assessment["model"], MODEL_VERSION)


if __name__ == "__main__":
    unittest.main()
