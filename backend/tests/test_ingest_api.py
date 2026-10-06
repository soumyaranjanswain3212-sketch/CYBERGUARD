import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import main, storage


class TelemetryIngestApiTests(unittest.TestCase):
    token = "test-token-" + ("x" * 40)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path_patch = patch.object(
            storage,
            "DATABASE_PATH",
            Path(self.temp_dir.name) / "ingest.sqlite3",
        )
        self.database_path_patch.start()
        storage.initialize()
        self.client = TestClient(main.app)
        self.environment_patch = patch.dict(os.environ, {"CYBERGUARD_INGEST_TOKEN": self.token})
        self.environment_patch.start()

    def tearDown(self):
        self.client.close()
        self.environment_patch.stop()
        self.database_path_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def payload():
        return {
            "source": "network",
            "source_name": "Authorized API gateway",
            "source_event_id": "evt-90210",
            "observed_at": datetime.now(UTC).isoformat(),
            "requests_per_minute": 900,
            "baseline_requests_per_minute": 100,
            "bytes_out_mb": 15,
            "baseline_bytes_out_mb": 10,
        }

    def test_requires_bearer_token(self):
        response = self.client.post("/api/ingest", json=self.payload())

        self.assertEqual(response.status_code, 401)
        self.assertEqual(storage.get_summary()["total_events"], 0)

    def test_rejects_ingestion_when_server_secret_is_unconfigured(self):
        with patch.dict(os.environ, {"CYBERGUARD_INGEST_TOKEN": ""}):
            response = self.client.post(
                "/api/ingest",
                json=self.payload(),
                headers={"Authorization": f"Bearer {self.token}"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(storage.get_summary()["total_events"], 0)

    def test_ingests_authorized_event_and_deduplicates_delivery_retries(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        first = self.client.post("/api/ingest", json=self.payload(), headers=headers)
        retry = self.client.post("/api/ingest", json=self.payload(), headers=headers)

        self.assertEqual(first.status_code, 202)
        self.assertEqual(retry.status_code, 202)
        self.assertEqual(first.json()["id"], retry.json()["id"])
        self.assertEqual(first.json()["source"], "Authorized API gateway")
        self.assertEqual(first.json()["category"], "Network / API anomaly")
        self.assertEqual(storage.get_summary()["total_events"], 1)

    def test_rejects_partial_baseline_and_unknown_payload_fields(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        payload = self.payload()
        payload.pop("baseline_requests_per_minute")
        partial_baseline = self.client.post("/api/ingest", json=payload, headers=headers)
        invalid_extra = self.client.post(
            "/api/ingest",
            json={**self.payload(), "unvalidated_payload": "unexpected"},
            headers=headers,
        )

        self.assertEqual(partial_baseline.status_code, 422)
        self.assertEqual(invalid_extra.status_code, 422)
        self.assertEqual(storage.get_summary()["total_events"], 0)


if __name__ == "__main__":
    unittest.main()
