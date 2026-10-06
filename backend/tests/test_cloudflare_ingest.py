import gzip
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import main, storage


class CloudflareLogpushTests(unittest.TestCase):
    token = "test-token-" + ("c" * 40)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path_patch = patch.object(
            storage,
            "DATABASE_PATH",
            Path(self.temp_dir.name) / "cloudflare.sqlite3",
        )
        self.database_path_patch.start()
        storage.initialize()
        self.environment_patch = patch.dict(os.environ, {"CYBERGUARD_INGEST_TOKEN": self.token})
        self.environment_patch.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        self.environment_patch.stop()
        self.database_path_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def record(action, ray_id):
        return {
            "Action": action,
            "Datetime": datetime.now(UTC).isoformat(),
            "RayID": ray_id,
            "Source": "firewallmanaged",
            "Description": "Managed firewall rule matched",
            "ClientRequestHost": "portal.example.org",
            "ClientRequestMethod": "POST",
            "ClientIP": "203.0.113.17",
            "ClientIPClass": "tor" if action == "block" else "unknown",
        }

    @staticmethod
    def gzipped_ndjson(records):
        lines = b"\n".join(
            json.dumps(record, separators=(",", ":")).encode("utf-8")
            for record in records
        )
        return gzip.compress(lines)

    def test_ingests_real_format_firewall_batch_and_deduplicates_retries(self):
        body = self.gzipped_ndjson([
            self.record("block", "ray-block-1"),
            self.record("allow", "ray-allow-2"),
        ])
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Encoding": "gzip",
            "Content-Type": "application/x-ndjson",
        }

        first = self.client.post("/api/ingest/cloudflare/logpush", content=body, headers=headers)
        retry = self.client.post("/api/ingest/cloudflare/logpush", content=body, headers=headers)
        saved_events = storage.list_events()
        blocked = next(event for event in saved_events if event["category"] == "Cloudflare firewall intervention")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), {"records_processed": 2, "validation_probe": False})
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(storage.get_summary()["total_events"], 2)
        self.assertEqual(blocked["severity"], "Critical")
        self.assertTrue(any("Cloudflare Ray ID: ray-block-1" in item for item in blocked["indicators"]))
        self.assertFalse(any("203.0.113.17" in item for item in blocked["indicators"]))

    def test_accepts_cloudflare_destination_validation_probe_without_storing_an_event(self):
        body = gzip.compress(b'{"content":"tests"}')
        response = self.client.post(
            "/api/ingest/cloudflare/logpush",
            content=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Encoding": "gzip",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"records_processed": 0, "validation_probe": True})
        self.assertEqual(storage.get_summary()["total_events"], 0)

    def test_rejects_invalid_batch_without_partially_storing_events(self):
        body = self.gzipped_ndjson([
            self.record("block", "ray-valid"),
            {"Action": "allow"},
        ])
        response = self.client.post(
            "/api/ingest/cloudflare/logpush",
            content=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Encoding": "gzip",
            },
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(storage.get_summary()["total_events"], 0)

    def test_rejects_unauthenticated_logpush_request(self):
        response = self.client.post("/api/ingest/cloudflare/logpush", content=b"")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(storage.get_summary()["total_events"], 0)

    def test_rejects_corrupted_gzip_stream(self):
        response = self.client.post(
            "/api/ingest/cloudflare/logpush",
            content=b"\x1f\x8bnot-a-gzip-stream",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Encoding": "gzip",
            },
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(storage.get_summary()["total_events"], 0)


if __name__ == "__main__":
    unittest.main()
