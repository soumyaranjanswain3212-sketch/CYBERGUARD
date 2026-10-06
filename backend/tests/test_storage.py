import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from backend.app import storage


class StorageSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.database_path_patch = patch.object(storage, "DATABASE_PATH", self.database_path)
        self.database_path_patch.start()
        storage.initialize()

    def tearDown(self):
        self.database_path_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def event(event_id, timestamp, severity, status):
        return {
            "id": event_id,
            "timestamp": timestamp.isoformat(),
            "source": "test",
            "subject": event_id,
            "category": "Test category",
            "severity": severity,
            "score": 80,
            "status": status,
            "summary": "Test event",
            "indicators": [],
            "recommendations": [],
        }

    def test_summary_separates_recent_risk_from_all_time_totals(self):
        now = datetime(2026, 10, 6, 12, 30, tzinfo=UTC)
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        start = current_hour - timedelta(hours=23)
        storage.insert_event(self.event("recent-high", now, "High", "New"))
        storage.insert_event(
            self.event("older-critical", start - timedelta(seconds=1), "Critical", "Investigating")
        )

        summary = storage.get_summary(now)

        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["events_last_24h"], 1)
        self.assertEqual(summary["high_risk_last_24h"], 1)
        self.assertEqual(summary["severity_counts"], {"Critical": 1, "High": 1})
        self.assertEqual(summary["severity_counts_last_24h"], {"High": 1})
        self.assertEqual(summary["open_events"], 2)
        self.assertEqual(summary["category_counts"], [{"category": "Test category", "count": 1}])

    def test_status_update_is_persisted(self):
        event = self.event("status-check", datetime.now(UTC), "High", "New")
        storage.insert_event(event)

        updated = storage.update_status(event["id"], "Resolved")

        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "Resolved")
        self.assertEqual(storage.list_events()[0]["status"], "Resolved")


if __name__ == "__main__":
    unittest.main()
