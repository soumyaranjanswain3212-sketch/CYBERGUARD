from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

DEFAULT_DATABASE = Path(__file__).resolve().parents[1] / "cyberguard.sqlite3"
DATABASE_PATH = Path(os.getenv("CYBERGUARD_DB_PATH", str(DEFAULT_DATABASE)))


def _connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize() -> None:
    with _connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                subject TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
                status TEXT NOT NULL CHECK(status IN ('New', 'Investigating', 'Contained', 'Resolved')),
                summary TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                recommendations_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS events_timestamp_idx ON events(timestamp DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS events_severity_idx ON events(severity)"
        )


def _decode(row: sqlite3.Row) -> dict:
    event = dict(row)
    event["indicators"] = json.loads(event.pop("indicators_json"))
    event["recommendations"] = json.loads(event.pop("recommendations_json"))
    return event


def insert_event(event: dict) -> dict:
    return insert_events([event])[0]


def insert_events(events: list[dict]) -> list[dict]:
    if not events:
        return []
    with _connection() as connection:
        connection.executemany(
            """
            INSERT INTO events (
                id, timestamp, source, subject, category, severity, score, status,
                summary, indicators_json, recommendations_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            [
                (
                    event["id"], event["timestamp"], event["source"], event["subject"],
                    event["category"], event["severity"], event["score"], event["status"],
                    event["summary"], json.dumps(event["indicators"]),
                    json.dumps(event["recommendations"]),
                )
                for event in events
            ],
        )
        rows = [
            connection.execute(
                "SELECT * FROM events WHERE id = ?",
                (event["id"],),
            ).fetchone()
            for event in events
        ]
    if any(row is None for row in rows):
        raise RuntimeError("Event batch insert did not produce all stored records.")
    return [_decode(row) for row in rows if row is not None]


def list_events(limit: int = 500, offset: int = 0) -> list[dict]:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [_decode(row) for row in rows]


def update_status(event_id: str, status: str) -> dict | None:
    with _connection() as connection:
        result = connection.execute(
            "UPDATE events SET status = ? WHERE id = ?",
            (status, event_id),
        )
        if result.rowcount == 0:
            return None
        row = connection.execute(
            "SELECT * FROM events WHERE id = ?",
            (event_id,),
        ).fetchone()
    return _decode(row) if row is not None else None


def get_summary(now: datetime | None = None) -> dict:
    current = (now or datetime.now(UTC)).astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    start = current - timedelta(hours=23)
    end = current + timedelta(hours=1)
    hourly = {hour.isoformat(): 0 for hour in (start + timedelta(hours=i) for i in range(24))}

    with _connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        recent_rows = connection.execute(
            "SELECT timestamp, severity, status, category FROM events WHERE timestamp >= ? AND timestamp < ?",
            (start.isoformat(), end.isoformat()),
        ).fetchall()
        open_events = connection.execute(
            "SELECT COUNT(*) FROM events WHERE status IN ('New', 'Investigating')"
        ).fetchone()[0]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM events GROUP BY severity"
        ).fetchall()

    severity_counts = {row["severity"]: row["count"] for row in severity_rows}
    recent_severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for row in recent_rows:
        event_time = (
            datetime.fromisoformat(row["timestamp"])
            .astimezone(UTC)
            .replace(minute=0, second=0, microsecond=0)
        )
        key = event_time.isoformat()
        if key in hourly:
            hourly[key] += 1
        recent_severity_counts[row["severity"]] = (
            recent_severity_counts.get(row["severity"], 0) + 1
        )
        category_counts[row["category"]] = category_counts.get(row["category"], 0) + 1

    return {
        "total_events": total,
        "events_last_24h": len(recent_rows),
        "high_risk_last_24h": sum(
            row["severity"] in ("Critical", "High") for row in recent_rows
        ),
        "open_events": open_events,
        "severity_counts": severity_counts,
        "severity_counts_last_24h": recent_severity_counts,
        "category_counts": [
            {"category": category, "count": count}
            for category, count in sorted(
                category_counts.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "hourly_counts": [
            {"hour": hour, "count": count} for hour, count in hourly.items()
        ],
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
    }
