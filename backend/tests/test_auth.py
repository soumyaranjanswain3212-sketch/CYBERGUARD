import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import main, storage
from backend.app.security import create_session, hash_password


class AnalystAuthenticationTests(unittest.TestCase):
    username = "analyst"
    password = "correct-horse-battery-staple"
    password_hash = hash_password(password)
    secret = "session-test-secret-" + ("s" * 32)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path_patch = patch.object(
            storage,
            "DATABASE_PATH",
            Path(self.temp_dir.name) / "auth.sqlite3",
        )
        self.database_path_patch.start()
        self.environment_patch = patch.dict(
            os.environ,
            {
                "CYBERGUARD_ANALYST_USERNAME": self.username,
                "CYBERGUARD_ANALYST_PASSWORD_HASH": self.password_hash,
                "CYBERGUARD_SESSION_SECRET": self.secret,
                "CYBERGUARD_COOKIE_SECURE": "false",
                "CYBERGUARD_INGEST_TOKEN": "ingest-test-token-" + ("i" * 32),
            },
        )
        self.environment_patch.start()
        storage.initialize()
        main._failed_login_attempts.clear()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        self.environment_patch.stop()
        self.database_path_patch.stop()
        self.temp_dir.cleanup()
        main._failed_login_attempts.clear()

    def sign_in(self) -> dict:
        response = self.client.post(
            "/api/auth/login",
            json={"username": self.username, "password": self.password},
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_login_sets_httponly_strict_session_and_returns_csrf_token(self):
        response = self.client.post(
            "/api/auth/login",
            json={"username": self.username, "password": self.password},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], self.username)
        self.assertGreaterEqual(len(response.json()["csrf_token"]), 32)
        cookie = response.headers["set-cookie"].casefold()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertIn("max-age=28800", cookie)
        self.assertNotIn("secure", cookie)

    def test_dashboard_data_is_not_available_without_an_analyst_session(self):
        for path in ("/api/events", "/api/summary"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

        response = self.client.post(
            "/api/analyze",
            json={"source": "email", "content": "Urgent verify your password"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(storage.get_summary()["total_events"], 0)

    def test_analysis_and_status_changes_require_the_session_csrf_token(self):
        session = self.sign_in()
        payload = {"source": "email", "content": "Urgent verify your password"}

        missing_csrf = self.client.post("/api/analyze", json=payload)
        allowed = self.client.post(
            "/api/analyze",
            json=payload,
            headers={"X-CSRF-Token": session["csrf_token"]},
        )

        self.assertEqual(missing_csrf.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        event_id = allowed.json()["id"]
        update = self.client.patch(
            f"/api/events/{event_id}",
            json={"status": "Investigating"},
            headers={"X-CSRF-Token": session["csrf_token"]},
        )
        wrong_csrf = self.client.patch(
            f"/api/events/{event_id}",
            json={"status": "Resolved"},
            headers={"X-CSRF-Token": "incorrect"},
        )

        self.assertEqual(update.status_code, 200)
        self.assertEqual(update.json()["status"], "Investigating")
        self.assertEqual(wrong_csrf.status_code, 403)

    def test_session_endpoint_and_logout_invalidate_browser_access(self):
        session = self.sign_in()
        session_response = self.client.get("/api/auth/session")
        self.assertEqual(session_response.json(), session)

        logout_response = self.client.post(
            "/api/auth/logout",
            headers={"X-CSRF-Token": session["csrf_token"]},
        )

        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(self.client.get("/api/events").status_code, 401)

    def test_tampered_or_expired_session_is_rejected(self):
        self.sign_in()
        cookie_name = "cyberguard_session"
        valid_cookie = self.client.cookies.get(cookie_name)
        replacement = "A" if valid_cookie[-1] != "A" else "B"
        self.client.cookies.set(cookie_name, f"{valid_cookie[:-1]}{replacement}")
        tampered = self.client.get("/api/events")
        self.assertEqual(tampered.status_code, 401)

        self.client.cookies.clear()
        self.sign_in()
        expired_cookie, _ = create_session(self.username)
        with patch("backend.app.security.time.time", return_value=10**12):
            self.client.cookies.set(cookie_name, expired_cookie)
            expired = self.client.get("/api/events")
        self.assertEqual(expired.status_code, 401)

    def test_production_cookie_can_be_marked_secure(self):
        with patch.dict(os.environ, {"CYBERGUARD_COOKIE_SECURE": "true"}):
            response = self.client.post(
                "/api/auth/login",
                json={"username": self.username, "password": self.password},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("secure", response.headers["set-cookie"].casefold())

    def test_invalid_credentials_are_generic_and_throttled(self):
        for attempt in range(5):
            response = self.client.post(
                "/api/auth/login",
                json={"username": self.username, "password": f"incorrect-{attempt}"},
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["detail"], "Invalid username or password.")

        blocked = self.client.post(
            "/api/auth/login",
            json={"username": self.username, "password": self.password},
        )

        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers["Retry-After"], "300")

    def test_missing_auth_configuration_fails_closed(self):
        with patch.dict(os.environ, {"CYBERGUARD_SESSION_SECRET": ""}):
            response = self.client.post(
                "/api/auth/login",
                json={"username": self.username, "password": self.password},
            )
        self.assertEqual(response.status_code, 503)

    def test_unauthenticated_telemetry_ingest_remains_token_protected(self):
        response = self.client.post(
            "/api/ingest",
            json={
                "source": "auth",
                "source_name": "unit test provider",
                "source_event_id": "login-test",
                "observed_at": datetime.now(UTC).isoformat(),
                "failed_attempts": 5,
            },
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
