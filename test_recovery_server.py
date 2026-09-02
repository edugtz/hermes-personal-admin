#!/usr/bin/env python3
"""Tests for the GET /notifications/pending recovery endpoint."""

import json
import socket
import sqlite3
import tempfile
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

import ack_server
import fcm_sender


TEST_KEY = bytes(range(32))
TEST_PORT = 2588


class _ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def _create_db(db_path):
    """Create the database schema used by ack_server tests."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            status TEXT NOT NULL
        );

        CREATE TABLE notifications (
            notification_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            dedupe_key TEXT NOT NULL UNIQUE,
            level TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            ack_token TEXT NOT NULL UNIQUE,
            ntfy_sequence_id TEXT NOT NULL UNIQUE,
            ntfy_message_id TEXT,
            created_at TEXT NOT NULL,
            sent_at TEXT,
            acknowledged_at TEXT,
            acknowledged_by TEXT,
            send_attempts INTEGER NOT NULL DEFAULT 0,
            last_attempt_at TEXT,
            last_error TEXT,
            canceled_at TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(run_id)
        );

        CREATE INDEX IF NOT EXISTS idx_notifications_ack
            ON notifications(acknowledged_at);
        """
    )
    conn.commit()
    conn.close()


def _insert_run(conn, run_id, status):
    conn.execute(
        "INSERT INTO runs(run_id, status) VALUES (?, ?)",
        (run_id, status),
    )
    conn.commit()


def _insert_notification(
    conn,
    notification_id,
    run_id="run-001",
    level="important",
    title="Test title",
    message="Test message",
    ack_token=None,
    created_at="2026-09-01T00:00:00Z",
    sent_at=None,
    acknowledged_at=None,
    acknowledged_by=None,
    canceled_at=None,
    send_attempts=0,
    last_attempt_at=None,
    last_error=None,
):
    conn.execute(
        """
        INSERT INTO notifications(
            notification_id, run_id, dedupe_key, level, title, message,
            ack_token, ntfy_sequence_id, created_at, sent_at,
            acknowledged_at, acknowledged_by, canceled_at,
            send_attempts, last_attempt_at, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            notification_id,
            run_id,
            "dedupe-" + notification_id,
            level,
            title,
            message,
            ack_token or "ack-" + notification_id,
            "seq-" + notification_id,
            created_at,
            sent_at,
            acknowledged_at,
            acknowledged_by,
            canceled_at,
            send_attempts,
            last_attempt_at,
            last_error,
        ),
    )
    conn.commit()


class RecoveryServerTest(unittest.TestCase):
    """Test the GET /notifications/pending recovery endpoint."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db_file = Path(self.directory.name) / "test.db"
        self.db_patch = patch.object(
            ack_server, "DB_FILE", self.db_file
        )
        self.db_patch.start()
        _create_db(self.db_file)

        # Start a test server on a different port
        self.server = _ReusableHTTPServer(
            ("127.0.0.1", TEST_PORT),
            ack_server.Handler,
        )
        self.server_thread = Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5.0)
        self.db_patch.stop()
        self.directory.cleanup()

    def _get_recovery(
        self,
        headers=None,
    ):
        """Make a GET /notifications/pending request and return
        (status, parsed_body)."""
        conn = HTTPConnection("127.0.0.1", TEST_PORT)

        default_headers = {
            "Host": "127.0.0.1:2587",
        }
        if headers is not None:
            default_headers.update(headers)

        conn.request(
            "GET",
            "/notifications/pending",
            headers=default_headers,
        )
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        conn.close()
        return response.status, json.loads(body)

    def _get_recovery_raw(
        self,
        headers=None,
    ):
        """Make a GET /notifications/pending request and return
        (status, response)."""
        conn = HTTPConnection("127.0.0.1", TEST_PORT)

        default_headers = {
            "Host": "127.0.0.1:2587",
        }
        if headers is not None:
            default_headers.update(headers)

        conn.request(
            "GET",
            "/notifications/pending",
            headers=default_headers,
        )
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        status = response.status
        cache_control = response.getheader("Cache-Control")
        conn.close()
        return status, json.loads(raw), raw, cache_control

    def _get_health(self):
        """Make a GET /health request and return (status, parsed_body)."""
        conn = HTTPConnection("127.0.0.1", TEST_PORT)
        conn.request(
            "GET",
            "/health",
            headers={"Host": "127.0.0.1:2587"},
        )
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        conn.close()
        return response.status, json.loads(body)

    def _get_unknown_route(self):
        """Make a GET to an unknown route and return (status, parsed_body,
        cache_control)."""
        conn = HTTPConnection("127.0.0.1", TEST_PORT)
        conn.request(
            "GET",
            "/unknown-route",
            headers={"Host": "127.0.0.1:2587"},
        )
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        cache_control = response.getheader("Cache-Control")
        conn.close()
        return response.status, json.loads(body), cache_control

    def _decrypt_envelope(
        self, envelope, key=None
    ):
        """Decrypt an envelope and return the inner payload dict."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64

        k = key if key is not None else TEST_KEY

        def _b64url_decode(s):
            padding = 4 - len(s) % 4
            if padding != 4:
                s += "=" * padding
            return base64.urlsafe_b64decode(s)

        nonce_bytes = _b64url_decode(envelope["nonce"])
        ciphertext_bytes = _b64url_decode(envelope["ciphertext"])
        kid = envelope["kid"]

        plaintext = AESGCM(k).decrypt(
            nonce_bytes,
            ciphertext_bytes,
            fcm_sender.canonical_aad(kid),
        )
        return json.loads(plaintext)

    def test_committed_uncanceled_unacknowledged_sent_at_null_returned(self):
        """Test 1: committed, uncanceled, unacknowledged, sent_at NULL
        is returned."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-001",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(1, body["count"])
        self.assertEqual(1, len(body["items"]))
        self.assertEqual(
            {"v", "kid", "nonce", "ciphertext"},
            set(body["items"][0]),
        )

    def test_committed_uncanceled_unacknowledged_sent_at_present_returned(
        self,
    ):
        """Test 2: committed, uncanceled, unacknowledged, sent_at PRESENT
        is returned."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-002",
            created_at="2026-09-01T00:01:00Z",
            sent_at="2026-09-01T00:02:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(1, body["count"])
        self.assertEqual(1, len(body["items"]))

    def test_acknowledged_excluded(self):
        """Test 3: acknowledged notifications are excluded."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-003",
            created_at="2026-09-01T00:00:00Z",
            acknowledged_at="2026-09-01T01:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(0, body["count"])
        self.assertEqual([], body["items"])

    def test_canceled_excluded(self):
        """Test 4: canceled notifications are excluded."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-004",
            created_at="2026-09-01T00:00:00Z",
            canceled_at="2026-09-01T01:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(0, body["count"])
        self.assertEqual([], body["items"])

    def test_run_status_pending_excluded(self):
        """Test 5: pending run status is excluded."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-002", "pending")
        _insert_notification(
            db_conn,
            "notif-005",
            run_id="run-002",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(0, body["count"])
        self.assertEqual([], body["items"])

    def test_run_status_aborted_excluded(self):
        """Test 6: aborted run status is excluded."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-003", "aborted")
        _insert_notification(
            db_conn,
            "notif-006",
            run_id="run-003",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(0, body["count"])
        self.assertEqual([], body["items"])

    def test_ordering_by_created_at_asc_and_notification_id_asc(self):
        """Test 7: ordering is created_at ASC then notification_id ASC."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")

        # Insert in reverse order to verify sorting
        _insert_notification(
            db_conn,
            "notif-007b",
            created_at="2026-09-01T00:02:00Z",
        )
        _insert_notification(
            db_conn,
            "notif-007a",
            created_at="2026-09-01T00:00:00Z",
        )
        _insert_notification(
            db_conn,
            "notif-007c",
            created_at="2026-09-01T00:02:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertEqual(3, body["count"])

        # Decrypt and verify order
        items = body["items"]
        inner0 = self._decrypt_envelope(items[0])
        inner1 = self._decrypt_envelope(items[1])
        inner2 = self._decrypt_envelope(items[2])

        self.assertEqual("notif-007a", inner0["notification_id"])
        self.assertEqual("notif-007b", inner1["notification_id"])
        self.assertEqual("notif-007c", inner2["notification_id"])

    def test_zero_rows_returns_200_count_0_items_empty(self):
        """Test 8: empty result returns 200 with count 0 and empty items."""
        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(0, body["count"])
        self.assertEqual([], body["items"])

    def test_missing_tailscale_identity_returns_403(self):
        """Test 9: missing Tailscale identity returns 403."""
        status, body = self._get_recovery(headers={})
        self.assertEqual(403, status)
        self.assertFalse(body["ok"])
        self.assertIn("error", body)

    def test_unknown_route_returns_404(self):
        """Test 10: unknown route returns 404."""
        status, body, cache_control = self._get_unknown_route()
        self.assertEqual(404, status)
        self.assertFalse(body["ok"])
        self.assertEqual("no-store", cache_control)

    def test_health_endpoint_unchanged(self):
        """Test 11: GET /health remains unchanged."""
        status, body = self._get_health()
        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual("personal-admin-ack", body["service"])

    def test_each_success_item_has_exact_keys(self):
        """Test 12: each success item has exactly v, kid, nonce, ciphertext."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-012",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        for item in body["items"]:
            self.assertEqual(
                {"v", "kid", "nonce", "ciphertext"},
                set(item),
            )

    def test_response_contains_no_plaintext_sentinel(self):
        """Test 13: HTTP response does not contain plaintext title, message,
        or ack_token."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-013",
            title="secret-title-013",
            message="secret-message-013",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body, raw, _ = self._get_recovery_raw(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertNotIn("secret-title-013", raw)
        self.assertNotIn("secret-message-013", raw)
        self.assertNotIn("ack-notif-013", raw)

    def test_envelope_decrypts_into_correct_inner_payload(self):
        """Test 14: envelope decrypts into correct inner payload using
        controlled test key."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-014",
            level="important",
            title="Payload title",
            message="Payload message",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        inner = self._decrypt_envelope(body["items"][0])
        self.assertEqual("1", inner["protocol"])
        self.assertEqual("notif-014", inner["notification_id"])
        self.assertEqual("important", inner["level"])
        self.assertEqual("Payload title", inner["title"])
        self.assertEqual("Payload message", inner["message"])
        self.assertEqual(
            "2026-09-01T00:00:00Z", inner["created_at"]
        )
        self.assertEqual("ack-notif-014", inner["ack_token"])

    def test_same_notification_retrieved_twice_produces_fresh_nonce_ciphertext(
        self,
    ):
        """Test 15: same notification retrieved twice produces fresh
        nonce/ciphertext."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-015",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status1, body1 = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )
            status2, body2 = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status1)
        self.assertEqual(200, status2)
        self.assertNotEqual(
            body1["items"][0]["nonce"],
            body2["items"][0]["nonce"],
        )
        self.assertNotEqual(
            body1["items"][0]["ciphertext"],
            body2["items"][0]["ciphertext"],
        )

    def test_exactly_200_pending_returns_200_with_200_items(self):
        """Test 16: exactly 200 pending returns 200 with 200 items."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")

        for i in range(200):
            _insert_notification(
                db_conn,
                f"notif-16-{i:04d}",
                created_at=f"2026-09-01T{i // 60:02d}:{i % 60:02d}:00Z",
            )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(200, body["count"])
        self.assertEqual(200, len(body["items"]))

    def test_201_pending_returns_409_too_many_pending(self):
        """Test 17: 201 pending returns 409 too_many_pending with no items."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")

        for i in range(201):
            _insert_notification(
                db_conn,
                f"notif-17-{i:04d}",
                created_at=f"2026-09-01T{i // 60:02d}:{i % 60:02d}:00Z",
            )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(409, status)
        self.assertFalse(body["ok"])
        self.assertEqual("too_many_pending", body["error"])

    def test_cache_control_no_store_on_success(self):
        """Test 18a: Cache-Control: no-store on 200 success."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-18a",
            created_at="2026-09-01T00:00:00Z",
        )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body, raw, cache_control = self._get_recovery_raw(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertEqual("no-store", cache_control)

    def test_cache_control_no_store_on_403(self):
        """Test 18b: Cache-Control: no-store on 403."""
        status, body, raw, cache_control = self._get_recovery_raw(
            headers={}
        )
        self.assertEqual(403, status)
        self.assertEqual("no-store", cache_control)

    def test_cache_control_no_store_on_409(self):
        """Test 18c: Cache-Control: no-store on 409."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")

        for i in range(201):
            _insert_notification(
                db_conn,
                f"notif-18c-{i:04d}",
                created_at=f"2026-09-01T{i // 60:02d}:{i % 60:02d}:00Z",
            )

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body, raw, cache_control = self._get_recovery_raw(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(409, status)
        self.assertEqual("no-store", cache_control)

    def test_read_only_guard_no_db_mutation(self):
        """Test 19: GET /notifications/pending does not mutate the DB."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-019",
            created_at="2026-09-01T00:00:00Z",
            sent_at="2026-09-01T00:01:00Z",
        )

        # Snapshot before
        before = db_conn.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            ("notif-019",),
        ).fetchone()
        before_dict = dict(before)

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)

        # Snapshot after
        after = db_conn.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            ("notif-019",),
        ).fetchone()
        after_dict = dict(after)

        self.assertEqual(before_dict, after_dict)
        db_conn.close()

    def test_build_envelope_failure_returns_500_no_partial_response(self):
        """Test 20: build_envelope failure returns 500 sanitized, no
        partial response, DB unchanged."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-020",
            title="Unencipherable",
            message="Secret",
            created_at="2026-09-01T00:00:00Z",
        )

        call_count = [0]

        def failing_build_envelope(row, key=None):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ValueError(
                    "poison row: cannot encrypt"
                )
            return fcm_sender.build_envelope(row, key)

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            with patch.object(
                fcm_sender,
                "build_envelope",
                side_effect=failing_build_envelope,
            ):
                status, body = self._get_recovery(
                    headers={
                        "Tailscale-User-Login": "user@example.com"
                    }
                )

        self.assertEqual(500, status)
        self.assertFalse(body["ok"])
        self.assertEqual(
            "internal recovery failure", body["error"]
        )
        self.assertNotIn("items", body)
        self.assertNotIn("poison", body["error"])
        self.assertNotIn("Unencipherable", body["error"])

        # Verify DB unchanged
        db_conn2 = sqlite3.connect(self.db_file)
        db_conn2.row_factory = sqlite3.Row
        row = db_conn2.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            ("notif-020",),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertIsNone(row["acknowledged_at"])
        self.assertIsNone(row["canceled_at"])
        db_conn2.close()

    def test_recovery_read_only_leaves_journal_mode_and_rows_unchanged(self):
        """Test 22: recovery against a non-WAL DB leaves its journal_mode
        and logical rows untouched, proving the read-only connection never
        runs PRAGMA journal_mode=WAL."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-022",
            created_at="2026-09-01T00:00:00Z",
            sent_at="2026-09-01T00:01:00Z",
        )

        mode_before = db_conn.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]
        rows_before = db_conn.execute(
            "SELECT * FROM notifications ORDER BY notification_id"
        ).fetchall()
        db_conn.close()

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertEqual(1, body["count"])

        db_conn2 = sqlite3.connect(self.db_file)
        db_conn2.row_factory = sqlite3.Row
        mode_after = db_conn2.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]
        rows_after = db_conn2.execute(
            "SELECT * FROM notifications ORDER BY notification_id"
        ).fetchall()
        db_conn2.close()

        self.assertEqual(mode_before, mode_after)
        self.assertNotEqual("wal", mode_after.lower())
        self.assertEqual(
            [dict(r) for r in rows_before],
            [dict(r) for r in rows_after],
        )
        self.assertFalse(
            Path(str(self.db_file) + "-wal").exists()
        )

    def test_connect_read_only_rejects_writes_and_ddl(self):
        """Test 22a: the recovery connection itself rejects INSERT/DDL,
        i.e. the read-only guarantee is enforced by SQLite mode=ro."""
        _insert_run(
            sqlite3.connect(self.db_file), "run-001", "committed"
        )

        conn = ack_server.connect_read_only()
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute(
                    "INSERT INTO runs(run_id, status) VALUES (?, ?)",
                    ("run-write-attempt", "committed"),
                )
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute(
                    "CREATE TABLE nope (x TEXT)"
                )
        finally:
            conn.close()

    def test_recovery_failure_response_contains_no_secret_sentinels(self):
        """Test 23: an eligible row with sentinel title/message/ack_token is
        actually selected and enters envelope building; a failure there must
        yield a sanitized 500 that leaks none of the sentinels."""
        sentinel_title = "TITLE-SENTINEL-77f1"
        sentinel_message = "MESSAGE-SENTINEL-88f2"
        sentinel_token = "TOKEN-SENTINEL-99f3"

        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-023",
            title=sentinel_title,
            message=sentinel_message,
            ack_token=sentinel_token,
            created_at="2026-09-01T00:00:00Z",
        )
        db_conn.close()

        def fail_key_load(path=None):
            raise fcm_sender.ConfigurationError(
                "invalid_argument",
                "E2EE key file unavailable",
            )

        with patch.object(
            fcm_sender,
            "load_key_file",
            side_effect=fail_key_load,
        ):
            status, body, raw, _ = self._get_recovery_raw(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(500, status)
        self.assertFalse(body["ok"])
        self.assertEqual("internal recovery failure", body["error"])
        self.assertNotIn("items", body)
        self.assertNotIn(sentinel_title, raw)
        self.assertNotIn(sentinel_message, raw)
        self.assertNotIn(sentinel_token, raw)

    def test_real_poison_row_over_limit_returns_500_no_leak_no_mutation(self):
        """Test 24: a real eligible row whose inner payload exceeds
        MAX_INNER_PAYLOAD_BYTES drives the real compact_inner_json failure
        path through the real GET handler (build_envelope not mocked)."""
        sentinel_title = "POISON-TITLE-A1B2"
        sentinel_message_chunk = "POISON-MESSAGE-C3D4"
        sentinel_token = "POISON-TOKEN-E5F6"
        # 900 x U+96EA (CJK snow) = 2700 UTF-8 bytes, over the 2500 limit.
        message = sentinel_message_chunk + ("\u96ea" * 900)

        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        _insert_notification(
            db_conn,
            "notif-024",
            title=sentinel_title,
            message=message,
            ack_token=sentinel_token,
            created_at="2026-09-01T00:00:00Z",
        )

        # Prove the row is genuinely over the production limit on the real
        # compact_inner_json path before driving the handler.
        proof_row = db_conn.execute(
            "SELECT notification_id, level, title, message, "
            "created_at, ack_token FROM notifications "
            "WHERE notification_id = ?",
            ("notif-024",),
        ).fetchone()
        with self.assertRaises(fcm_sender.ConfigurationError):
            fcm_sender.compact_inner_json(
                fcm_sender.build_inner_payload(proof_row)
            )

        rows_before = db_conn.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            ("notif-024",),
        ).fetchall()
        db_conn.close()

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body, raw, cache_control = self._get_recovery_raw(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(500, status)
        self.assertFalse(body["ok"])
        self.assertEqual("internal recovery failure", body["error"])
        self.assertNotIn("items", body)
        self.assertEqual("no-store", cache_control)
        self.assertNotIn(sentinel_title, raw)
        self.assertNotIn(sentinel_message_chunk, raw)
        self.assertNotIn(sentinel_token, raw)

        db_conn2 = sqlite3.connect(self.db_file)
        db_conn2.row_factory = sqlite3.Row
        rows_after = db_conn2.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            ("notif-024",),
        ).fetchall()
        db_conn2.close()
        self.assertEqual(
            [dict(r) for r in rows_before],
            [dict(r) for r in rows_after],
        )

    def test_orphan_run_id_excluded_from_recovery(self):
        """Test 25: a notification whose run_id has no matching runs row is
        excluded because the recovery INNER JOIN cannot match it."""
        db_conn = sqlite3.connect(self.db_file)
        db_conn.row_factory = sqlite3.Row
        _insert_run(db_conn, "run-001", "committed")
        # Valid row that must still be returned.
        _insert_notification(
            db_conn,
            "notif-025-ok",
            created_at="2026-09-01T00:00:00Z",
        )
        # Orphan row: no runs row exists for run-orphan.  sqlite3 does not
        # enable PRAGMA foreign_keys by default, so the orphan can be
        # inserted directly with no production schema/behavior change.
        _insert_notification(
            db_conn,
            "notif-025-orphan",
            run_id="run-orphan",
            created_at="2026-09-01T00:01:00Z",
        )
        db_conn.close()

        with patch.object(
            fcm_sender, "load_key_file", return_value=TEST_KEY
        ):
            status, body = self._get_recovery(
                headers={"Tailscale-User-Login": "user@example.com"}
            )

        self.assertEqual(200, status)
        self.assertEqual(1, body["count"])
        self.assertEqual(1, len(body["items"]))
        inner = self._decrypt_envelope(body["items"][0])
        self.assertEqual("notif-025-ok", inner["notification_id"])


if __name__ == "__main__":
    unittest.main()
