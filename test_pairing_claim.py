#!/usr/bin/env python3
"""Tests for pairing-session issuance and POST /pairing/claim (P2A-H1).

Focused pairing tests, kept separate from the recovery suite. No real FCM
message is ever sent here; all key/FID material below uses fake sentinels.
"""

import base64
import hashlib
import io
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Barrier, Thread
from unittest.mock import patch

import ack_server
import fcm_sender
import pairing_sessions


TEST_KEY = bytes(range(32))
TEST_PORT = 2589

SENTINEL_FID_A = "test-fid-alpha-001"
SENTINEL_FID_B = "test-fid-beta-002"


class _ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class PairingClaimTest(unittest.TestCase):
    """Test the pairing-session store, CLI shape, and claim endpoint."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.pairing_db = Path(self.directory.name) / "pairing.db"
        self.fid_file = Path(self.directory.name) / "ackline-fid"

        self.pairing_db_patch = patch.object(
            pairing_sessions, "PAIRING_DB_FILE", self.pairing_db
        )
        self.fid_patch = patch.object(
            fcm_sender, "FID_FILE", self.fid_file
        )
        self.key_patch = patch.object(
            fcm_sender,
            "load_key_file",
            lambda path=None: TEST_KEY,
        )
        self.ack_url_patch = patch.object(
            ack_server,
            "ACK_BASE_URL",
            "https://hermes.example:8443",
        )
        self.pairing_db_patch.start()
        self.fid_patch.start()
        self.key_patch.start()
        self.ack_url_patch.start()
        ack_server._claim_rate_limiter.reset()

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
        ack_server._claim_rate_limiter.reset()
        self.ack_url_patch.stop()
        self.key_patch.stop()
        self.fid_patch.stop()
        self.pairing_db_patch.stop()
        self.directory.cleanup()

    # -- helpers ------------------------------------------------------

    def _post_claim(self, payload=None, raw=None, headers=None):
        conn = HTTPConnection("127.0.0.1", TEST_PORT)
        default_headers = {
            "Host": "127.0.0.1:2587",
            "Content-Type": "application/json",
            "Tailscale-User-Login": "operator@example.com",
        }
        if headers is not None:
            default_headers.update(headers)
        body = raw if raw is not None else json.dumps(payload).encode()
        conn.request("POST", "/pairing/claim", body=body, headers=default_headers)
        response = conn.getresponse()
        raw_body = response.read().decode("utf-8")
        result = (
            response.status,
            json.loads(raw_body),
            {
                "cache_control": response.getheader("Cache-Control"),
                "retry_after": response.getheader("Retry-After"),
            },
        )
        conn.close()
        return result

    def _issue(self, intent="fresh", ttl_minutes=10):
        return pairing_sessions.issue_session(
            intent=intent, ttl_minutes=ttl_minutes
        )

    def _claim(self, session, fid=SENTINEL_FID_A):
        return self._post_claim(
            {
                "session_id": session["session_id"],
                "token": session["token"],
                "fid": fid,
            }
        )

    # -- issuance / store ---------------------------------------------

    def test_begin_stores_hash_not_token(self):
        session = self._issue()
        token = session["token"]
        self.assertTrue(token)

        raw_db = self.pairing_db.read_bytes()
        self.assertNotIn(token.encode("utf-8"), raw_db)

        conn = sqlite3.connect(self.pairing_db)
        try:
            row = conn.execute(
                "SELECT token_hash FROM pairing_sessions WHERE session_id = ?",
                (session["session_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(
            bytes(row[0]), hashlib.sha256(token.encode("utf-8")).digest()
        )
        mode = stat.S_IMODE(os.stat(self.pairing_db).st_mode)
        self.assertEqual(mode, 0o600)

    def test_default_ttl_is_10_minutes(self):
        session = self._issue()
        created = datetime.fromisoformat(session["created_at"])
        expires = datetime.fromisoformat(session["expires_at"])
        self.assertEqual(session["ttl_seconds"], 600)
        self.assertEqual((expires - created).total_seconds(), 600)

    def test_ttl_bounds_enforced(self):
        for bad_ttl in (0, 1, 4, 31, 60, -5):
            with self.assertRaises(ValueError):
                pairing_sessions.issue_session(ttl_minutes=bad_ttl)
        for ok_ttl in (5, 10, 30):
            session = pairing_sessions.issue_session(ttl_minutes=ok_ttl)
            self.assertEqual(session["ttl_seconds"], ok_ttl * 60)
        with self.assertRaises(ValueError):
            pairing_sessions.issue_session(intent="bogus")

    def test_revoke(self):
        session = self._issue()
        self.assertTrue(
            pairing_sessions.revoke_session(session["session_id"])
        )
        # Idempotent: revoking again still reports the session.
        self.assertTrue(
            pairing_sessions.revoke_session(session["session_id"])
        )
        self.assertFalse(pairing_sessions.revoke_session("no-such-session"))

    def test_cli_begin_output_contract(self):
        import argparse

        import notification_state

        args = argparse.Namespace(replace=False, ttl_minutes=10)
        captured = io.StringIO()
        with redirect_stdout(captured):
            notification_state.cmd_pairing_begin(args)
        envelope = json.loads(captured.getvalue())
        self.assertTrue(envelope["ok"])
        self.assertEqual(envelope["intent"], "fresh")
        self.assertEqual(envelope["ttl_seconds"], 600)
        self.assertEqual(envelope["claim_path"], "/pairing/claim")
        self.assertTrue(envelope["token"])
        self.assertTrue(envelope["session_id"])
        raw_db = self.pairing_db.read_bytes()
        self.assertNotIn(envelope["token"].encode("utf-8"), raw_db)

    def test_cli_ttl_out_of_range_exits_nonzero(self):
        import argparse

        import notification_state

        args = argparse.Namespace(replace=False, ttl_minutes=45)
        with self.assertRaises(SystemExit):
            notification_state.cmd_pairing_begin(args)

    # -- successful claims --------------------------------------------

    def test_valid_fresh_claim_no_existing_fid(self):
        session = self._issue()
        self.assertFalse(self.fid_file.exists())

        status, body, headers = self._claim(session)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["kid"], fcm_sender.KID)
        assert body["ack_base_url"].startswith(
            "https://"
        ), "ack_base_url must be an https URL"
        self.assertEqual(base64.b64decode(body["e2ee_key_b64"]), TEST_KEY)
        self.assertEqual(headers["cache_control"], "no-store")

        self.assertEqual(
            self.fid_file.read_text(encoding="utf-8"),
            SENTINEL_FID_A + "\n",
        )
        mode = stat.S_IMODE(os.stat(self.fid_file).st_mode)
        self.assertEqual(mode, 0o600)

    def test_fresh_claim_same_fid_idempotent_success(self):
        self.fid_file.write_text(SENTINEL_FID_A + "\n", encoding="utf-8")
        before = self.fid_file.read_bytes()

        session = self._issue(intent="fresh")
        status, body, _ = self._claim(session, fid=SENTINEL_FID_A)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.fid_file.read_bytes(), before)

    def test_fresh_claim_differing_fid_rejected_session_preserved(self):
        self.fid_file.write_text(SENTINEL_FID_A + "\n", encoding="utf-8")
        before = self.fid_file.read_bytes()

        session = self._issue(intent="fresh")
        status, body, _ = self._claim(session, fid=SENTINEL_FID_B)
        self.assertEqual(status, 409)
        self.assertEqual(
            body, {"ok": False, "error": "replace_required"}
        )
        self.assertEqual(self.fid_file.read_bytes(), before)

        verified, _ = pairing_sessions.verify_session(
            session["session_id"], session["token"]
        )
        self.assertTrue(verified)

    def test_replace_claim_differing_fid_success(self):
        self.fid_file.write_text(SENTINEL_FID_A + "\n", encoding="utf-8")

        session = self._issue(intent="replace")
        status, body, _ = self._claim(session, fid=SENTINEL_FID_B)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(
            self.fid_file.read_text(encoding="utf-8"),
            SENTINEL_FID_B + "\n",
        )

    # -- token failures ------------------------------------------------

    def test_invalid_token(self):
        session = self._issue()
        status, body, _ = self._post_claim(
            {
                "session_id": session["session_id"],
                "token": "wrong-token-value",
                "fid": SENTINEL_FID_A,
            }
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, {"ok": False, "error": "invalid"})
        self.assertFalse(self.fid_file.exists())

    def test_unknown_session_indistinguishable_from_invalid_token(self):
        session = self._issue()
        bad_status, bad_body, _ = self._post_claim(
            {
                "session_id": session["session_id"],
                "token": "wrong-token-value",
                "fid": SENTINEL_FID_A,
            }
        )
        unknown_status, unknown_body, _ = self._post_claim(
            {
                "session_id": "0" * 32,
                "token": "wrong-token-value",
                "fid": SENTINEL_FID_A,
            }
        )
        self.assertEqual((unknown_status, unknown_body), (bad_status, bad_body))
        self.assertEqual(unknown_status, 403)
        self.assertEqual(unknown_body, {"ok": False, "error": "invalid"})

    def test_expired(self):
        session = self._issue()
        conn = sqlite3.connect(self.pairing_db)
        try:
            conn.execute(
                "UPDATE pairing_sessions SET expires_at = ? WHERE session_id = ?",
                (
                    "2000-01-01T00:00:00+00:00",
                    session["session_id"],
                ),
            )
            conn.commit()
        finally:
            conn.close()

        status, body, _ = self._claim(session)
        self.assertEqual(status, 403)
        self.assertEqual(body, {"ok": False, "error": "expired"})

    def test_consumed_replay(self):
        session = self._issue()
        status, _, _ = self._claim(session)
        self.assertEqual(status, 200)

        status, body, _ = self._claim(session)
        self.assertEqual(status, 403)
        self.assertEqual(body, {"ok": False, "error": "consumed"})

    def test_revoked_replay(self):
        session = self._issue()
        self.assertTrue(
            pairing_sessions.revoke_session(session["session_id"])
        )
        status, body, _ = self._claim(session)
        self.assertEqual(status, 403)
        self.assertEqual(body, {"ok": False, "error": "consumed"})

    def test_concurrent_double_claim_exactly_one_success(self):
        session = self._issue()
        payload = {
            "session_id": session["session_id"],
            "token": session["token"],
            "fid": SENTINEL_FID_A,
        }
        barrier = Barrier(3)
        statuses = []

        def _claim_once():
            barrier.wait()
            conn = HTTPConnection("127.0.0.1", TEST_PORT)
            conn.request(
                "POST",
                "/pairing/claim",
                body=json.dumps(payload).encode(),
                headers={
                    "Host": "127.0.0.1:2587",
                    "Content-Type": "application/json",
                    "Tailscale-User-Login": "operator@example.com",
                },
            )
            statuses.append(conn.getresponse().status)
            conn.close()

        workers = [Thread(target=_claim_once) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=10.0)
        self.assertEqual(sorted(statuses), [200, 403])

    # -- request shape / identity --------------------------------------

    def test_malformed_requests(self):
        session = self._issue()
        valid = {
            "session_id": session["session_id"],
            "token": session["token"],
            "fid": SENTINEL_FID_A,
        }
        cases = [
            {"payload": None, "raw": b""},
            {"payload": None, "raw": b"not-json"},
            {"payload": None, "raw": b"[1, 2]"},
            {"payload": {"token": "x", "fid": SENTINEL_FID_A}},
            {"payload": {**valid, "fid": ""}},
            {"payload": {**valid, "fid": "  padded  "}},
            {"payload": {**valid, "fid": "two\nlines"}},
        ]
        for case in cases:
            status, body, _ = self._post_claim(
                payload=case.get("payload"), raw=case.get("raw")
            )
            self.assertEqual(status, 400, msg="case: %r" % (case,))
            self.assertEqual(body, {"ok": False, "error": "invalid_request"})
        oversized = b"x" * (ack_server.PAIRING_BODY_LIMIT_BYTES + 1)
        conn = HTTPConnection("127.0.0.1", TEST_PORT)
        conn.request(
            "POST",
            "/pairing/claim",
            body=oversized,
            headers={
                "Host": "127.0.0.1:2587",
                "Content-Type": "application/json",
                "Tailscale-User-Login": "operator@example.com",
            },
        )
        response = conn.getresponse()
        response.read()
        self.assertEqual(response.status, 400)
        conn.close()

    def test_missing_tailscale_identity(self):
        session = self._issue()
        conn = HTTPConnection("127.0.0.1", TEST_PORT)
        conn.request(
            "POST",
            "/pairing/claim",
            body=json.dumps(
                {
                    "session_id": session["session_id"],
                    "token": session["token"],
                    "fid": SENTINEL_FID_A,
                }
            ).encode(),
            headers={
                "Host": "127.0.0.1:2587",
                "Content-Type": "application/json",
            },
        )
        response = conn.getresponse()
        body = json.loads(response.read().decode("utf-8"))
        cache_control = response.getheader("Cache-Control")
        conn.close()
        self.assertEqual(response.status, 403)
        self.assertEqual(
            body, {"ok": False, "error": "tailscale_identity_required"}
        )
        self.assertEqual(cache_control, "no-store")

    # -- failure preservation ------------------------------------------

    def test_missing_key_does_not_consume_session(self):
        session = self._issue()
        with patch.object(
            fcm_sender,
            "load_key_file",
            side_effect=fcm_sender.ConfigurationError(
                "invalid_argument", "E2EE key file unavailable"
            ),
        ):
            status, body, _ = self._claim(session)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"ok": False, "error": "server_misconfigured"})
        self.assertFalse(self.fid_file.exists())

        verified, _ = pairing_sessions.verify_session(
            session["session_id"], session["token"]
        )
        self.assertTrue(verified)

    def test_fid_write_failure_preserves_previous_no_key(self):
        old_fid_path = Path(self.directory.name) / "old-fid"
        old_fid_path.write_text(SENTINEL_FID_A + "\n", encoding="utf-8")
        with patch.object(
            fcm_sender, "FID_FILE", Path(self.directory.name) / "no-dir" / "fid"
        ):
            session = self._issue(intent="replace")
            status, body, _ = self._claim(session, fid=SENTINEL_FID_B)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"ok": False, "error": "server_misconfigured"})
        self.assertNotIn("e2ee_key_b64", body)
        self.assertEqual(
            old_fid_path.read_text(encoding="utf-8"), SENTINEL_FID_A + "\n"
        )

    # -- headers / rate limit / persistence / leakage -------------------

    def test_cache_control_no_store_everywhere(self):
        session_ok = self._issue()
        status, _, headers = self._claim(session_ok)
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache_control"], "no-store")

        session_bad = self._issue()
        _, _, bad_headers = self._post_claim(
            {
                "session_id": session_bad["session_id"],
                "token": "wrong",
                "fid": SENTINEL_FID_A,
            }
        )
        self.assertEqual(bad_headers["cache_control"], "no-store")

        self.fid_file.write_text(SENTINEL_FID_A + "\n", encoding="utf-8")
        session_conflict = self._issue(intent="fresh")
        _, _, conflict_headers = self._claim(
            session_conflict, fid=SENTINEL_FID_B
        )
        self.assertEqual(conflict_headers["cache_control"], "no-store")

    def test_rate_limit_returns_429_with_retry_after(self):
        session = self._issue()
        bad_payload = {
            "session_id": session["session_id"],
            "token": "wrong-token-value",
            "fid": SENTINEL_FID_A,
        }
        for _ in range(ack_server.PAIRING_RATE_PER_SESSION):
            status, _, _ = self._post_claim(bad_payload)
            self.assertEqual(status, 403)
        status, body, headers = self._post_claim(bad_payload)
        self.assertEqual(status, 429)
        self.assertEqual(body, {"ok": False, "error": "rate_limited"})
        self.assertEqual(
            headers["retry_after"],
            str(ack_server.PAIRING_RETRY_AFTER_SECONDS),
        )

    def test_session_state_survives_reopen(self):
        session = self._issue()
        verified, info = pairing_sessions.verify_session(
            session["session_id"], session["token"]
        )
        self.assertTrue(verified)
        self.assertEqual(info["intent"], "fresh")

        consumed, _ = pairing_sessions.consume_session(
            session["session_id"], session["token"]
        )
        self.assertTrue(consumed)
        verified, code = pairing_sessions.verify_session(
            session["session_id"], session["token"]
        )
        self.assertFalse(verified)
        self.assertEqual(code, "consumed")

    def test_session_db_contains_no_secrets(self):
        session = self._issue()
        self._claim(session, fid=SENTINEL_FID_A)
        raw_db = self.pairing_db.read_bytes()
        self.assertNotIn(session["token"].encode("utf-8"), raw_db)
        self.assertNotIn(SENTINEL_FID_A.encode("utf-8"), raw_db)
        self.assertNotIn(TEST_KEY, raw_db)

    def test_no_secret_sentinels_in_server_output_or_errors(self):
        session = self._issue()
        statuses_bodies = []
        captured = io.StringIO()
        with redirect_stdout(captured):
            statuses_bodies.append(self._claim(session, fid=SENTINEL_FID_A))
            statuses_bodies.append(self._claim(session, fid=SENTINEL_FID_A))
            statuses_bodies.append(
                self._post_claim(
                    {
                        "session_id": session["session_id"],
                        "token": "wrong-token-value",
                        "fid": SENTINEL_FID_A,
                    }
                )
            )
        server_output = captured.getvalue()
        expected_key_b64 = base64.b64encode(TEST_KEY).decode("ascii")

        # Failure messages below use only fixed labels and field NAMES
        # (never sentinel values, never whole bodies). A failing
        # assertion can therefore never serialize/print a pairing
        # response to stdout -- which would expose the private
        # ack_base_url.
        forbidden = {
            "bearer token": session["token"],
            "FID": SENTINEL_FID_A,
            "E2EE key material": expected_key_b64,
        }

        # Server stdout must never carry secret material.
        for label, sentinel in forbidden.items():
            assert sentinel not in server_output, (
                "server stdout must not contain the %s" % (label,)
            )

        # First response is the single authorized success: it must carry
        # the released key by design, but never echo the token or FID.
        status_ok, success_body, _ = statuses_bodies[0]
        assert status_ok == 200, "claim must succeed with HTTP 200"
        assert success_body.get("ok") is True, "success response must set ok=true"
        for field in ("kid", "e2ee_key_b64", "ack_base_url"):
            assert field in success_body, (
                "success response must include field %r" % (field,)
            )
            assert isinstance(success_body[field], str) and success_body[field], (
                "success response field %r must be a non-empty string" % (field,)
            )
        for field, value in success_body.items():
            assert session["token"] not in str(value), (
                "success response field %r must not contain the bearer token"
                % (field,)
            )
            assert SENTINEL_FID_A not in str(value), (
                "success response field %r must not contain the FID" % (field,)
            )

        # All remaining responses are rejections; they must carry no
        # token, FID, or key material in any field.
        for _, body, _ in statuses_bodies[1:]:
            assert body.get("ok") is False, "rejection response must set ok=false"
            assert "e2ee_key_b64" not in body, (
                "rejection response must not release key material"
            )
            for label, sentinel in forbidden.items():
                for field, value in body.items():
                    assert sentinel not in str(value), (
                        "rejection response field %r must not contain the %s"
                        % (field, label)
                    )


if __name__ == "__main__":
    unittest.main()
