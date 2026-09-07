#!/Users/eduardo/.hermes/personal-admin/.venv/bin/python

import base64
import contextlib
import json
import os
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path

import fcm_sender
import pairing_sessions
from notification_state import ACK_BASE_URL


DB_FILE = (
    Path.home()
    / ".hermes"
    / "personal-admin"
    / "personal_admin.db"
)

HOST = "127.0.0.1"
PORT = 2587

MAX_PENDING_RECOVERY_ITEMS = 200

PAIRING_CLAIM_PATH = "/pairing/claim"
PAIRING_BODY_LIMIT_BYTES = 4096
PAIRING_RATE_PER_SESSION = 10
PAIRING_RATE_GLOBAL = 60
PAIRING_RATE_WINDOW_SECONDS = 60.0
PAIRING_RETRY_AFTER_SECONDS = 60


class ClaimRateLimiter:
    """Bounded in-memory pairing-claim limiter (single process, thread-safe).

    Only failed token evaluations are counted. Counters reset when
    ack_server restarts by design: sessions are short-lived and
    high-entropy, so persistence buys nothing. Source IP is deliberately
    not used because Tailscale Serve proxies connections locally.
    """

    def __init__(
        self,
        per_session=PAIRING_RATE_PER_SESSION,
        global_limit=PAIRING_RATE_GLOBAL,
        window_seconds=PAIRING_RATE_WINDOW_SECONDS,
    ):
        self._per_session = per_session
        self._global_limit = global_limit
        self._window = window_seconds
        self._lock = threading.Lock()
        self._session_failures = {}
        self._global_window_start = None
        self._global_count = 0

    def _prune_locked(self, now):
        expired_keys = [
            key
            for key, (start, _)
            in self._session_failures.items()
            if now - start >= self._window
        ]
        for key in expired_keys:
            del self._session_failures[key]
        if (
            self._global_window_start is not None
            and now - self._global_window_start >= self._window
        ):
            self._global_window_start = None
            self._global_count = 0

    def limited(self, session_key):
        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            entry = self._session_failures.get(session_key)
            if entry is not None and entry[1] >= self._per_session:
                return True
            return self._global_count >= self._global_limit

    def note_failure(self, session_key):
        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            start, count = self._session_failures.get(
                session_key, (now, 0)
            )
            self._session_failures[session_key] = (start, count + 1)
            if self._global_window_start is None:
                self._global_window_start = now
                self._global_count = 0
            self._global_count += 1

    def reset(self):
        """Clear all counters. Used by tests only."""
        with self._lock:
            self._session_failures = {}
            self._global_window_start = None
            self._global_count = 0


_claim_rate_limiter = ClaimRateLimiter()


def write_fid_file_atomic(candidate):
    """Atomically replace the FID file with one validated line.

    The previous file is preserved byte-for-byte on any failure.
    Raises OSError or ConfigurationError without exposing file contents.
    """

    fid_path = fcm_sender.FID_FILE
    directory = fid_path.parent
    fd, tmp_name = tempfile.mkstemp(
        dir=str(directory),
        prefix=".ackline-fid.",
        suffix=".tmp",
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as tmp:
            tmp.write(candidate + "\n")
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, fid_path)
        os.chmod(fid_path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def connect_read_only():
    """Strictly read-only connection used by the recovery endpoint only.

    Opens the same production DB path via a SQLite URI with mode=ro, so SQLite
    itself rejects any INSERT/UPDATE/DELETE/DDL on this connection.  Unlike
    connect(), it never executes PRAGMA journal_mode, preserving the DB's
    existing journal mode.
    """

    conn = sqlite3.connect(
        f"file:{DB_FILE}?mode=ro",
        uri=True,
    )
    conn.row_factory = sqlite3.Row
    return conn


class Handler(BaseHTTPRequestHandler):
    server_version = "PersonalAdminAck/1.0"

    def log_message(self, fmt, *args):
        print(
            "%s - %s"
            % (
                self.address_string(),
                fmt % args,
            )
        )

    def json_response(
        self,
        status,
        payload,
        extra_headers=None,
    ):
        body = json.dumps(
            payload,
            ensure_ascii=False,
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header(
            "Cache-Control",
            "no-store",
        )
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.json_response(
                200,
                {
                    "ok": True,
                    "service": "personal-admin-ack",
                },
            )
            return

        if self.path == "/notifications/pending":
            self._handle_pending_recovery()
            return

        self.json_response(
            404,
            {"ok": False},
        )

    def _handle_pending_recovery(self):
        """Read-only recovery endpoint returning pending notifications as
        encrypted envelopes.

        Authorization reuses the same Tailscale identity boundary as the
        ACK endpoint.  No DB mutations occur.
        """

        tailscale_user = self.headers.get(
            "Tailscale-User-Login"
        )

        if not tailscale_user:
            self.json_response(
                403,
                {
                    "ok": False,
                    "error": "Tailscale identity required",
                },
            )
            return

        # Any connect/query failure is answered with the same sanitized 500
        # instead of aborting the HTTP connection, and the read-only
        # connection is always closed once opened, including on failure.
        try:
            with contextlib.closing(
                connect_read_only()
            ) as conn:
                rows = conn.execute(
                    """
                    SELECT n.notification_id,
                           n.level,
                           n.title,
                           n.message,
                           n.created_at,
                           n.ack_token
                    FROM notifications n
                    JOIN runs r
                      ON r.run_id = n.run_id
                    WHERE n.canceled_at IS NULL
                      AND n.acknowledged_at IS NULL
                      AND r.status = 'committed'
                    ORDER BY n.created_at ASC,
                             n.notification_id ASC
                    LIMIT ?
                    """,
                    (MAX_PENDING_RECOVERY_ITEMS + 1,),
                ).fetchall()
        except Exception:
            self.json_response(
                500,
                {
                    "ok": False,
                    "error": "internal recovery failure",
                },
            )
            return

        if len(rows) > MAX_PENDING_RECOVERY_ITEMS:
            self.json_response(
                409,
                {
                    "ok": False,
                    "error": "too_many_pending",
                },
            )
            return

        # Load the E2EE key exactly once for the batch; any key-load or
        # envelope failure still yields the sanitized 500 with no partial
        # success.  Details are never logged.
        items = []
        if rows:
            try:
                key = fcm_sender.load_key_file()
                for row in rows:
                    items.append(
                        fcm_sender.build_envelope(row, key=key)
                    )
            except Exception:
                self.json_response(
                    500,
                    {
                        "ok": False,
                        "error": "internal recovery failure",
                    },
                )
                return

        self.json_response(
            200,
            {
                "ok": True,
                "count": len(items),
                "items": items,
            },
        )

    def do_POST(self):
        if self.path.split("?", 1)[0] == PAIRING_CLAIM_PATH:
            self._handle_pairing_claim()
            return

        prefix = "/ack/"

        if not self.path.startswith(prefix):
            self.json_response(
                404,
                {"ok": False},
            )
            return

        notification_id = (
            self.path[len(prefix):]
            .split("?", 1)[0]
            .strip()
        )

        token = self.headers.get(
            "X-Ack-Token",
            "",
        )

        # This header is injected by Tailscale Serve.
        tailscale_user = self.headers.get(
            "Tailscale-User-Login"
        )

        if not tailscale_user:
            self.json_response(
                403,
                {
                    "ok": False,
                    "error":
                        "Tailscale identity required",
                },
            )
            return

        conn = connect()

        row = conn.execute(
            """
            SELECT ack_token,
                   acknowledged_at
            FROM notifications
            WHERE notification_id = ?
            """,
            (notification_id,),
        ).fetchone()

        if not row:
            self.json_response(
                404,
                {
                    "ok": False,
                    "error":
                        "notification not found",
                },
            )
            return

        if not token or token != row["ack_token"]:
            self.json_response(
                403,
                {
                    "ok": False,
                    "error": "invalid token",
                },
            )
            return

        if row["acknowledged_at"]:
            self.json_response(
                200,
                {
                    "ok": True,
                    "already_acknowledged":
                        True,
                },
            )
            return

        timestamp = now()

        conn.execute(
            """
            UPDATE notifications
            SET acknowledged_at = ?,
                acknowledged_by = ?
            WHERE notification_id = ?
              AND acknowledged_at IS NULL
            """,
            (
                timestamp,
                tailscale_user,
                notification_id,
            ),
        )

        conn.commit()

        self.json_response(
            200,
            {
                "ok": True,
                "acknowledged": True,
                "acknowledged_at":
                    timestamp,
            },
        )

    def _handle_pairing_claim(self):
        """One-time pairing claim: authorized FID write + key release.

        Ordering is pre-consume validation (request shape, FID shape,
        E2EE key load, token/expiry/consume state, fresh/replace
        permission) and only then atomic consume, FID write, and the
        single key-bearing response. Nothing carrying key material,
        token material, or FID contents is ever logged.
        """

        tailscale_user = self.headers.get(
            "Tailscale-User-Login"
        )

        if not tailscale_user:
            self.json_response(
                403,
                {
                    "ok": False,
                    "error":
                        "tailscale_identity_required",
                },
            )
            return

        try:
            content_length = int(
                self.headers.get("Content-Length") or 0
            )
        except (TypeError, ValueError):
            content_length = 0

        if (
            content_length <= 0
            or content_length > PAIRING_BODY_LIMIT_BYTES
        ):
            self.json_response(
                400,
                {
                    "ok": False,
                    "error": "invalid_request",
                },
            )
            return

        try:
            raw_body = self.rfile.read(content_length)
        except Exception:
            self.json_response(
                400,
                {
                    "ok": False,
                    "error": "invalid_request",
                },
            )
            return

        try:
            request_body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self.json_response(
                400,
                {
                    "ok": False,
                    "error": "invalid_request",
                },
            )
            return

        if not isinstance(request_body, dict):
            self.json_response(
                400,
                {
                    "ok": False,
                    "error": "invalid_request",
                },
            )
            return

        session_id = request_body.get("session_id")
        token = request_body.get("token")
        fid = request_body.get("fid")

        if (
            not isinstance(session_id, str)
            or not session_id
            or not isinstance(token, str)
            or not token
            or not isinstance(fid, str)
            or not fid
        ):
            self.json_response(
                400,
                {
                    "ok": False,
                    "error": "invalid_request",
                },
            )
            return

        rate_key = session_id[:128]
        if _claim_rate_limiter.limited(rate_key):
            self.json_response(
                429,
                {
                    "ok": False,
                    "error": "rate_limited",
                },
                extra_headers={
                    "Retry-After": str(
                        PAIRING_RETRY_AFTER_SECONDS
                    ),
                },
            )
            return

        try:
            candidate_fid = fcm_sender.validate_fid_candidate(fid)
        except Exception:
            self.json_response(
                400,
                {
                    "ok": False,
                    "error": "invalid_request",
                },
            )
            return

        try:
            key = fcm_sender.load_key_file()
        except Exception:
            self.json_response(
                500,
                {
                    "ok": False,
                    "error": "server_misconfigured",
                },
            )
            return

        try:
            stored_fid = fcm_sender.load_fid_file()
        except Exception:
            stored_fid = None

        verified, verify_info = pairing_sessions.verify_session(
            session_id, token
        )
        if not verified:
            _claim_rate_limiter.note_failure(rate_key)
            self.json_response(
                403,
                {
                    "ok": False,
                    "error": verify_info,
                },
            )
            return

        if (
            verify_info["intent"] == "fresh"
            and stored_fid is not None
            and stored_fid != candidate_fid
        ):
            self.json_response(
                409,
                {
                    "ok": False,
                    "error": "replace_required",
                },
            )
            return

        consumed, consume_info = pairing_sessions.consume_session(
            session_id, token
        )
        if not consumed:
            _claim_rate_limiter.note_failure(rate_key)
            self.json_response(
                403,
                {
                    "ok": False,
                    "error": consume_info,
                },
            )
            return

        if stored_fid != candidate_fid:
            try:
                write_fid_file_atomic(candidate_fid)
            except Exception:
                self.json_response(
                    500,
                    {
                        "ok": False,
                        "error": "server_misconfigured",
                    },
                )
                return

        self.json_response(
            200,
            {
                "ok": True,
                "kid": fcm_sender.KID,
                "e2ee_key_b64": base64.b64encode(key).decode(
                    "ascii"
                ),
                "ack_base_url": ACK_BASE_URL,
            },
        )


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        (HOST, PORT),
        Handler,
    )

    print(
        f"Personal Admin ACK listening on "
        f"http://{HOST}:{PORT}"
    )

    server.serve_forever()
