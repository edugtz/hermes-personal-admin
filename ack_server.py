#!/Users/eduardo/.hermes/personal-admin/.venv/bin/python

import contextlib
import json
import sqlite3
from datetime import datetime, timezone
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path

import fcm_sender


DB_FILE = (
    Path.home()
    / ".hermes"
    / "personal-admin"
    / "personal_admin.db"
)

HOST = "127.0.0.1"
PORT = 2587

MAX_PENDING_RECOVERY_ITEMS = 200


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
