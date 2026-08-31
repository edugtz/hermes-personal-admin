#!/Users/eduardo/.hermes/personal-admin/.venv/bin/python

import json
import sqlite3
from datetime import datetime, timezone
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path


DB_FILE = (
    Path.home()
    / ".hermes"
    / "personal-admin"
    / "personal_admin.db"
)

HOST = "127.0.0.1"
PORT = 2587


def now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
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

        self.json_response(
            404,
            {"ok": False},
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
