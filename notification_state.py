#!/Users/eduardo/.hermes/personal-admin/.venv/bin/python

import argparse
import hashlib
import json
import secrets
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import fcm_sender


BASE = Path.home() / ".hermes" / "personal-admin"
DB_FILE = BASE / "personal_admin.db"
TOKEN_FILE = BASE / "ntfy" / "publisher_token"

NTFY_URL = "http://127.0.0.1:2586/"
TOPIC = "personal-admin"

ACK_BASE_URL = (
    "https://macbook-pro-de-eduardo.taildc9db9.ts.net:8443"
)

PRIORITIES = {
    "remember": 3,
    "important": 4,
    "urgent": 5,
}

ACTIVE_TRANSPORT = "fcm"
SUPPORTED_TRANSPORTS = frozenset({"ntfy", "fcm"})
INITIAL = "initial"
REDELIVERY = "redelivery"
REDELIVERY_WINDOW = timedelta(hours=6)
REDELIVERY_MINIMUM_GAP = timedelta(hours=2)


@dataclass(frozen=True)
class DispatchCandidate:
    row: sqlite3.Row
    mode: str


def now():
    return datetime.now(timezone.utc).isoformat()


def utc_now():
    return datetime.now(timezone.utc)


def parse_utc_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def redelivery_is_eligible(row, dispatch_time):
    sent_at = parse_utc_timestamp(row["sent_at"])
    last_attempt_at = parse_utc_timestamp(row["last_attempt_at"])
    if sent_at is None or last_attempt_at is None:
        return False

    sent_elapsed = dispatch_time - sent_at
    attempt_elapsed = dispatch_time - last_attempt_at
    return (
        timedelta() <= sent_elapsed <= REDELIVERY_WINDOW
        and attempt_elapsed >= REDELIVERY_MINIMUM_GAP
    )


def fail(message):
    print(
        json.dumps(
            {"ok": False, "error": message},
            ensure_ascii=False,
        ),
        file=sys.stderr,
    )
    sys.exit(1)


def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS notifications (
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

            FOREIGN KEY(run_id)
                REFERENCES runs(run_id)
        );

        CREATE INDEX IF NOT EXISTS idx_notifications_outbox
            ON notifications(sent_at, canceled_at);

        CREATE INDEX IF NOT EXISTS idx_notifications_ack
            ON notifications(acknowledged_at);
        """
    )

    conn.commit()


def run_status(conn, run_id):
    row = conn.execute(
        """
        SELECT status
        FROM runs
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()

    return row["status"] if row else None


def cmd_init(args):
    conn = connect()
    init_db(conn)

    print(
        json.dumps(
            {
                "ok": True,
                "database": str(DB_FILE),
                "notifications_ready": True,
            },
            indent=2,
        )
    )


def cmd_queue(args):
    conn = connect()
    init_db(conn)

    status = run_status(conn, args.run_id)

    if status not in {"pending", "committed"}:
        fail(
            f"Run {args.run_id} is not queueable; status={status}"
        )

    material = json.dumps(
        {
            "run_id": args.run_id,
            "level": args.level,
            "title": args.title,
            "message": args.message,
        },
        sort_keys=True,
        ensure_ascii=False,
    )

    dedupe_key = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()

    existing = conn.execute(
        """
        SELECT notification_id
        FROM notifications
        WHERE dedupe_key = ?
        """,
        (dedupe_key,),
    ).fetchone()

    if existing:
        print(
            json.dumps(
                {
                    "ok": True,
                    "already_queued": True,
                    "notification_id":
                        existing["notification_id"],
                },
                indent=2,
            )
        )
        return

    notification_id = uuid.uuid4().hex
    ack_token = secrets.token_urlsafe(32)

    # Stable ID used on ntfy retries.
    sequence_id = "pa-" + notification_id[:24]

    conn.execute(
        """
        INSERT INTO notifications(
            notification_id,
            run_id,
            dedupe_key,
            level,
            title,
            message,
            ack_token,
            ntfy_sequence_id,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            notification_id,
            args.run_id,
            dedupe_key,
            args.level,
            args.title,
            args.message,
            ack_token,
            sequence_id,
            now(),
        ),
    )

    conn.commit()

    print(
        json.dumps(
            {
                "ok": True,
                "queued": True,
                "notification_id": notification_id,
                "run_id": args.run_id,
            },
            indent=2,
        )
    )


def publish(row):
    if not TOKEN_FILE.exists():
        raise RuntimeError("publisher_token missing")

    token = TOKEN_FILE.read_text(
        encoding="utf-8"
    ).strip()

    ack_url = (
        f"{ACK_BASE_URL}/ack/"
        f"{row['notification_id']}"
    )

    payload = {
        "topic": TOPIC,
        "title": row["title"],
        "message": row["message"],
        "priority": PRIORITIES[row["level"]],
        "sequence_id": row["ntfy_sequence_id"],
        "actions": [
            {
                "action": "http",
                "label": "Visto",
                "url": ack_url,
                "method": "POST",
                "headers": {
                    "X-Ack-Token": row["ack_token"],
                },
                "clear": True,
            }
        ],
    }

    request = urllib.request.Request(
        NTFY_URL,
        data=json.dumps(
            payload,
            ensure_ascii=False,
        ).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=10,
    ) as response:
        return json.loads(
            response.read().decode("utf-8")
        )


def validate_active_transport():
    if ACTIVE_TRANSPORT not in SUPPORTED_TRANSPORTS:
        raise ValueError("unsupported active transport")


def send_transport(row, *, priority_override=None):
    validate_active_transport()
    if ACTIVE_TRANSPORT == "ntfy":
        return publish(row)
    if priority_override is None:
        return fcm_sender.send_notification(row)
    return fcm_sender.send_notification(
        row,
        priority_override=priority_override,
    )


def dispatch_candidates(conn, dispatch_time):
    initial_rows = conn.execute(
        """
        SELECT n.*
        FROM notifications n
        JOIN runs r
          ON r.run_id = n.run_id
        WHERE n.sent_at IS NULL
          AND n.canceled_at IS NULL
          AND n.acknowledged_at IS NULL
          AND r.status = 'committed'
        ORDER BY n.created_at
        """
    ).fetchall()

    candidates = [
        DispatchCandidate(row, INITIAL)
        for row in initial_rows
    ]

    if ACTIVE_TRANSPORT != "fcm":
        return candidates

    redelivery_rows = conn.execute(
        """
        SELECT n.*
        FROM notifications n
        JOIN runs r
          ON r.run_id = n.run_id
        WHERE n.sent_at IS NOT NULL
          AND n.canceled_at IS NULL
          AND n.acknowledged_at IS NULL
          AND r.status = 'committed'
        ORDER BY n.created_at
        """
    ).fetchall()

    candidates.extend(
        DispatchCandidate(row, REDELIVERY)
        for row in redelivery_rows
        if redelivery_is_eligible(row, dispatch_time)
    )
    return candidates


def cmd_dispatch(args):
    validate_active_transport()
    conn = connect()
    init_db(conn)

    candidates = dispatch_candidates(conn, utc_now())

    sent = 0
    failed = 0

    for candidate in candidates:
        row = candidate.row
        attempt_time = now()

        try:
            result = send_transport(
                row,
                priority_override=(
                    "normal"
                    if candidate.mode == REDELIVERY
                    else None
                ),
            )

            if ACTIVE_TRANSPORT == "fcm":
                if not result.accepted:
                    conn.execute(
                        """
                        UPDATE notifications
                        SET send_attempts = send_attempts + 1,
                            last_attempt_at = ?,
                            last_error = ?
                        WHERE notification_id = ?
                        """,
                        (
                            attempt_time,
                            fcm_sender.sanitized_error_marker(result)
                            or "FCM_UNKNOWN:unknown",
                            row["notification_id"],
                        ),
                    )
                    conn.commit()
                    failed += 1
                    continue

                if candidate.mode == INITIAL:
                    conn.execute(
                        """
                        UPDATE notifications
                        SET sent_at = ?,
                            send_attempts = send_attempts + 1,
                            last_attempt_at = ?,
                            last_error = NULL
                        WHERE notification_id = ?
                        """,
                        (
                            now(),
                            attempt_time,
                            row["notification_id"],
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE notifications
                        SET send_attempts = send_attempts + 1,
                            last_attempt_at = ?,
                            last_error = NULL
                        WHERE notification_id = ?
                        """,
                        (
                            attempt_time,
                            row["notification_id"],
                        ),
                    )
            else:
                conn.execute(
                    """
                    UPDATE notifications
                    SET sent_at = ?,
                        ntfy_message_id = ?,
                        send_attempts = send_attempts + 1,
                        last_attempt_at = ?,
                        last_error = NULL
                    WHERE notification_id = ?
                    """,
                    (
                        now(),
                        result.get("id"),
                        attempt_time,
                        row["notification_id"],
                    ),
                )

            conn.commit()
            sent += 1

        except Exception as exc:
            conn.execute(
                """
                UPDATE notifications
                SET send_attempts = send_attempts + 1,
                    last_attempt_at = ?,
                    last_error = ?
                WHERE notification_id = ?
                """,
                (
                    attempt_time,
                    (
                        "FCM_UNKNOWN:unknown"
                        if ACTIVE_TRANSPORT == "fcm"
                        else str(exc)[:2000]
                    ),
                    row["notification_id"],
                ),
            )

            conn.commit()
            failed += 1

    print(
        json.dumps(
            {
                "ok": failed == 0,
                "eligible": len(candidates),
                "sent": sent,
                "failed": failed,
            },
            indent=2,
        )
    )

    if failed:
        sys.exit(2)


def cmd_status(args):
    conn = connect()
    init_db(conn)

    result = {}

    queries = {
        "queued_unsent": """
            SELECT COUNT(*) c
            FROM notifications
            WHERE sent_at IS NULL
              AND canceled_at IS NULL
        """,
        "sent_unacknowledged": """
            SELECT COUNT(*) c
            FROM notifications
            WHERE sent_at IS NOT NULL
              AND acknowledged_at IS NULL
              AND canceled_at IS NULL
        """,
        "acknowledged": """
            SELECT COUNT(*) c
            FROM notifications
            WHERE acknowledged_at IS NOT NULL
        """,
    }

    for key, query in queries.items():
        result[key] = conn.execute(
            query
        ).fetchone()["c"]

    print(
        json.dumps(
            {
                "ok": True,
                **result,
            },
            indent=2,
        )
    )


def cmd_pending(args):
    conn = connect()
    init_db(conn)

    rows = conn.execute(
        """
        SELECT notification_id,
               level,
               title,
               created_at,
               sent_at
        FROM notifications
        WHERE acknowledged_at IS NULL
          AND canceled_at IS NULL
        ORDER BY created_at DESC
        """
    ).fetchall()

    print(
        json.dumps(
            {
                "ok": True,
                "count": len(rows),
                "items": [
                    dict(row)
                    for row in rows
                ],
            },
            indent=2,
            ensure_ascii=False,
        )
    )


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    p = sub.add_parser("init")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("queue")
    p.add_argument("--run-id", required=True)
    p.add_argument(
        "--level",
        required=True,
        choices=[
            "remember",
            "important",
            "urgent",
        ],
    )
    p.add_argument("--title", required=True)
    p.add_argument("--message", required=True)
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser("dispatch")
    p.set_defaults(func=cmd_dispatch)

    p = sub.add_parser("status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("pending")
    p.set_defaults(func=cmd_pending)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
