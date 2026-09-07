#!/usr/bin/env python3
"""One-time pairing sessions for Ackline guided setup (P2A-H1).

This module owns the server-side pairing-session store: a small durable
SQLite database that is separate from the production notifications/outbox
database (``personal_admin.db``).

Security properties:

- Only the SHA-256 hash of the bearer token is stored. The token itself
  is returned once by the issuance CLI and never persisted.
- No FID and no E2EE key material ever enters this store.
- Session consumption is atomic (``BEGIN IMMEDIATE`` + single guarded
  ``UPDATE``), so concurrent claims yield exactly one success.
- Token comparison uses :func:`hmac.compare_digest`.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE = Path.home() / ".hermes" / "personal-admin"
PAIRING_DB_FILE = BASE / "pairing_sessions.db"

DEFAULT_TTL_MINUTES = 10
MIN_TTL_MINUTES = 5
MAX_TTL_MINUTES = 30

INTENTS = frozenset({"fresh", "replace"})

# Sessions fully resolved (consumed/revoked) or expired longer ago than
# this are removed lazily during normal pairing operations.
RETENTION_GRACE = timedelta(hours=24)

_PAIRING_FILE_MODE = 0o600


def utc_now():
    return datetime.now(timezone.utc)


def format_ts(moment):
    return moment.astimezone(timezone.utc).isoformat()


def parse_ts(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def connect(db_path=None):
    """Open the pairing-session store, creating it with mode 0600."""

    path = Path(db_path) if db_path is not None else PAIRING_DB_FILE
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    init_db(conn)
    try:
        os.chmod(path, _PAIRING_FILE_MODE)
    except OSError:
        pass
    return conn


def init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS pairing_sessions (
            session_id TEXT PRIMARY KEY,
            token_hash BLOB NOT NULL,
            intent TEXT NOT NULL
                CHECK (intent IN ('fresh', 'replace')),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT NULL,
            revoked_at TEXT NULL
        );
        """
    )
    conn.commit()


def issue_session(intent="fresh", ttl_minutes=DEFAULT_TTL_MINUTES, db_path=None):
    """Create one pairing session; return its public fields plus the token.

    The token is returned exactly once by this call. Only its SHA-256
    digest is persisted.
    """

    if intent not in INTENTS:
        raise ValueError("pairing intent must be 'fresh' or 'replace'")
    if (
        not isinstance(ttl_minutes, int)
        or isinstance(ttl_minutes, bool)
        or not MIN_TTL_MINUTES <= ttl_minutes <= MAX_TTL_MINUTES
    ):
        raise ValueError(
            "pairing TTL must be an integer between %d and %d minutes"
            % (MIN_TTL_MINUTES, MAX_TTL_MINUTES)
        )

    created = utc_now()
    expires = created + timedelta(minutes=ttl_minutes)
    session_id = secrets.token_hex(16)
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).digest()

    conn = connect(db_path)
    try:
        cleanup_old_sessions(conn, created)
        conn.execute(
            """
            INSERT INTO pairing_sessions(
                session_id, token_hash, intent,
                created_at, expires_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                token_hash,
                intent,
                format_ts(created),
                format_ts(expires),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "session_id": session_id,
        "token": token,
        "intent": intent,
        "created_at": format_ts(created),
        "expires_at": format_ts(expires),
        "ttl_seconds": ttl_minutes * 60,
    }


def revoke_session(session_id, db_path=None):
    """Idempotently revoke an unused session; True if the session exists."""

    if not isinstance(session_id, str) or not session_id:
        return False

    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT session_id, consumed_at
            FROM pairing_sessions
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        if row is None:
            return False
        if row["consumed_at"] is None:
            moment = format_ts(utc_now())
            conn.execute(
                """
                UPDATE pairing_sessions
                SET consumed_at = ?, revoked_at = ?
                WHERE session_id = ?
                  AND consumed_at IS NULL
                """,
                (moment, moment, session_id),
            )
            conn.commit()
        return True
    finally:
        conn.close()


def consume_session(session_id, token, db_path=None, now=None):
    """Atomically consume one session.

    Returns ``(True, row_dict)`` on success where ``row_dict`` carries the
    session intent, else ``(False, error_code)`` with ``error_code`` in
    ``{"invalid", "expired", "consumed"}``. Unknown sessions and token
    mismatches are deliberately indistinguishable (``invalid``).
    """

    moment = now if now is not None else utc_now()
    if not isinstance(session_id, str) or not session_id:
        return False, "invalid"
    if not isinstance(token, str) or not token:
        return False, "invalid"

    presented_hash = hashlib.sha256(token.encode("utf-8")).digest()

    conn = connect(db_path)
    try:
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                """
                SELECT session_id, token_hash, intent,
                       created_at, expires_at,
                       consumed_at, revoked_at
                FROM pairing_sessions
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()

            if row is None:
                conn.execute("ROLLBACK")
                return False, "invalid"

            stored_hash = bytes(row["token_hash"])
            if not hmac.compare_digest(stored_hash, presented_hash):
                conn.execute("ROLLBACK")
                return False, "invalid"

            if row["consumed_at"] is not None or row["revoked_at"] is not None:
                conn.execute("ROLLBACK")
                return False, "consumed"

            expires_at = parse_ts(row["expires_at"])
            if expires_at is None or moment >= expires_at:
                conn.execute("ROLLBACK")
                return False, "expired"

            cursor = conn.execute(
                """
                UPDATE pairing_sessions
                SET consumed_at = ?
                WHERE session_id = ?
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (format_ts(moment), session_id),
            )
            if cursor.rowcount != 1:
                conn.execute("ROLLBACK")
                return False, "consumed"
            conn.execute("COMMIT")
            return True, {"session_id": session_id, "intent": row["intent"]}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
    finally:
        conn.close()


def verify_session(session_id, token, db_path=None, now=None):
    """Validate a session without consuming it.

    Returns ``(True, info_dict)`` where ``info_dict`` carries the session
    intent, else ``(False, error_code)``. Used by the claim endpoint to
    evaluate fresh/replace permission before the atomic consume, so a
    409 rejection never burns the one-time session. The consume step
    re-validates everything atomically; a race between verify and
    consume fails closed as ``consumed``.
    """

    moment = now if now is not None else utc_now()
    if not isinstance(session_id, str) or not session_id:
        return False, "invalid"
    if not isinstance(token, str) or not token:
        return False, "invalid"

    presented_hash = hashlib.sha256(token.encode("utf-8")).digest()

    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT session_id, token_hash, intent,
                   created_at, expires_at,
                   consumed_at, revoked_at
            FROM pairing_sessions
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()

        if row is None:
            return False, "invalid"
        if not hmac.compare_digest(
            bytes(row["token_hash"]), presented_hash
        ):
            return False, "invalid"
        if row["consumed_at"] is not None or row["revoked_at"] is not None:
            return False, "consumed"
        expires_at = parse_ts(row["expires_at"])
        if expires_at is None or moment >= expires_at:
            return False, "expired"
        return True, {"session_id": session_id, "intent": row["intent"]}
    finally:
        conn.close()


def cleanup_old_sessions(conn, now=None):
    """Delete sufficiently old resolved/expired sessions (lazy, no scheduler)."""

    moment = now if now is not None else utc_now()
    cutoff = format_ts(moment - RETENTION_GRACE)
    conn.execute(
        """
        DELETE FROM pairing_sessions
        WHERE (consumed_at IS NOT NULL AND consumed_at < ?)
           OR (revoked_at IS NOT NULL AND revoked_at < ?)
           OR (consumed_at IS NULL AND revoked_at IS NULL
               AND expires_at < ?)
        """,
        (cutoff, cutoff, cutoff),
    )
