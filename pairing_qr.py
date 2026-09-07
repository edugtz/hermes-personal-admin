"""Ephemeral operator QR output. Never persist or log payloads."""

import io
import json
from urllib.parse import urlsplit, urlunsplit

import segno


def claim_endpoint(base_url):
    """Append the claim route to a valid HTTPS base without losing its path."""
    parts = urlsplit(base_url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or "?" in base_url
        or "#" in base_url
        or any(char.isspace() or ord(char) < 32 for char in base_url)
    ):
        raise ValueError("Invalid HTTPS ACK base URL")
    parts.port  # Validate a configured port without echoing the URL.
    return urlunsplit(
        ("https", parts.netloc, parts.path.rstrip("/") + "/pairing/claim", "", "")
    )


def build_payload(endpoint, session_id, token):
    """Use an explicit allowlist, never serialize a session or claim response."""
    return json.dumps(
        {"v": 1, "endpoint": endpoint, "session_id": session_id, "token": token},
        separators=(",", ":"),
    )


def render_pairing(session, endpoint, out):
    payload = build_payload(endpoint, session["session_id"], session["token"])
    # Build in memory before printing so encoder errors produce no partial QR.
    terminal = io.StringIO()
    segno.make_qr(payload).terminal(out=terminal, border=4, compact=True)
    mode = "replacement pairing" if session["intent"] == "replace" else "new pairing"
    print("Ackline pairing", file=out)
    print(terminal.getvalue(), end="", file=out)
    print(f"\nExpires in: {session['ttl_seconds'] // 60} minutes", file=out)
    print(f"Mode: {mode}\n", file=out)
    print("1. Open Ackline\n2. Choose pair / re-pair\n3. Scan this QR", file=out)
    print("\nThis QR is sensitive and expires soon. Avoid saving, redirecting, or sharing it.", file=out)
    print("To revoke a known session, use pairing-revoke <session-id>.", file=out)
