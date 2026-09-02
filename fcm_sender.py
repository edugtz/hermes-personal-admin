#!/usr/bin/env python3
"""Production FCM sender for the Hermes Personal Admin outbox.

This module owns one FCM transport attempt.  It deliberately does not import
the Ackline checkout and does not mutate the Hermes database.
"""

import base64
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.error import URLError

import firebase_admin
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from firebase_admin import credentials, exceptions, messaging


ENVELOPE_VERSION = "1"
KID = "ackline-main"
KEY_BYTES = 32
NONCE_BYTES = 12
GCM_TAG_BYTES = 16
MAX_INNER_PAYLOAD_BYTES = 2_500

SECRETS_DIR = Path.home() / ".hermes" / "secrets"
FIREBASE_CREDENTIAL_FILE = SECRETS_DIR / "firebase-service-account.json"
E2EE_KEY_FILE = SECRETS_DIR / "hermes-notify.key"
FID_FILE = SECRETS_DIR / "ackline-fid"

FCM_PRIORITY_BY_LEVEL = {
    "remember": "normal",
    "important": "high",
    "urgent": "high",
}

_KID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_VALID_DETAILS = frozenset(
    {
        "unregistered",
        "invalid_argument",
        "sender_mismatch",
        "auth",
        "quota",
        "unavailable",
        "internal",
        "network",
        "unknown",
    }
)
_CATEGORY_PREFIXES = {
    "transient": "FCM_TRANSIENT",
    "permanent_target": "FCM_PERMANENT",
    "permanent_configuration": "FCM_CONFIG",
    "unknown": "FCM_UNKNOWN",
}

_APP_LOCK = threading.Lock()


@dataclass(frozen=True)
class TransportResult:
    """Sanitized result of one FCM attempt."""

    accepted: bool
    category: str
    detail: str | None = None
    message_id: str | None = None


class ConfigurationError(ValueError):
    """A local configuration/input failure with a symbolic result detail."""

    def __init__(self, detail: str, message: str):
        self.result_detail = detail if detail in _VALID_DETAILS else "unknown"
        super().__init__(message)


def load_key_file(path: str | os.PathLike[str] | None = None) -> bytes:
    """Read and validate the configured AES-256-GCM key without exposing it."""

    key_path = Path(path) if path is not None else E2EE_KEY_FILE
    try:
        key = key_path.read_bytes()
    except (OSError, TypeError, ValueError):
        raise ConfigurationError(
            "invalid_argument",
            "E2EE key file unavailable",
        ) from None

    if len(key) != KEY_BYTES:
        raise ConfigurationError(
            "invalid_argument",
            "E2EE key file must contain exactly 32 bytes",
        )
    return key


def load_fid_file(path: str | os.PathLike[str] | None = None) -> str:
    """Read exactly one non-empty FID line, stripping only line endings."""

    fid_path = Path(path) if path is not None else FID_FILE
    try:
        raw = fid_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError, TypeError, ValueError):
        raise ConfigurationError(
            "invalid_argument",
            "FCM FID file unavailable",
        ) from None

    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0] or lines[0] != lines[0].strip():
        raise ConfigurationError(
            "invalid_argument",
            "FCM FID file must contain exactly one non-empty line",
        )
    return lines[0]


def validate_kid(kid: str) -> str:
    if not isinstance(kid, str) or not _KID_PATTERN.fullmatch(kid):
        raise ValueError("E2EE kid must match [A-Za-z0-9._-]{1,64}")
    return kid


def canonical_aad(kid: str) -> bytes:
    return f"ackline-e2ee|v={ENVELOPE_VERSION}|kid={validate_kid(kid)}".encode(
        "utf-8"
    )


def compact_inner_json(inner_payload: Mapping[str, str]) -> bytes:
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in inner_payload.items()
    ):
        raise ConfigurationError(
            "invalid_argument",
            "inner payload keys and values must be strings",
        )

    encoded = json.dumps(
        dict(inner_payload),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_INNER_PAYLOAD_BYTES:
        raise ConfigurationError(
            "invalid_argument",
            "inner payload exceeds 2500 UTF-8 bytes",
        )
    return encoded


def build_inner_payload(row: Mapping[str, object]) -> dict[str, str]:
    """Build the frozen inner payload from one existing Hermes row."""

    field_names = (
        "notification_id",
        "level",
        "title",
        "message",
        "created_at",
        "ack_token",
    )
    try:
        values = {field: row[field] for field in field_names}
    except (KeyError, TypeError):
        raise ConfigurationError(
            "invalid_argument",
            "notification row is missing required fields",
        ) from None

    if any(not isinstance(value, str) for value in values.values()):
        raise ConfigurationError(
            "invalid_argument",
            "notification row fields must be strings",
        )

    return {
        "protocol": "1",
        **values,
    }


def _base64url_without_padding(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _encrypt_with_nonce(
    *,
    key: bytes,
    kid: str,
    inner_payload: Mapping[str, str],
    nonce: bytes,
) -> dict[str, str]:
    """Deterministic hook used only by protocol-parity tests."""

    if len(key) != KEY_BYTES:
        raise ValueError("AES-256-GCM requires exactly 32 bytes")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")

    plaintext = compact_inner_json(inner_payload)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, canonical_aad(kid))
    return {
        "v": ENVELOPE_VERSION,
        "kid": validate_kid(kid),
        "nonce": _base64url_without_padding(nonce),
        "ciphertext": _base64url_without_padding(ciphertext),
    }


def encrypt_inner_payload(
    *,
    key: bytes,
    kid: str,
    inner_payload: Mapping[str, str],
) -> dict[str, str]:
    """Encrypt one payload with a fresh cryptographically random nonce."""

    return _encrypt_with_nonce(
        key=key,
        kid=kid,
        inner_payload=inner_payload,
        nonce=os.urandom(NONCE_BYTES),
    )


def build_envelope(
    row: Mapping[str, object],
    key: bytes | None = None,
) -> dict[str, str]:
    return encrypt_inner_payload(
        key=load_key_file() if key is None else key,
        kid=KID,
        inner_payload=build_inner_payload(row),
    )


def priority_for_level(level: str) -> str:
    try:
        return FCM_PRIORITY_BY_LEVEL[level]
    except (KeyError, TypeError):
        raise ConfigurationError(
            "invalid_argument",
            "notification level is not supported",
        ) from None


def build_message(
    row: Mapping[str, object],
    fid: str,
    key: bytes | None = None,
) -> messaging.Message:
    return messaging.Message(
        fid=fid,
        android=messaging.AndroidConfig(
            priority=priority_for_level(row["level"]),
        ),
        data=build_envelope(row, key),
    )


def initialize_firebase(
    credential_file: str | os.PathLike[str] | None = None,
):
    """Return the default Firebase app, initializing it once with a file path."""

    credential_path = (
        Path(credential_file)
        if credential_file is not None
        else FIREBASE_CREDENTIAL_FILE
    )

    with _APP_LOCK:
        try:
            return firebase_admin.get_app()
        except ValueError:
            pass

        if not credential_path.is_file():
            raise ConfigurationError(
                "auth",
                "Firebase credential file unavailable",
            )

        try:
            certificate = credentials.Certificate(str(credential_path))
            return firebase_admin.initialize_app(certificate)
        except ValueError:
            # A concurrently initialized default app is safe to reuse.  If no
            # app exists, avoid exposing credential/parser exception details.
            try:
                return firebase_admin.get_app()
            except ValueError:
                raise ConfigurationError(
                    "auth",
                    "Firebase credential initialization failed",
                ) from None
        except Exception:
            raise ConfigurationError(
                "auth",
                "Firebase credential initialization failed",
            ) from None


def classify_firebase_exception(exc: BaseException) -> TransportResult:
    """Map SDK/network failures to a fixed, non-sensitive result."""

    if isinstance(exc, messaging.UnregisteredError):
        return TransportResult(False, "permanent_target", "unregistered")
    if isinstance(exc, messaging.SenderIdMismatchError):
        return TransportResult(False, "permanent_configuration", "sender_mismatch")
    if isinstance(exc, messaging.ThirdPartyAuthError):
        return TransportResult(False, "permanent_configuration", "auth")
    if isinstance(exc, messaging.QuotaExceededError):
        return TransportResult(False, "transient", "quota")
    if isinstance(exc, exceptions.InvalidArgumentError):
        return TransportResult(False, "permanent_configuration", "invalid_argument")
    if isinstance(exc, exceptions.UnauthenticatedError):
        return TransportResult(False, "permanent_configuration", "auth")
    if isinstance(exc, exceptions.PermissionDeniedError):
        return TransportResult(False, "permanent_configuration", "auth")
    if isinstance(exc, exceptions.ResourceExhaustedError):
        return TransportResult(False, "transient", "quota")
    if isinstance(exc, exceptions.UnavailableError):
        return TransportResult(False, "transient", "unavailable")
    if isinstance(exc, exceptions.DeadlineExceededError):
        return TransportResult(False, "transient", "network")
    if isinstance(exc, exceptions.InternalError):
        return TransportResult(False, "transient", "internal")
    if isinstance(exc, ConfigurationError):
        return TransportResult(
            False,
            "permanent_configuration",
            exc.result_detail,
        )
    if isinstance(exc, ValueError):
        return TransportResult(False, "permanent_configuration", "invalid_argument")
    if isinstance(exc, (requests.RequestException, URLError, TimeoutError, ConnectionError)):
        return TransportResult(False, "transient", "network")
    return TransportResult(False, "unknown", "unknown")


def sanitized_error_marker(result: object) -> str | None:
    """Return the only form of FCM failure suitable for outbox persistence."""

    if getattr(result, "accepted", False):
        return None

    category = getattr(result, "category", "unknown")
    detail = getattr(result, "detail", "unknown")
    prefix = _CATEGORY_PREFIXES.get(category, "FCM_UNKNOWN")
    if detail not in _VALID_DETAILS:
        detail = "unknown"
    return f"{prefix}:{detail}"


def send_notification(
    row: Mapping[str, object],
    *,
    fid_file: str | os.PathLike[str] | None = None,
    key_file: str | os.PathLike[str] | None = None,
    credential_file: str | os.PathLike[str] | None = None,
) -> TransportResult:
    """Perform one encrypted FCM send and return a sanitized result."""

    try:
        fid = load_fid_file(fid_file)
        key = load_key_file(key_file)
        message = build_message(row, fid, key)
        initialize_firebase(credential_file)
        response = messaging.send(message)
    except Exception as exc:
        return classify_firebase_exception(exc)

    if not isinstance(response, str) or not response:
        return TransportResult(False, "unknown", "unknown")
    return TransportResult(True, "accepted", message_id=response)
