#!/usr/bin/env python3

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, patch

import fcm_sender
import notification_state
import requests
from firebase_admin import exceptions, messaging


class FcmSenderTest(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.row = {
            "notification_id": "sender-test-001",
            "level": "important",
            "title": "Non-sensitive test title",
            "message": "Non-sensitive test message",
            "created_at": "2026-08-30T00:00:00Z",
            "ack_token": "test-ack-token",
        }

    def _config_files(self, directory):
        root = Path(directory)
        key_file = root / "test.key"
        fid_file = root / "test.fid"
        credential_file = root / "test-credential.json"
        key_file.write_bytes(self.key)
        fid_file.write_text("test-fid-0001\n", encoding="utf-8")
        credential_file.write_text("test credential placeholder\n", encoding="utf-8")
        return key_file, fid_file, credential_file

    def test_inner_payload_preserves_row_fields_and_protocol(self):
        payload = fcm_sender.build_inner_payload(self.row)

        self.assertEqual(
            {
                "protocol": "1",
                "notification_id": self.row["notification_id"],
                "level": self.row["level"],
                "title": self.row["title"],
                "message": self.row["message"],
                "created_at": self.row["created_at"],
                "ack_token": self.row["ack_token"],
            },
            payload,
        )
        self.assertTrue(all(isinstance(value, str) for value in payload.values()))

    def test_deterministic_cross_language_vector(self):
        envelope = fcm_sender._encrypt_with_nonce(
            key=self.key,
            kid="test-vector",
            inner_payload={
                "protocol": "1",
                "notification_id": "vector-001",
                "level": "important",
                "title": "Vector",
                "message": "Non-sensitive test",
                "created_at": "2026-08-30T00:00:00Z",
                "ack_token": "vector-token",
            },
            nonce=bytes(range(12)),
        )

        self.assertEqual(
            "PCCmaaqRrXjiLbWxk9haQaG46ECZHTYfWROM6nM2adYjKoyKyqJm9waJT925pQQagjwW6Db0mfhW-lp2apeUgIQe6linuFINeXaQTLnqbZxX-OtOVA42G46c-alaypvDpJZ0lcEvu3PqdUjXaAFEDM5FTomAt0D7OZozkuOSTDSZYDD0gvr7ayXSePUN6nbyBs7TBW8zv2jtPIMojr2Ci_21pDefmq8KyBHwjrDr49W_s-dujbZdrCcmIPM89XMuGsY",
            envelope["ciphertext"],
        )

    def test_outer_envelope_has_only_protocol_metadata(self):
        envelope = fcm_sender.build_envelope(self.row, self.key)

        self.assertEqual({"v", "kid", "nonce", "ciphertext"}, set(envelope))
        self.assertEqual("1", envelope["v"])
        self.assertEqual("ackline-main", envelope["kid"])
        for private_field in fcm_sender.build_inner_payload(self.row):
            self.assertNotIn(private_field, envelope)

    def test_fresh_nonce_per_normal_encryption_attempt(self):
        first = fcm_sender.build_envelope(self.row, self.key)
        second = fcm_sender.build_envelope(self.row, self.key)

        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_priority_mapping(self):
        self.assertEqual("normal", fcm_sender.priority_for_level("remember"))
        self.assertEqual("high", fcm_sender.priority_for_level("important"))
        self.assertEqual("high", fcm_sender.priority_for_level("urgent"))

    def test_normal_priority_override_is_available_for_redelivery_only(self):
        message = fcm_sender.build_message(
            self.row,
            "test-fid-0001",
            self.key,
            priority_override="normal",
        )

        self.assertEqual("normal", message.android.priority)

    def test_oversize_payload_rejected_before_firebase_send(self):
        oversized = dict(self.row, message="x" * 3_000)
        with tempfile.TemporaryDirectory() as directory:
            key_file, fid_file, credential_file = self._config_files(directory)
            with patch.object(fcm_sender, "initialize_firebase") as initialize:
                with patch.object(fcm_sender.messaging, "send") as send:
                    result = fcm_sender.send_notification(
                        oversized,
                        key_file=key_file,
                        fid_file=fid_file,
                        credential_file=credential_file,
                    )

        self.assertFalse(result.accepted)
        self.assertEqual("permanent_configuration", result.category)
        self.assertEqual("invalid_argument", result.detail)
        initialize.assert_not_called()
        send.assert_not_called()

    def test_bad_key_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            fcm_sender._encrypt_with_nonce(
                key=b"bad",
                kid=fcm_sender.KID,
                inner_payload=fcm_sender.build_inner_payload(self.row),
                nonce=bytes(range(12)),
            )

    def test_missing_key_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "key file unavailable"):
                fcm_sender.load_key_file(Path(directory) / "missing.key")

    def test_missing_and_blank_fid_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.fid"
            with self.assertRaisesRegex(ValueError, "FID file unavailable"):
                fcm_sender.load_fid_file(missing)

            blank = Path(directory) / "blank.fid"
            blank.write_text("\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one non-empty line"):
                fcm_sender.load_fid_file(blank)

    def test_explicit_credential_path_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            credential_file = Path(directory) / "credential.json"
            credential_file.write_text("test credential placeholder\n", encoding="utf-8")
            certificate = object()
            with patch.object(fcm_sender.firebase_admin, "get_app", side_effect=ValueError):
                with patch.object(
                    fcm_sender.credentials,
                    "Certificate",
                    return_value=certificate,
                ) as certificate_factory:
                    with patch.object(
                        fcm_sender.firebase_admin,
                        "initialize_app",
                        return_value=object(),
                    ):
                        fcm_sender.initialize_firebase(credential_file)

        certificate_factory.assert_called_once_with(str(credential_file))

    def test_accepted_firebase_result(self):
        with tempfile.TemporaryDirectory() as directory:
            key_file, fid_file, credential_file = self._config_files(directory)
            with patch.object(fcm_sender, "initialize_firebase"):
                with patch.object(
                    fcm_sender.messaging,
                    "send",
                    return_value="projects/test/messages/accepted-001",
                ) as send:
                    result = fcm_sender.send_notification(
                        self.row,
                        key_file=key_file,
                        fid_file=fid_file,
                        credential_file=credential_file,
                    )

        self.assertEqual(
            fcm_sender.TransportResult(
                True,
                "accepted",
                message_id="projects/test/messages/accepted-001",
            ),
            result,
        )
        send.assert_called_once()

    def test_exception_classification(self):
        cases = (
            (messaging.UnregisteredError("safe"), "permanent_target", "unregistered"),
            (messaging.QuotaExceededError("safe"), "transient", "quota"),
            (exceptions.DeadlineExceededError("safe"), "transient", "network"),
            (exceptions.UnavailableError("safe"), "transient", "unavailable"),
            (exceptions.InternalError("safe"), "transient", "internal"),
            (messaging.SenderIdMismatchError("safe"), "permanent_configuration", "sender_mismatch"),
            (messaging.ThirdPartyAuthError("safe"), "permanent_configuration", "auth"),
            (exceptions.InvalidArgumentError("safe"), "permanent_configuration", "invalid_argument"),
            (exceptions.UnauthenticatedError("safe"), "permanent_configuration", "auth"),
            (requests.RequestException("safe"), "transient", "network"),
            (RuntimeError("safe"), "unknown", "unknown"),
        )

        for exception, category, detail in cases:
            with self.subTest(exception=type(exception).__name__):
                result = fcm_sender.classify_firebase_exception(exception)
                self.assertFalse(result.accepted)
                self.assertEqual(category, result.category)
                self.assertEqual(detail, result.detail)

    def test_results_and_error_markers_never_contain_private_values(self):
        private_values = (
            self.row["title"],
            self.row["message"],
            self.row["ack_token"],
            "test-fid-0001",
            self.key.hex(),
        )
        result = fcm_sender.classify_firebase_exception(
            RuntimeError(" ".join(private_values))
        )
        marker = fcm_sender.sanitized_error_marker(
            SimpleNamespace(
                accepted=False,
                category="permanent_target",
                detail="not-a-valid-detail",
            )
        )

        result_text = repr(result) + repr(marker)
        for private_value in private_values:
            self.assertNotIn(private_value, result_text)


class DispatcherTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db_file = Path(self.directory.name) / "test.db"
        self.db_patch = patch.object(notification_state, "DB_FILE", self.db_file)
        self.db_patch.start()

        conn = notification_state.connect()
        conn.execute(
            "CREATE TABLE runs (run_id TEXT PRIMARY KEY, status TEXT NOT NULL)"
        )
        notification_state.init_db(conn)
        conn.execute(
            "INSERT INTO runs(run_id, status) VALUES (?, ?)",
            ("run-001", "committed"),
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.db_patch.stop()
        self.directory.cleanup()

    def add_row(
        self,
        notification_id,
        *,
        created_at,
        run_id="run-001",
        level="important",
        sent_at=None,
        acknowledged_at=None,
        canceled_at=None,
        send_attempts=0,
        last_attempt_at=None,
        last_error=None,
        ntfy_message_id=None,
    ):
        conn = notification_state.connect()
        conn.execute(
            """
            INSERT INTO notifications(
                notification_id, run_id, dedupe_key, level, title, message,
                ack_token, ntfy_sequence_id, ntfy_message_id, created_at,
                sent_at, acknowledged_at, canceled_at, send_attempts,
                last_attempt_at, last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                notification_id,
                run_id,
                "dedupe-" + notification_id,
                level,
                "test title",
                "test message",
                "ack-" + notification_id,
                "seq-" + notification_id,
                ntfy_message_id,
                created_at,
                sent_at,
                acknowledged_at,
                canceled_at,
                send_attempts,
                last_attempt_at,
                last_error,
            ),
        )
        conn.commit()
        conn.close()

    def read_row(self, notification_id):
        conn = notification_state.connect()
        row = conn.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            (notification_id,),
        ).fetchone()
        conn.close()
        return row

    def dispatch_with_results(self, results):
        result_iter = iter(results)

        def fake_send(row, **_kwargs):
            return next(result_iter)

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "fcm"):
            with patch.object(fcm_sender, "send_notification", side_effect=fake_send):
                try:
                    notification_state.cmd_dispatch(None)
                except SystemExit as exit_context:
                    return exit_context.code
        return 0

    def test_accepted_sets_sent_after_sender_result_and_leaves_ntfy_id_untouched(self):
        self.add_row("accepted-001", created_at="2026-08-30T00:00:00Z")
        observed_before_return = []

        def fake_send(row):
            observed_before_return.append(row["sent_at"])
            return fcm_sender.TransportResult(
                True,
                "accepted",
                message_id="fcm-message-id-not-stored",
            )

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "fcm"):
            with patch.object(fcm_sender, "send_notification", side_effect=fake_send):
                notification_state.cmd_dispatch(None)

        row = self.read_row("accepted-001")
        self.assertEqual([None], observed_before_return)
        self.assertIsNotNone(row["sent_at"])
        self.assertEqual(1, row["send_attempts"])
        self.assertIsNotNone(row["last_attempt_at"])
        self.assertIsNone(row["last_error"])
        self.assertIsNone(row["ntfy_message_id"])

    def test_acknowledged_unsent_committed_row_is_not_dispatched(self):
        self.add_row(
            "ack-unsent-001",
            created_at="2026-08-30T00:00:00Z",
            acknowledged_at="2026-08-30T01:00:00Z",
            send_attempts=0,
            last_attempt_at=None,
            last_error=None,
        )

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "fcm"):
            with patch.object(fcm_sender, "send_notification") as send:
                notification_state.cmd_dispatch(None)

        send.assert_not_called()
        row = self.read_row("ack-unsent-001")
        self.assertIsNone(row["sent_at"])
        self.assertEqual(0, row["send_attempts"])
        self.assertIsNone(row["last_attempt_at"])
        self.assertIsNone(row["last_error"])
        self.assertIsNotNone(row["acknowledged_at"])

    def test_unacknowledged_unsent_committed_row_is_dispatched(self):
        self.add_row("unack-unsent-001", created_at="2026-08-30T00:00:00Z")
        observed = []

        def fake_send(row):
            observed.append(row["notification_id"])
            return fcm_sender.TransportResult(
                True,
                "accepted",
                message_id="m-1",
            )

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "fcm"):
            with patch.object(
                fcm_sender,
                "send_notification",
                side_effect=fake_send,
            ):
                notification_state.cmd_dispatch(None)

        row = self.read_row("unack-unsent-001")
        self.assertEqual(["unack-unsent-001"], observed)
        self.assertIsNotNone(row["sent_at"])
        self.assertEqual(1, row["send_attempts"])
        self.assertIsNone(row["last_error"])

    def test_acknowledged_row_with_previous_failed_attempt_is_not_retried(self):
        self.add_row(
            "ack-failed-001",
            created_at="2026-08-30T00:00:00Z",
            acknowledged_at="2026-08-30T02:00:00Z",
            send_attempts=3,
            last_attempt_at="2026-08-30T03:00:00Z",
            last_error="FCM_TRANSIENT:network",
        )

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "fcm"):
            with patch.object(fcm_sender, "send_notification") as send:
                notification_state.cmd_dispatch(None)

        send.assert_not_called()
        row = self.read_row("ack-failed-001")
        self.assertIsNone(row["sent_at"])
        self.assertEqual(3, row["send_attempts"])
        self.assertEqual("2026-08-30T03:00:00Z", row["last_attempt_at"])
        self.assertEqual("FCM_TRANSIENT:network", row["last_error"])
        self.assertIsNotNone(row["acknowledged_at"])

    def test_ntfy_acknowledged_row_is_not_published(self):
        self.add_row(
            "ntfy-ack-001",
            created_at="2026-08-30T00:00:00Z",
            acknowledged_at="2026-08-30T01:00:00Z",
        )

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "ntfy"):
            with patch.object(notification_state, "publish") as publish:
                notification_state.cmd_dispatch(None)

        publish.assert_not_called()
        row = self.read_row("ntfy-ack-001")
        self.assertIsNone(row["sent_at"])
        self.assertEqual(0, row["send_attempts"])

    def test_transient_failure_keeps_sent_at_null(self):
        self.add_row("transient-001", created_at="2026-08-30T00:00:00Z")

        exit_code = self.dispatch_with_results(
            [fcm_sender.TransportResult(False, "transient", "network")]
        )

        row = self.read_row("transient-001")
        self.assertEqual(2, exit_code)
        self.assertIsNone(row["sent_at"])
        self.assertEqual(1, row["send_attempts"])
        self.assertIsNotNone(row["last_attempt_at"])
        self.assertEqual("FCM_TRANSIENT:network", row["last_error"])

    def test_permanent_target_failure_keeps_sent_at_null_and_uses_exact_marker(self):
        self.add_row("permanent-target-001", created_at="2026-08-30T00:00:00Z")

        self.dispatch_with_results(
            [fcm_sender.TransportResult(False, "permanent_target", "unregistered")]
        )

        row = self.read_row("permanent-target-001")
        self.assertIsNone(row["sent_at"])
        self.assertEqual("FCM_PERMANENT:unregistered", row["last_error"])

    def test_permanent_configuration_failure_is_sanitized(self):
        self.add_row("permanent-config-001", created_at="2026-08-30T00:00:00Z")

        self.dispatch_with_results(
            [fcm_sender.TransportResult(False, "permanent_configuration", "auth")]
        )

        row = self.read_row("permanent-config-001")
        self.assertIsNone(row["sent_at"])
        self.assertEqual("FCM_CONFIG:auth", row["last_error"])

    def test_attempts_increment_on_success_and_failure(self):
        self.add_row("attempt-success-001", created_at="2026-08-30T00:00:00Z")
        self.add_row("attempt-failure-001", created_at="2026-08-30T00:01:00Z")

        self.dispatch_with_results(
            [
                fcm_sender.TransportResult(True, "accepted"),
                fcm_sender.TransportResult(False, "unknown", "unknown"),
            ]
        )

        self.assertEqual(1, self.read_row("attempt-success-001")["send_attempts"])
        self.assertEqual(1, self.read_row("attempt-failure-001")["send_attempts"])

    def test_later_success_clears_previous_error(self):
        self.add_row(
            "recover-001",
            created_at="2026-08-30T00:00:00Z",
            last_error="FCM_TRANSIENT:network",
        )

        self.dispatch_with_results([fcm_sender.TransportResult(True, "accepted")])

        row = self.read_row("recover-001")
        self.assertIsNotNone(row["sent_at"])
        self.assertIsNone(row["last_error"])

    def test_one_failed_row_does_not_block_later_success(self):
        self.add_row("batch-failure-001", created_at="2026-08-30T00:00:00Z")
        self.add_row("batch-success-001", created_at="2026-08-30T00:01:00Z")

        exit_code = self.dispatch_with_results(
            [
                fcm_sender.TransportResult(False, "transient", "unavailable"),
                fcm_sender.TransportResult(True, "accepted"),
            ]
        )

        self.assertEqual(2, exit_code)
        self.assertIsNone(self.read_row("batch-failure-001")["sent_at"])
        self.assertIsNotNone(self.read_row("batch-success-001")["sent_at"])

    def test_deadline_exceeded_timeout_keeps_sent_at_null_and_persists_correct_marker(self):
        self.add_row("timeout-001", created_at="2026-08-30T00:00:00Z")

        deadline_exc = exceptions.DeadlineExceededError("Firebase messaging timed out")
        self.assertEqual("transient", fcm_sender.classify_firebase_exception(deadline_exc).category)
        self.assertEqual("network", fcm_sender.classify_firebase_exception(deadline_exc).detail)

        exit_code = self.dispatch_with_results(
            [fcm_sender.classify_firebase_exception(deadline_exc)]
        )

        row = self.read_row("timeout-001")
        self.assertEqual(2, exit_code)
        self.assertIsNone(row["sent_at"])
        self.assertEqual(1, row["send_attempts"])
        self.assertIsNotNone(row["last_attempt_at"])
        self.assertEqual("FCM_TRANSIENT:network", row["last_error"])

    def test_ntfy_path_retains_message_id_behavior(self):
        self.add_row("ntfy-001", created_at="2026-08-30T00:00:00Z")

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "ntfy"):
            with patch.object(
                notification_state,
                "publish",
                return_value={"id": "ntfy-message-001"},
            ) as publish:
                notification_state.cmd_dispatch(None)

        row = self.read_row("ntfy-001")
        publish.assert_called_once()
        self.assertIsNotNone(row["sent_at"])
        self.assertEqual("ntfy-message-001", row["ntfy_message_id"])

    def test_ntfy_rollback_does_not_redeliver_already_sent_row(self):
        sent_at = "2026-09-01T00:00:00Z"
        last_attempt_at = "2026-09-01T04:00:00Z"
        self.add_row(
            "ntfy-sent-no-redelivery-001",
            created_at=sent_at,
            sent_at=sent_at,
            last_attempt_at=last_attempt_at,
            send_attempts=1,
        )

        # Same row shape as the FCM redelivery tests: sent_at exactly 6h
        # before dispatch, last_attempt_at exactly 2h before dispatch.
        # Under fcm this row IS redelivered (priority normal); under ntfy
        # it must be left completely untouched.
        with patch.object(
            notification_state,
            "utc_now",
            return_value=datetime(2026, 9, 1, 6, 0, 0, tzinfo=timezone.utc),
        ):
            with patch.object(notification_state, "ACTIVE_TRANSPORT", "ntfy"):
                with patch.object(notification_state, "publish") as publish:
                    with patch.object(fcm_sender, "send_notification") as send:
                        notification_state.cmd_dispatch(None)

        publish.assert_not_called()
        send.assert_not_called()
        row = self.read_row("ntfy-sent-no-redelivery-001")
        self.assertEqual(sent_at, row["sent_at"])
        self.assertEqual(1, row["send_attempts"])
        self.assertEqual(last_attempt_at, row["last_attempt_at"])
        self.assertIsNone(row["last_error"])

    def test_unsupported_active_transport_is_rejected(self):
        with patch.object(notification_state, "ACTIVE_TRANSPORT", "unsupported"):
            with self.assertRaisesRegex(ValueError, "unsupported active transport"):
                notification_state.validate_active_transport()

    def test_unexpected_fcm_exception_is_not_persisted_raw(self):
        self.add_row("unexpected-001", created_at="2026-08-30T00:00:00Z")

        with patch.object(notification_state, "ACTIVE_TRANSPORT", "fcm"):
            with patch.object(
                fcm_sender,
                "send_notification",
                side_effect=RuntimeError("private title private message private token"),
            ):
                with self.assertRaises(SystemExit):
                    notification_state.cmd_dispatch(None)

        row = self.read_row("unexpected-001")
        self.assertEqual("FCM_UNKNOWN:unknown", row["last_error"])
        self.assertNotIn("private", row["last_error"])

    def test_redelivery_just_under_two_hours_since_attempt_is_not_dispatched(self):
        self.add_row(
            "redelivery-too-soon-001",
            created_at="2026-09-01T00:00:00Z",
            sent_at="2026-09-01T00:00:00Z",
            last_attempt_at="2026-09-01T04:00:01Z",
            send_attempts=1,
        )

        with patch.object(
            notification_state,
            "utc_now",
            return_value=datetime(2026, 9, 1, 6, 0, 0, tzinfo=timezone.utc),
        ):
            with patch.object(fcm_sender, "send_notification") as send:
                notification_state.cmd_dispatch(None)

        send.assert_not_called()
        self.assertEqual(1, self.read_row("redelivery-too-soon-001")["send_attempts"])

    def test_redelivery_exactly_two_hours_uses_normal_priority_and_preserves_sent_at(self):
        sent_at = "2026-09-01T00:00:00Z"
        self.add_row(
            "redelivery-exact-gap-001",
            created_at=sent_at,
            level="important",
            sent_at=sent_at,
            last_attempt_at="2026-09-01T04:00:00Z",
            send_attempts=1,
            last_error="FCM_TRANSIENT:network",
        )

        with patch.object(
            notification_state,
            "utc_now",
            return_value=datetime(2026, 9, 1, 6, 0, 0, tzinfo=timezone.utc),
        ):
            with patch.object(
                fcm_sender,
                "send_notification",
                return_value=fcm_sender.TransportResult(True, "accepted"),
            ) as send:
                notification_state.cmd_dispatch(None)

        send.assert_called_once_with(
            ANY,
            priority_override="normal",
        )
        self.assertEqual(
            "redelivery-exact-gap-001",
            send.call_args.args[0]["notification_id"],
        )
        row = self.read_row("redelivery-exact-gap-001")
        self.assertEqual(sent_at, row["sent_at"])
        self.assertEqual(2, row["send_attempts"])
        self.assertIsNotNone(row["last_attempt_at"])
        self.assertNotEqual("2026-09-01T04:00:00Z", row["last_attempt_at"])
        self.assertIsNone(row["last_error"])

    def test_redelivery_exactly_six_hours_since_first_send_is_dispatched(self):
        self.add_row(
            "redelivery-exact-window-001",
            created_at="2026-09-01T00:00:00Z",
            level="urgent",
            sent_at="2026-09-01T00:00:00Z",
            last_attempt_at="2026-09-01T04:00:00Z",
            send_attempts=1,
        )

        with patch.object(
            notification_state,
            "utc_now",
            return_value=datetime(2026, 9, 1, 6, 0, 0, tzinfo=timezone.utc),
        ):
            with patch.object(
                fcm_sender,
                "send_notification",
                return_value=fcm_sender.TransportResult(True, "accepted"),
            ) as send:
                notification_state.cmd_dispatch(None)

        send.assert_called_once_with(
            ANY,
            priority_override="normal",
        )
        self.assertEqual(2, self.read_row("redelivery-exact-window-001")["send_attempts"])

    def test_redelivery_failure_preserves_sent_at_and_records_sanitized_error(self):
        sent_at = "2026-09-01T00:00:00Z"
        self.add_row(
            "redelivery-failure-001",
            created_at=sent_at,
            sent_at=sent_at,
            last_attempt_at="2026-09-01T04:00:00Z",
            send_attempts=1,
        )

        with patch.object(
            notification_state,
            "utc_now",
            return_value=datetime(2026, 9, 1, 6, 0, 0, tzinfo=timezone.utc),
        ):
            self.dispatch_with_results(
                [fcm_sender.TransportResult(False, "transient", "network")]
            )

        row = self.read_row("redelivery-failure-001")
        self.assertEqual(sent_at, row["sent_at"])
        self.assertEqual(2, row["send_attempts"])
        self.assertEqual("FCM_TRANSIENT:network", row["last_error"])

    def test_redelivery_excludes_acknowledged_canceled_non_committed_and_expired_rows(self):
        common = {
            "created_at": "2026-09-01T00:00:00Z",
            "sent_at": "2026-09-01T00:00:00Z",
            "last_attempt_at": "2026-09-01T04:00:00Z",
            "send_attempts": 1,
        }
        self.add_row(
            "redelivery-acknowledged-001",
            acknowledged_at="2026-09-01T01:00:00Z",
            **common,
        )
        self.add_row(
            "redelivery-canceled-001",
            canceled_at="2026-09-01T01:00:00Z",
            **common,
        )
        self.add_row("redelivery-expired-001", **common)
        conn = notification_state.connect()
        conn.execute(
            "INSERT INTO runs(run_id, status) VALUES (?, ?)",
            ("run-002", "pending"),
        )
        conn.commit()
        conn.close()
        self.add_row(
            "redelivery-noncommitted-001",
            run_id="run-002",
            **common,
        )

        with patch.object(
            notification_state,
            "utc_now",
            return_value=datetime(2026, 9, 1, 6, 0, 1, tzinfo=timezone.utc),
        ):
            with patch.object(fcm_sender, "send_notification") as send:
                notification_state.cmd_dispatch(None)

        send.assert_not_called()
        for notification_id in (
            "redelivery-acknowledged-001",
            "redelivery-canceled-001",
            "redelivery-expired-001",
            "redelivery-noncommitted-001",
        ):
            self.assertEqual(1, self.read_row(notification_id)["send_attempts"])


if __name__ == "__main__":
    unittest.main()
