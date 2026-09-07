"""P2B-H1 tooling tests; all sessions use temporary state."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import notification_state
import pairing_qr
import pairing_sessions


class PairingQRTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        db_patch = patch.object(pairing_sessions, "PAIRING_DB_FILE", Path(directory.name) / "pairing.db")
        db_patch.start()
        self.addCleanup(db_patch.stop)
        url_patch = patch.object(notification_state, "ACK_BASE_URL", "https://hermes.example:8443/")
        url_patch.start()
        self.addCleanup(url_patch.stop)

    def cli(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["notification_state.py", *arguments]), redirect_stdout(stdout), redirect_stderr(stderr):
            notification_state.main()
        return stdout.getvalue(), stderr.getvalue()

    def test_default_machine_contract_fresh_and_replace(self):
        for options, intent in [((), "fresh"), (("--replace",), "replace")]:
            output, errors = self.cli("pairing-begin", *options, "--ttl-minutes", "5")
            session = json.loads(output)
            self.assertEqual(set(session), {"ok", "session_id", "intent", "created_at", "expires_at", "ttl_seconds", "claim_path", "token"})
            self.assertTrue(session["ok"])
            self.assertEqual(session["intent"], intent)
            self.assertEqual(session["ttl_seconds"], 300)
            self.assertEqual(session["claim_path"], "/pairing/claim")
            self.assertTrue(session["created_at"])
            self.assertTrue(session["expires_at"])
            self.assertEqual(output.count(session["token"]), 1)
            self.assertEqual(errors, "")
            self.assertTrue(pairing_sessions.verify_session(session["session_id"], session["token"])[0])

    def test_canonical_payload(self):
        endpoint = pairing_qr.claim_endpoint("https://hermes.example:8443/")
        payload = pairing_qr.build_payload(endpoint, "synthetic-session", "synthetic-token")
        self.assertEqual(payload, '{"v":1,"endpoint":"https://hermes.example:8443/pairing/claim","session_id":"synthetic-session","token":"synthetic-token"}')
        self.assertEqual(set(json.loads(payload)), {"v", "endpoint", "session_id", "token"})

    def test_endpoint_normalization_and_rejection(self):
        for suffix in ("", "/", "///"):
            self.assertEqual(pairing_qr.claim_endpoint("https://hermes.example:8443" + suffix), "https://hermes.example:8443/pairing/claim")
        self.assertEqual(pairing_qr.claim_endpoint("https://hermes.example/prefix/"), "https://hermes.example/prefix/pairing/claim")
        for url in ("http://hermes.example", "https:///path", "https://user:pass@hermes.example", "https://hermes.example?secret", "https://hermes.example#fragment", "https://hermes.example:bad", "https://hermes.example\n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                pairing_qr.claim_endpoint(url)

    def check_qr_mode(self, replace):
        # Extra fields deliberately emulate sensitive data that must be ignored.
        issue = pairing_sessions.issue_session
        issued = []
        def issue_with_extras(**kwargs):
            session = issue(**kwargs)
            session.update({key: "forbidden-" + key for key in ("e2ee_key_b64", "kid", "fid", "ack_token", "ack_base_url", "credentials", "content", "file_path")})
            issued.append(session)
            return session
        with patch.object(pairing_sessions, "issue_session", side_effect=issue_with_extras), patch.object(pairing_qr.segno, "make_qr") as renderer:
            renderer.return_value.terminal.side_effect = lambda **kwargs: kwargs["out"].write("[QR art]\n")
            options = ["--replace"] if replace else []
            output, errors = self.cli("pairing-begin", "--qr", *options, "--ttl-minutes", "5")
        session = issued[0]
        expected = pairing_qr.build_payload("https://hermes.example:8443/pairing/claim", session["session_id"], session["token"])
        renderer.assert_called_once_with(expected)
        terminal_kwargs = renderer.return_value.terminal.call_args.kwargs
        self.assertEqual(terminal_kwargs["border"], 4)
        self.assertTrue(terminal_kwargs["compact"])
        self.assertEqual(set(json.loads(expected)), {"v", "endpoint", "session_id", "token"})
        for key in ("session_id", "token", "e2ee_key_b64", "kid", "fid", "ack_token", "ack_base_url", "credentials", "content", "file_path"):
            self.assertTrue(session[key] not in output + errors, "human output leaked field: " + key)
        self.assertNotIn('"token":', output + errors)
        self.assertEqual(errors, "")
        self.assertIn("Mode: replacement pairing" if replace else "Mode: new pairing", output)
        self.assertIn("Expires in: 5 minutes", output)
        self.assertIn("3. Scan this QR", output)
        self.assertTrue(pairing_sessions.verify_session(session["session_id"], session["token"])[0])
        self.assertEqual(session["intent"], "replace" if replace else "fresh")

    def test_fresh_qr(self):
        self.check_qr_mode(False)

    def test_replace_qr(self):
        self.check_qr_mode(True)

    def test_real_terminal_renderer(self):
        session = {"session_id": "synthetic-session", "token": "synthetic-token", "intent": "fresh", "ttl_seconds": 600}
        output = io.StringIO()
        pairing_qr.render_pairing(session, "https://hermes.example/pairing/claim", output)
        text = output.getvalue()
        self.assertIn("Ackline pairing", text)
        self.assertTrue(any(char in text for char in "▀▄█"))
        self.assertNotIn(session["token"], text)
        self.assertNotIn(session["session_id"], text)

    def test_encoder_exception_is_redacted(self):
        output, errors = io.StringIO(), io.StringIO()
        def broken_encoder(payload):
            raise ValueError(payload)
        with patch("sys.argv", ["notification_state.py", "pairing-begin", "--qr"]), patch.object(pairing_qr.segno, "make_qr", side_effect=broken_encoder), redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit):
            notification_state.main()
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(json.loads(errors.getvalue()), {"ok": False, "error": "QR output failed; generate a new QR when ready."})

    def test_invalid_config_does_not_issue_session(self):
        with patch.object(notification_state, "ACK_BASE_URL", "http://invalid.example"), patch.object(pairing_sessions, "issue_session") as issue, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.cli("pairing-begin", "--qr")
        issue.assert_not_called()

    def test_revoke_cli(self):
        session = pairing_sessions.issue_session()
        output, errors = self.cli("pairing-revoke", session["session_id"])
        self.assertEqual(json.loads(output), {"ok": True, "session_id": session["session_id"], "revoked": True})
        self.assertEqual(errors, "")
        self.assertFalse(pairing_sessions.verify_session(session["session_id"], session["token"])[0])


if __name__ == "__main__":
    unittest.main()
