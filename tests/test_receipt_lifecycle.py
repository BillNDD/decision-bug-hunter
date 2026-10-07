"""Inherited durability regressions using finite local judgments and real files."""
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from decision_bug_hunter import providers as p
from decision_bug_hunter.protocol import QUESTION, ProviderError, encode_request
from tests.test_provider_boundary import SyntheticProvider

KEY = "offline-receipt-fault-key"
STATE = {"source": "L1: def total(a, b):\nL2:     return a - b\n"}
META = {"window_id": "W1", "start_line": 1, "end_line": 2}
GOOD = {"q": {"type": "noul", "noul": .82}}
USAGE = {"input_tokens": 80, "output_tokens": 3}


class ReceiptLifecycleSmokeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def gateway(self, name="receipts", response=None, failure=None):
        provider = SyntheticProvider(response or p.ProviderResponse(GOOD, USAGE),
                                     failure=failure, secret=KEY)
        gateway = p.ValidatedGateway(provider, self.root / name)
        self.addCleanup(gateway.close)
        return gateway, provider

    def evaluate(self, gateway, state=STATE, questions=None, metadata=META):
        return gateway.evaluate(state, questions or {"q": QUESTION}, metadata=metadata)

    def saved(self, gateway):
        return json.loads(Path(gateway.last_receipt).read_text())

    def assert_private(self, gateway):
        for path in gateway.receipt_dir.iterdir():
            text = path.read_text()
            for value in (KEY, STATE["source"], "def total"):
                self.assertNotIn(value, text)

    def test_success_orders_two_durable_transitions_around_transport(self):
        gateway, provider = self.gateway()
        events = []
        real_sync, real_replace, decide = p.os.fsync, p.os.replace, provider.decide

        def sync(fd):
            real_sync(fd)
            events.append("sync")

        def replace(source, destination):
            status = json.loads(Path(source).read_text())["status"]
            self.assertEqual(events[-1], "sync")
            real_replace(source, destination)
            events.append(status)

        def dispatch(request):
            saved = self.saved(gateway)
            self.assertEqual(saved["status"], "dispatching")
            self.assertTrue(saved["submission_possible"])
            self.assertEqual(saved["question_count"], 1)
            # The local request hash binds both state and questions.
            self.assertEqual(saved["request_sha256"], hashlib.sha256(encode_request(STATE, {"q": QUESTION})).hexdigest())
            self.assertEqual(saved["metadata"], META)
            self.assertEqual(events[-1], "sync" if os.name == "posix" else "dispatching")
            events.append("provider")
            return decide(request)

        with patch.object(p.os, "fsync", side_effect=sync), \
                patch.object(p.os, "replace", side_effect=replace), \
                patch.object(provider, "decide", side_effect=dispatch):
            self.assertEqual(self.evaluate(gateway)["q"]["noul"], Decimal(".82"))
        self.assertEqual([event for event in events if event != "sync"], ["dispatching", "provider", "validated"])
        self.assertEqual(events.count("sync"), 4 if os.name == "posix" else 2)
        self.assertEqual(self.saved(gateway)["status"], "validated")
        self.assertEqual(len(list(gateway.receipt_dir.iterdir())), 1)
        self.assert_private(gateway)

    def test_rejected_preflight_has_no_receipt_and_no_transport(self):
        cases = (({"source": "x" * 20000}, META, "request_too_large"),
                 (STATE, {"unsafe": "field"}, "invalid_metadata"),
                 ({"source": KEY}, META, "sensitive_input"))
        for index, (state, metadata, code) in enumerate(cases):
            with self.subTest(code=code):
                gateway, provider = self.gateway(str(index))
                with patch.object(p, "_write_receipt", wraps=p._write_receipt) as persist:
                    with self.assertRaises(ProviderError) as caught:
                        self.evaluate(gateway, state, metadata=metadata)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(provider.requests, [])
                persist.assert_not_called()
                self.assertIsNone(gateway.last_call_stats)
                self.assertFalse(gateway.receipt_dir.exists())

    def test_intent_faults_prevent_submission_and_record_failure_when_possible(self):
        for boundary in ("serialization", "fsync", "replace"):
            with self.subTest(boundary=boundary):
                gateway, provider = self.gateway(boundary)
                original = p._write_receipt

                def write(path, receipt):
                    if receipt["status"] == "dispatching":
                        target, attr = ((p, "_receipt_bytes") if boundary == "serialization" else (p.os, boundary))
                        with patch.object(target, attr, side_effect=OSError("synthetic disk failure")):
                            original(path, receipt)
                    else:
                        original(path, receipt)

                with patch.object(p, "_write_receipt", side_effect=write):
                    with self.assertRaises(ProviderError) as caught:
                        self.evaluate(gateway)
                self.assertEqual(caught.exception.code, "receipt_failed")
                self.assertEqual(provider.requests, [])
                self.assertEqual(self.saved(gateway)["status"], "failed")
                self.assertEqual(self.saved(gateway)["error"], "receipt_failed")
                self.assertIsNone(self.saved(gateway)["answers"])
                self.assertFalse(self.saved(gateway)["submission_possible"])
                self.assert_private(gateway)

    def test_terminal_faults_never_release_valid_answers_or_clear_intent(self):
        for boundary in ("serialization", "fsync", "replace"):
            with self.subTest(boundary=boundary):
                gateway, provider = self.gateway(boundary)
                original = p._write_receipt

                def write(path, receipt):
                    if receipt["status"] == "validated":
                        target, attr = ((p, "_receipt_bytes") if boundary == "serialization" else (p.os, boundary))
                        with patch.object(target, attr, side_effect=OSError("synthetic disk failure")):
                            original(path, receipt)
                    else:
                        original(path, receipt)

                with patch.object(p, "_write_receipt", side_effect=write):
                    with self.assertRaises(ProviderError) as caught:
                        self.evaluate(gateway)
                self.assertEqual(caught.exception.code, "receipt_failed")
                self.assertEqual(len(provider.requests), 1)
                self.assertEqual(self.saved(gateway)["status"], "dispatching")
                self.assertIsNone(self.saved(gateway)["answers"])
                self.assertTrue(gateway.last_call_stats["submission_possible"])
                self.assertEqual(gateway.last_call_stats["usage"]["input_tokens"], 80)
                self.assertIsNone(gateway.last_call_stats["answers"])
                self.assert_private(gateway)
                with self.assertRaises(ProviderError):
                    self.evaluate(gateway)
                self.assertEqual(len(provider.requests), 1)

    def test_deadline_expiring_during_intent_sync_prevents_submission(self):
        gateway, provider = self.gateway()
        gateway.set_run_deadline(time.monotonic() + 30)
        original = p._write_receipt

        def write(path, receipt):
            original(path, receipt)
            if receipt["status"] == "dispatching":
                gateway.set_run_deadline(time.monotonic() - 1)

        with patch.object(p, "_write_receipt", side_effect=write):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "run_deadline_exceeded")
        self.assertEqual(provider.requests, [])
        self.assertEqual(self.saved(gateway)["error"], "run_deadline_exceeded")
        # Refused before the provider call: nothing can have been submitted.
        self.assertFalse(self.saved(gateway)["submission_possible"])

    def test_malformed_batch_retains_usage_and_fails_atomically(self):
        gateway, provider = self.gateway(response=p.ProviderResponse(
            {"q": {"type": "noul", "noul": .9}, "other": {"type": "noul", "noul": 1.1}}, USAGE))
        with self.assertRaises(ProviderError) as caught:
            self.evaluate(gateway, questions={"q": QUESTION, "other": QUESTION})
        self.assertEqual(caught.exception.code, "response_probability")
        self.assertEqual(len(provider.requests), 1)
        saved = self.saved(gateway)
        self.assertEqual(saved["status"], "failed")
        self.assertIsNone(saved["answers"])
        self.assertEqual(saved["usage"], USAGE)

    def test_interruptions_are_settled_without_a_second_submission(self):
        for boundary in ("intent", "transport"):
            with self.subTest(boundary=boundary):
                gateway, provider = self.gateway(boundary, failure=KeyboardInterrupt() if boundary == "transport" else None)
                original = p._write_receipt

                def write(path, receipt):
                    original(path, receipt)
                    if receipt["status"] == "dispatching" and boundary == "intent":
                        raise KeyboardInterrupt

                with patch.object(p, "_write_receipt", side_effect=write):
                    with self.assertRaises(KeyboardInterrupt):
                        self.evaluate(gateway)
                self.assertEqual(len(provider.requests), 0 if boundary == "intent" else 1)
                self.assertEqual(self.saved(gateway)["error"], "interrupted")
                self.assertTrue(self.saved(gateway)["submission_possible"])
                with self.assertRaises(ProviderError):
                    self.evaluate(gateway)
                self.assertEqual(len(provider.requests), 0 if boundary == "intent" else 1)

    @unittest.skipUnless(os.name == "posix", "directory durability uses POSIX fsync")
    def test_directory_sync_failure_never_releases_an_answer(self):
        gateway, provider = self.gateway()
        real_sync = p.os.fsync
        calls = 0

        def sync(fd):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("synthetic directory sync failure")
            real_sync(fd)

        with patch.object(p.os, "fsync", side_effect=sync):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "receipt_failed")
        self.assertTrue(gateway.last_call_stats["submission_possible"])
        self.assertEqual(gateway.last_call_stats["usage"], USAGE)
        self.assertEqual(len(provider.requests), 1)

    def test_abrupt_process_exit_preserves_last_durable_outcome(self):
        script = r'''
import json, os, sys
from pathlib import Path
from decision_bug_hunter import providers as p
from decision_bug_hunter.protocol import QUESTION
directory, boundary = sys.argv[1:]
class Fixture:
    identity = p.ProviderIdentity("offline-crash-fixture", synthetic=True)
    def require_available(self): pass
    def check_sensitive(self, *values): pass
    def close(self): pass
    def decide(self, request):
        saved = json.loads(Path(gateway.last_receipt).read_text())
        assert saved["status"] == "dispatching" and saved["submission_possible"]
        if boundary == "dispatch": os._exit(91)
        return p.ProviderResponse({"q": {"type": "noul", "noul": .82}},
                                  {"input_tokens": 80, "output_tokens": 3})
gateway = p.ValidatedGateway(Fixture(), directory)
original = p._write_receipt
def write(path, receipt):
    if receipt["status"] == "validated" and boundary == "terminal": os._exit(92)
    original(path, receipt)
    if receipt["status"] == "validated" and boundary == "after_terminal": os._exit(93)
p._write_receipt = write
gateway.evaluate({"source": "synthetic crash evidence"}, {"q": QUESTION}, metadata={"window_id": "W1"})
raise AssertionError("abrupt exit was not reached")
'''
        for boundary, code in (("dispatch", 91), ("terminal", 92), ("after_terminal", 93)):
            with self.subTest(boundary=boundary):
                directory = self.root / boundary
                completed = subprocess.run([sys.executable, "-B", "-c", script, str(directory), boundary],
                                           capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, code, completed.stderr)
                files = list(directory.glob("*.json"))
                self.assertEqual(len(files), 1)
                saved = json.loads(files[0].read_text())
                self.assertTrue(saved["submission_possible"])
                self.assertEqual(saved["status"], "validated" if boundary == "after_terminal" else "dispatching")
                self.assertIsNotNone(saved["answers"] if boundary == "after_terminal" else saved["request_sha256"])
                if boundary != "after_terminal": self.assertIsNone(saved["answers"])
                self.assertNotIn("synthetic crash evidence", files[0].read_text())
