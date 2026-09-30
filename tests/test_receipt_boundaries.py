"""Independent offline reproductions of deadline and journal interruption gaps."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from decision_bug_hunter import providers as p
from decision_bug_hunter.protocol import QUESTION, ProviderError


class CountingProvider:
    identity = p.ProviderIdentity("independent-offline-check", synthetic=True)

    def __init__(self):
        self.calls = 0
        self.timeouts = []

    def require_available(self):
        pass

    def check_sensitive(self, *values):
        pass

    def decide(self, request):
        self.calls += 1
        self.timeouts.append(request.timeout_seconds)
        return p.ProviderResponse({"q": {"type": "noul", "noul": 0.9}},
                                  {"input_tokens": 2, "output_tokens": 1})

    def close(self):
        pass


class ReceiptBoundaryRegressions(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="dbh-independent-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def gateway(self, name):
        provider = CountingProvider()
        gateway = p.ValidatedGateway(provider, self.root / name)
        self.addCleanup(gateway.close)
        return gateway, provider

    def evaluate(self, gateway):
        return gateway.evaluate({"text": "synthetic fixture",
                                 "context_scope": "declared_standalone"},
                                {"q": QUESTION}, metadata={})

    def saved(self, name):
        paths = list((self.root / name).glob("*.json"))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text(encoding="utf-8"))

    def test_deadline_expires_during_intent_persistence(self):
        gateway, provider = self.gateway("deadline")
        clock = [100.0]
        gateway.set_run_deadline(101.0)
        original = p._write_receipt

        def delay_intent(path, receipt):
            original(path, receipt)
            if receipt["status"] == "dispatching":
                clock[0] = 102.0

        with patch.object(p.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(p, "_write_receipt", side_effect=delay_intent):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "run_deadline_exceeded")
        self.assertEqual(provider.calls, 0)
        saved = self.saved("deadline")
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["error"], "run_deadline_exceeded")
        self.assertIsNone(saved["answers"])

    def test_dispatch_budget_shrinks_by_intent_persistence_time(self):
        gateway, provider = self.gateway("remaining")
        clock = [100.0]
        gateway.set_run_deadline(101.0)
        original = p._write_receipt

        def delay_intent(path, receipt):
            original(path, receipt)
            if receipt["status"] == "dispatching":
                clock[0] = 100.75

        with patch.object(p.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(p, "_write_receipt", side_effect=delay_intent):
            self.evaluate(gateway)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(provider.timeouts, [.25])

    def test_journal_interrupt_blocks_gateway_reuse(self):
        cases = (("intent_before", 0), ("intent", 0),
                 ("terminal", 1), ("terminal_after", 1))
        for boundary, expected_calls in cases:
            with self.subTest(boundary=boundary):
                gateway, provider = self.gateway(boundary)
                original = p._write_receipt
                fired = [False]

                def interrupt_write(path, receipt):
                    target = (receipt["status"] == "dispatching" if boundary.startswith("intent")
                              else receipt["status"] != "dispatching")
                    if target and not fired[0]:
                        fired[0] = True
                        if boundary in ("intent", "terminal_after"):
                            original(path, receipt)
                        raise KeyboardInterrupt
                    original(path, receipt)

                with patch.object(p, "_write_receipt", side_effect=interrupt_write):
                    with self.assertRaises(KeyboardInterrupt):
                        self.evaluate(gateway)
                self.assertTrue(fired[0])
                self.assertEqual(provider.calls, expected_calls)
                self.assertTrue(self.saved(boundary)["submission_possible"])
                with self.assertRaises(ProviderError):
                    self.evaluate(gateway)
                self.assertEqual(provider.calls, expected_calls)
