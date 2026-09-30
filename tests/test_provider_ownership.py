"""Inherited ownership, cleanup and concurrent-call isolation without a worker."""
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter.core import Config, Source, scan
from decision_bug_hunter.protocol import ProviderError, QUESTION
from decision_bug_hunter.providers import ProviderResponse, ValidatedGateway
from tests.support import FixtureProvider, KEY
from tests.test_provider_boundary import SyntheticProvider


class ProviderOwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_library_scan_borrows_gateway_and_context_owns_cleanup(self):
        config = Config(width=2, min_width=1, whole_file=False, bug_lenses=False,
                        max_depth=0, max_action_steps=0, max_localizations=0)
        provider = SyntheticProvider(fixture=FixtureProvider())
        with ValidatedGateway(provider, self.root / "receipts") as gateway:
            for _ in range(2):
                report = scan(Source.from_text("synthetic\n", "fixture.txt"), gateway,
                              config=config, context_scope="declared_standalone")
                self.assertEqual(report["status"], "complete")
                self.assertEqual(report["issues"], [])
                self.assertEqual(report["findings"], [])
                self.assertTrue(report["coverage"]["all_lines_assessed"])
                self.assertEqual(report["questions_validated"], report["questions_attempted"])
                self.assertEqual(report["requests"][0]["answers"]["rank_0"]["type"], "choice")
                self.assertFalse(provider.closed)
        self.assertTrue(provider.closed)

    def run_cli(self, *, cleanup_error=False, scan_error=None):
        target = self.root / "target.txt"
        target.write_text("synthetic\n", encoding="utf-8")
        output = self.root / "runs"
        stdout, stderr = io.StringIO(), io.StringIO()
        owner = self

        class TrackedProvider(SyntheticProvider):
            def close(self):
                owner.assertEqual(stdout.getvalue(), "")
                owner.assertFalse(list(output.glob("run-*/report.json")))
                self.close_calls += 1
                if cleanup_error:
                    raise RuntimeError(KEY)
                super().close()

        provider = TrackedProvider(fixture=FixtureProvider(), secret=KEY)
        provider.close_calls = 0
        with patch.object(cli, "DecisionsProvider", return_value=provider), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            args = [str(target), "--scope", "standalone", "--output-dir", str(output),
                    "--no-whole-file", "--no-bug-lenses", "--width", "2", "--min-width", "1",
                    "--max-depth", "0", "--max-action-steps", "0", "--max-localizations", "0"]
            if scan_error is None:
                code = cli.main(args)
            else:
                with patch.object(cli, "scan", side_effect=scan_error):
                    code = cli.main(args)
        self.assertEqual(provider.close_calls, 1)
        self.assertEqual(provider.closed, not cleanup_error)
        reports = list(output.glob("run-*/report.json"))
        report = json.loads(reports[0].read_text()) if reports else None
        return code, stdout.getvalue(), stderr.getvalue(), report

    def test_cli_closes_owned_provider_before_complete_output(self):
        code, stdout, stderr, report = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("SCAN: complete", stdout)
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["findings"], [])
        self.assertTrue(report["coverage"]["all_lines_assessed"])
        self.assertEqual(report["questions_validated"], report["questions_attempted"])
        self.assertEqual(report["usage"]["attempts_with_known_usage"], 1)
        self.assertNotIn(KEY, stdout + stderr + json.dumps(report))

    def test_cli_cleanup_failure_preserves_usage_and_reports_incomplete(self):
        code, stdout, stderr, report = self.run_cli(cleanup_error=True)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["handoff"]["status"], "incomplete")
        self.assertEqual(report["usage"]["input_tokens"], 100)
        self.assertEqual(report["usage"]["attempts_with_known_usage"], 1)
        self.assertEqual(report["questions_validated"], report["questions_attempted"])
        self.assertEqual({issue["phase"] for issue in report["issues"]}, {"transport-cleanup"})
        self.assertIn("Transport cleanup failed (transport_failed)", stderr)
        self.assertNotIn("SCAN: complete", stdout)
        self.assertNotIn(KEY, stdout + stderr + json.dumps(report))

    def test_cli_scan_exception_still_closes_owned_gateway(self):
        code, stdout, stderr, report = self.run_cli(scan_error=KeyboardInterrupt())
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("interrupted", stderr)
        self.assertIsNone(report)

    def test_concurrent_rejection_does_not_expose_another_callers_receipt_or_usage(self):
        entered, release = threading.Event(), threading.Event()
        completed = []
        response = ProviderResponse({"q": {"type": "noul", "noul": .13}},
                                    {"input_tokens": 2, "output_tokens": 2})
        provider = SyntheticProvider(response)
        gateway = ValidatedGateway(provider, self.root / "receipts")
        self.addCleanup(gateway.close)
        original = provider.decide

        def dispatch(request):
            entered.set()
            if not release.wait(10):
                raise AssertionError("test caller did not release provider")
            return original(request)

        def caller():
            answer = gateway.evaluate({}, {"q": QUESTION}, metadata={})
            completed.append((answer, gateway.last_receipt, gateway.last_call_stats))

        with patch.object(provider, "decide", side_effect=dispatch):
            thread = threading.Thread(target=caller)
            thread.start()
            try:
                self.assertTrue(entered.wait(10))
                with self.assertRaises(ProviderError) as caught:
                    gateway.evaluate({}, {"q": QUESTION}, metadata={})
                self.assertEqual(caught.exception.code, "transport_failed")
                self.assertIsNone(gateway.last_receipt)
                self.assertIsNone(gateway.last_call_stats)
            finally:
                release.set()
                thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0][0]["q"]["noul"], Decimal(".13"))
        self.assertEqual(completed[0][2]["usage"]["input_tokens"], 2)
