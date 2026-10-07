"""Local contracts and failure bookkeeping; zero service compatibility claims."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from decimal import Decimal
import io
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter.core import Config, Source, scan
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.protocol import ProviderError, QUESTION, encode_request
from decision_bug_hunter.providers import (ProviderIdentity, ProviderRequest,
                                          ProviderResponse, ValidatedGateway)
from tests.support import FixtureProvider, clean_provider_env


def without_credential():
    """Every provider credential, routing and proxy variable is cleared explicitly."""
    return clean_provider_env()


class SyntheticProvider:
    identity = ProviderIdentity("offline-contract-fixture", synthetic=True)

    def __init__(self, response=None, *, failure=None, fixture=None, secret=""):
        self.response = response
        self.failure = failure
        self.fixture = fixture
        self.secret = secret
        self.requests = []
        self.closed = False

    def require_available(self):
        return None

    def check_sensitive(self, *values):
        if self.secret and self.secret in repr(values):
            raise ProviderError("sensitive_input")

    def decide(self, request):
        self.requests.append(request)
        if self.failure:
            raise self.failure
        if self.fixture is not None:
            data = json.loads(request.payload)
            self.fixture.requests.append(data)
            return ProviderResponse(
                {qid: self.fixture.answer(qid, q, data["state"])
                 for qid, q in data["questions"].items()},
                {"input_tokens": 100, "output_tokens": len(data["questions"])})
        return self.response

    def close(self):
        self.closed = True


class ProviderBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = {"text": "private-source-sentinel", "context_scope": "declared_standalone"}
        self.questions = {"q": deepcopy(QUESTION)}
        self.good = {"q": {"type": "noul", "noul": Decimal(".9")}}

    def gateway(self, response=None, **kwargs):
        provider = SyntheticProvider(response or ProviderResponse(self.good), **kwargs)
        gateway = ValidatedGateway(provider, self.root / "receipts")
        self.addCleanup(gateway.close)
        return gateway, provider

    def evaluate(self, gateway):
        return gateway.evaluate(self.state, self.questions, metadata={"sequence": 1, "phase": "test"})

    def saved(self, gateway):
        return json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))

    def test_unavailable_before_any_source_read_output_or_network(self):
        output = self.root / "outputs"
        out, err = io.StringIO(), io.StringIO()
        with without_credential(), \
                patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")), \
                patch.object(Source, "read", side_effect=AssertionError("source read forbidden")), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["secret-target-name", "--scope", "standalone", "--provider", "openai",
                             "--output-dir", str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("provider_unavailable", err.getvalue())
        self.assertNotIn("secret-target-name", err.getvalue())
        self.assertFalse(output.exists())

    def test_unavailable_empty_library_scan_cannot_be_complete(self):
        gateway = ValidatedGateway(DecisionsProvider(environ={}), self.root / "receipts")
        with self.assertRaises(ProviderError) as caught:
            scan(Source.from_text(""), gateway, context_scope="declared_standalone")
        self.assertEqual(caught.exception.code, "provider_unavailable")
        self.assertFalse((self.root / "receipts").exists())

    def test_unavailable_adapter_reads_credentials_only_at_construction(self):
        provider = DecisionsProvider(environ={})
        gateway = ValidatedGateway(provider, self.root / "receipts")
        with patch.dict("os.environ", {"OPENAI_API_KEY": "offline-ignored-sentinel"}), \
                patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")):
            for operation in (provider.require_available,
                              lambda: provider.decide(ProviderRequest(b"{}", 1)),
                              lambda: self.evaluate(gateway)):
                with self.assertRaises(ProviderError) as caught:
                    operation()
                self.assertEqual(caught.exception.code, "provider_unavailable")
        self.assertIsNone(gateway.last_call_stats)

    def test_validated_receipt_has_hashes_and_no_raw_source(self):
        gateway, provider = self.gateway(ProviderResponse(self.good, {"input_tokens": 7, "output_tokens": 2}))
        self.assertEqual(self.evaluate(gateway), self.good)
        saved = self.saved(gateway)
        self.assertEqual(saved["status"], "validated")
        self.assertTrue(saved["synthetic"])
        self.assertEqual(saved["usage"], {"input_tokens": 7, "output_tokens": 2})
        self.assertNotIn(self.state["text"], json.dumps(saved))
        self.assertEqual(len(provider.requests), 1)

    def test_invalid_last_answer_rejects_whole_batch_and_keeps_usage(self):
        self.questions["last"] = deepcopy(QUESTION)
        gateway, _ = self.gateway(ProviderResponse({**self.good, "last": {"type": "noul", "noul": "0.9"}},
                                                  {"input_tokens": 8, "output_tokens": 3}))
        with self.assertRaises(ProviderError):
            self.evaluate(gateway)
        saved = self.saved(gateway)
        self.assertEqual(saved["status"], "failed")
        self.assertIsNone(saved["answers"])
        self.assertEqual(saved["usage"]["input_tokens"], 8)

    def test_missing_probability_is_not_synthesized_from_boolean(self):
        gateway, _ = self.gateway(ProviderResponse({"q": {"type": "noul", "noul": True}}))
        with self.assertRaises(ProviderError) as caught:
            self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "response_probability")
        self.assertIsNone(self.saved(gateway)["answers"])

    def test_missing_answer_and_extra_answer_both_fail_atomically(self):
        for answers in ({}, {**self.good, "extra": self.good["q"]}):
            with self.subTest(answers=answers):
                gateway, _ = self.gateway(ProviderResponse(answers))
                with self.assertRaises(ProviderError):
                    self.evaluate(gateway)
                self.assertIsNone(self.saved(gateway)["answers"])

    def test_unknown_usage_stays_unknown_in_report(self):
        class NoUsage(SyntheticProvider):
            def decide(self, request):
                response = super().decide(request)
                return ProviderResponse(response.answers)
        provider = NoUsage(fixture=FixtureProvider())
        with ValidatedGateway(provider, self.root / "receipts") as gateway:
            report = scan(Source.from_text("line\n"), gateway,
                          Config(whole_file=False, bug_lenses=False, max_action_steps=0),
                          context_scope="declared_standalone")
        self.assertGreater(report["usage"]["attempts_with_unknown_usage"], 0)
        self.assertEqual(report["usage"]["attempts_with_known_usage"], 0)
        self.assertTrue(report["synthetic"])
        self.assertIsNone(report["model"])

    def test_invalid_usage_is_a_limitation_not_zero_tokens(self):
        gateway, _ = self.gateway(ProviderResponse(self.good, {"input_tokens": True, "output_tokens": 0}))
        with self.assertRaises(ProviderError) as caught:
            self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "response_usage")
        self.assertIsNone(self.saved(gateway)["usage"])

    def test_truncated_reply_preserves_usage_without_answers(self):
        gateway, _ = self.gateway(ProviderResponse(self.good, {"input_tokens": 2, "output_tokens": 1}, False))
        with self.assertRaises(ProviderError) as caught:
            self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "response_truncated")
        self.assertEqual(self.saved(gateway)["usage"]["input_tokens"], 2)

    def test_wrong_choice_argmax_and_impossible_mass_are_rejected(self):
        self.questions = {"pick": {"type": "choice", "instructions": "Choose.", "criteria": {"a": "A", "b": "B"}}}
        for values, chosen, code in (({"a": .4, "b": .6}, "a", "choice_argmax_mismatch"),
                                     ({"a": .7, "b": .7}, "a", "response_distribution")):
            with self.subTest(code=code):
                gateway, _ = self.gateway(ProviderResponse({"pick": {"type": "choice", "choice": chosen,
                        "confidence": .9, "probabilities": values}}))
                with self.assertRaises(ProviderError) as caught:
                    self.evaluate(gateway)
                self.assertEqual(caught.exception.code, code)

    def test_strict_default_and_explicit_rounding_never_renormalize(self):
        self.questions = {"pick": {"type": "choice", "instructions": "Choose.", "criteria": {"a": "A", "b": "B", "c": "C"}}}
        response = ProviderResponse({"pick": {"type": "choice", "choice": "a", "confidence": .9,
                                              "probabilities": {"a": .6, "b": .2, "c": .19}}})
        gateway, _ = self.gateway(response)
        with self.assertRaises(ProviderError):
            self.evaluate(gateway)
        gateway.rounding_places = 2
        answer = self.evaluate(gateway)
        self.assertEqual(sum(answer["pick"]["probabilities"].values()), Decimal(".99"))

    def test_expired_deadline_does_not_dispatch_or_write_receipt(self):
        gateway, provider = self.gateway()
        gateway.set_run_deadline(time.monotonic() - 1)
        with self.assertRaises(ProviderError) as caught:
            self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "run_deadline_exceeded")
        self.assertEqual(provider.requests, [])
        self.assertFalse((self.root / "receipts").exists())

    def test_effective_timeout_is_remaining_run_budget(self):
        gateway, provider = self.gateway()
        gateway.set_run_deadline(time.monotonic() + 5)
        self.evaluate(gateway)
        self.assertGreater(provider.requests[0].timeout_seconds, 0)
        self.assertLessEqual(provider.requests[0].timeout_seconds, 5)

    def test_late_complete_answer_is_kept_marked_late_and_not_blocking(self):
        # ADR-2(7): a complete 200 after the deadline was paid for; it is
        # accepted with ``late: true`` (it used to be discarded and block).
        gateway, provider = self.gateway(
            ProviderResponse(self.good, {"input_tokens": 1, "output_tokens": 1}))
        clock = [1.0]
        original = provider.decide

        def slow(request):
            clock[0] += 31.0
            return original(request)

        provider.decide = slow
        with patch("decision_bug_hunter.providers.time.monotonic", side_effect=lambda: clock[0]):
            answers = self.evaluate(gateway)
        self.assertIn("q", answers)
        saved = self.saved(gateway)
        self.assertIs(saved["late"], True)
        self.assertEqual(saved["status"], "validated")
        self.assertEqual(saved["usage"]["input_tokens"], 1)
        self.assertIsNone(gateway.stop_reason)
        self.evaluate(gateway)
        self.assertEqual(len(provider.requests), 2)

    def test_initial_journal_failure_prevents_dispatch(self):
        gateway, provider = self.gateway()
        with patch("decision_bug_hunter.providers._write_receipt", side_effect=ProviderError("receipt_failed")):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "receipt_failed")
        self.assertEqual(provider.requests, [])

    def test_terminal_journal_failure_keeps_dispatching_and_blocks_reuse(self):
        from decision_bug_hunter.providers import _write_receipt
        gateway, provider = self.gateway()
        def fail_final(path, receipt):
            if receipt["status"] != "dispatching":
                raise ProviderError("receipt_failed")
            _write_receipt(path, receipt)
        with patch("decision_bug_hunter.providers._write_receipt", side_effect=fail_final):
            with self.assertRaises(ProviderError):
                self.evaluate(gateway)
        self.assertEqual(self.saved(gateway)["status"], "dispatching")
        with self.assertRaises(ProviderError):
            self.evaluate(gateway)
        self.assertEqual(len(provider.requests), 1)

    def test_arbitrary_provider_exception_is_safe_and_never_retried(self):
        gateway, provider = self.gateway(failure=RuntimeError("private-provider-secret"))
        for _ in range(2):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
            self.assertNotIn("private-provider-secret", str(caught.exception))
        self.assertEqual(len(provider.requests), 1)

    def test_keyboard_interrupt_records_uncertainty_and_blocks_reuse(self):
        gateway, provider = self.gateway(failure=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.evaluate(gateway)
        self.assertEqual(self.saved(gateway)["error"], "interrupted")
        self.assertTrue(self.saved(gateway)["submission_possible"])
        with self.assertRaises(ProviderError):
            self.evaluate(gateway)
        self.assertEqual(len(provider.requests), 1)

    def test_receipt_stats_and_answers_own_mutable_snapshots(self):
        gateway, _ = self.gateway(ProviderResponse(self.good, {"input_tokens": 4, "output_tokens": 1}))
        result = self.evaluate(gateway)
        self.good["q"]["noul"] = Decimal(".1")
        stats = gateway.last_call_stats
        stats["usage"]["input_tokens"] = 999
        self.assertEqual(result["q"]["noul"], Decimal(".9"))
        self.assertEqual(gateway.last_call_stats["usage"]["input_tokens"], 4)

    def test_input_preflight_and_sensitive_check_prevent_any_dispatch(self):
        gateway, provider = self.gateway(secret=self.state["text"])
        with self.assertRaises(ProviderError) as caught:
            self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "sensitive_input")
        self.assertEqual(provider.requests, [])
        self.assertFalse((self.root / "receipts").exists())

    def test_fixture_cli_exercises_engine_output_and_source_nonexecution(self):
        source = self.root / "target.py"
        marker = self.root / "executed.txt"
        source.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n", encoding="utf-8")
        provider = SyntheticProvider(fixture=FixtureProvider([(2, 2)]))
        out, err = io.StringIO(), io.StringIO()
        with patch.object(cli, "make_provider", return_value=provider), \
                patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main([str(source), "--scope", "standalone", "--output-dir", str(self.root / "runs"),
                             "--no-whole-file", "--no-bug-lenses", "--max-action-steps", "0"])
        self.assertEqual(code, 1, err.getvalue())
        self.assertFalse(marker.exists())
        report = json.loads(next((self.root / "runs").glob("run-*/report.json")).read_text())
        self.assertTrue(report["synthetic"])
        self.assertGreater(report["calls_attempted"], 0)
        self.assertTrue(provider.closed)

    def test_fresh_runs_have_identical_requests_and_reports_for_both_policies(self):
        from tests.test_beta_policy import RolesProvider, role_values
        source = Source.from_text("\n".join(f"fixture line {i}" for i in range(1, 13)))
        for policy in ("legacy-v1", "scoped-v2-beta"):
            runs, payloads = [], []
            for index in range(2):
                # The scoped contract has distinct support/refutation/missing roles.
                # An ordinary bug-screen fixture must not assign them the same score.
                def roles(qid, state, target):
                    present = target["start_line"] <= 7 <= target["end_line"]
                    return role_values(".95" if present else ".05",
                                       ".05" if present else ".95", ".05")
                provider = SyntheticProvider(fixture=RolesProvider(values=roles, bugs=[(7, 7)]))
                with ValidatedGateway(provider, self.root / f"receipts-{policy}-{index}") as gateway:
                    runs.append(scan(source, gateway,
                        Config(width=12, min_width=12, max_depth=0, whole_file=False,
                               bug_lenses=False, max_action_steps=0, max_localizations=1,
                               localization_beam_width=1, search_policy=policy),
                        context_scope="declared_standalone"))
                payloads.append([request.payload for request in provider.requests])
            self.assertEqual(payloads[0], payloads[1], policy)
            self.assertEqual(runs[0], runs[1], policy)
            self.assertEqual(runs[0]["status"], "complete", policy)
            self.assertTrue(runs[0]["findings"], policy)

    def test_failed_identical_request_is_not_retried_by_either_search_policy(self):
        from decision_bug_hunter.engine import Search
        from decision_bug_hunter.core import Span
        for policy in ("legacy-v1", "scoped-v2-beta"):
            provider = SyntheticProvider(ProviderResponse({}))
            with ValidatedGateway(provider, self.root / policy) as gateway:
                search = Search(Source.from_text("line"), gateway, Config(search_policy=policy), None)
                for _ in range(2):
                    self.assertEqual(search.ask(self.state, self.questions, Span(1, 1), "test"), {})
                self.assertEqual(len(provider.requests), 1)
                self.assertTrue(search.issues)

    def test_reentrant_dispatch_or_close_cannot_erase_the_outer_receipt(self):
        gateway, provider = self.gateway()
        original = provider.decide
        def reentrant(request):
            for operation in (lambda: self.evaluate(gateway), gateway.close):
                with self.assertRaises(ProviderError):
                    operation()
            return original(request)
        provider.decide = reentrant
        self.evaluate(gateway)
        self.assertIsNotNone(gateway.last_receipt)
        self.assertEqual(self.saved(gateway)["status"], "validated")
        self.assertEqual(len(provider.requests), 1)

    def test_failed_cleanup_keeps_ownership_and_blocks_new_dispatch(self):
        gateway, provider = self.gateway()
        attempts = []
        def cleanup():
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("private cleanup detail")
            provider.closed = True
        provider.close = cleanup
        with self.assertRaises(ProviderError) as caught:
            gateway.close()
        self.assertNotIn("private cleanup detail", str(caught.exception))
        with self.assertRaises(ProviderError):
            self.evaluate(gateway)
        self.assertEqual(provider.requests, [])
        gateway.close()
        self.assertTrue(provider.closed)
        self.assertEqual(len(attempts), 2)


class MissingChoiceDataTests(unittest.TestCase):
    def test_selected_option_does_not_fabricate_probabilities_or_confidence(self):
        question = {"type": "choice", "instructions": "Choose.", "criteria": {"a": "A", "b": "B"}}
        for answer in ({"type": "choice", "choice": "a"},
                       {"type": "choice", "choice": "a", "probabilities": {"a": 1, "b": 0}},
                       {"type": "choice", "choice": "a", "confidence": 1}):
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as td:
                provider = SyntheticProvider(ProviderResponse({"q": answer}, {"input_tokens": 2, "output_tokens": 1}))
                gateway = ValidatedGateway(provider, td)
                self.addCleanup(gateway.close)
                with self.assertRaises(ProviderError) as caught:
                    gateway.evaluate({}, {"q": question}, metadata={})
                self.assertEqual(caught.exception.code, "response_schema")
                self.assertIsNone(gateway.last_call_stats["answers"])
                self.assertEqual(gateway.last_call_stats["usage"]["input_tokens"], 2)


class AttemptBookkeepingTests(unittest.TestCase):
    def test_blocked_reuse_clears_statistics_without_rebooking_known_usage(self):
        from decision_bug_hunter.providers import _write_receipt
        with tempfile.TemporaryDirectory() as td:
            provider = SyntheticProvider(ProviderResponse({"q": {"type": "noul", "noul": .9}},
                                                         {"input_tokens": 17, "output_tokens": 3}))
            gateway = ValidatedGateway(provider, td)
            self.addCleanup(gateway.close)
            def fail_terminal(path, receipt):
                if receipt["status"] != "dispatching":
                    raise ProviderError("receipt_failed")
                _write_receipt(path, receipt)
            with patch("decision_bug_hunter.providers._write_receipt", side_effect=fail_terminal):
                with self.assertRaises(ProviderError):
                    gateway.evaluate({}, {"q": QUESTION}, metadata={})
            prior = gateway.last_call_stats
            self.assertEqual(prior["usage"]["input_tokens"], 17)
            with self.assertRaises(ProviderError):
                gateway.evaluate({"different": "state"}, {"q": QUESTION}, metadata={})
            self.assertEqual(len(provider.requests), 1)
            self.assertIsNone(gateway.last_call_stats)
            self.assertIsNone(gateway.last_receipt)
            self.assertEqual(prior["usage"]["input_tokens"], 17)


if __name__ == "__main__":
    unittest.main()
