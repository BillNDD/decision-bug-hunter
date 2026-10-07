"""Receipt copy discipline, the narrow call summary and the legacy-path oracle.

The fast paths in ``ValidatedGateway`` and ``Search.ask`` apply only when
``type(gw) is ValidatedGateway``. ``_Legacy`` takes the old path, and the
oracle checks that both paths produce the same reports and receipts.
"""
from decimal import Decimal
from copy import deepcopy
import json
from pathlib import Path
import random
import tempfile
import threading
import unittest
from unittest.mock import patch

from decision_bug_hunter import providers
from decision_bug_hunter.core import Config
from decision_bug_hunter.protocol import QUESTION, ProviderError
from decision_bug_hunter.providers import ProviderResponse, ValidatedGateway, _tree_copy
from tests.support import FixtureProvider, scan, source
from tests.test_provider_boundary import SyntheticProvider

#: Planted bugs as (start, end) inclusive line ranges of ``source(8)``.
BUGS = ((2, 3), (6, 6))
#: Keys that depend on the clock, the run identity or the file names.
VOLATILE_KEYS = {"run_id", "started_at_utc", "finished_at_utc", "logical_id", "late"}
SUMMARY_FIELDS = {"request_sha256", "model_returned", "answer_order_mismatch",
                  "logical_usage", "usage"}


class _Legacy(ValidatedGateway):
    """The same gateway, but not ``type(gw) is ValidatedGateway``: the old engine path."""


class FlakySynthetic(SyntheticProvider):
    """Raises the scripted failures first, then behaves like the base provider."""

    def __init__(self, failures, **kwargs):
        super().__init__(**kwargs)
        self.failures = list(failures)

    def decide(self, request):
        if self.failures:
            self.requests.append(request)
            raise self.failures.pop(0)
        return super().decide(request)


class MutatingSynthetic(SyntheticProvider):
    """Edits the caller's question objects while the provider call is in flight."""

    def __init__(self, questions, **kwargs):
        super().__init__(**kwargs)
        self.questions = questions

    def decide(self, request):
        self.questions["q"]["type"] = "choice"
        self.questions["q"]["instructions"] = "edited after encoding"
        self.questions["extra"] = {"type": "noul"}
        return super().decide(request)


def scrub(value):
    """Drop clock, identity and file-name fields so two runs can be compared."""
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items()
                if key not in VOLATILE_KEYS and not key.endswith(("_seconds", "_at_utc"))
                and "elapsed" not in key}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True)


def scramble(value):
    """Overwrite every nested dict and list in place, including the top level."""
    if isinstance(value, dict):
        for key in list(value):
            scramble(value[key])
            value[key] = "scrambled"
        value["extra"] = ["scrambled"]
    elif isinstance(value, list):
        for index, item in enumerate(value):
            scramble(item)
            value[index] = "scrambled"
        value.append("scrambled")


class CallSummaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = {"text": "private-source-sentinel", "context_scope": "declared_standalone"}
        self.questions = {"q": deepcopy(QUESTION)}
        self.good = {"q": {"type": "noul", "noul": Decimal(".9")}}

    def gateway(self, provider, label="receipts", gateway_class=ValidatedGateway, **kwargs):
        gateway = gateway_class(provider, self.root / label, **kwargs)
        self.addCleanup(gateway.close)
        return gateway

    def evaluate(self, gateway, questions=None):
        return gateway.evaluate(self.state, self.questions if questions is None else questions,
                                metadata={"sequence": 1, "phase": "test"})

    def saved(self, gateway):
        return json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))

    def run_scan(self, gateway_class, label, **options):
        provider = SyntheticProvider(fixture=FixtureProvider(BUGS))
        receipts = self.root / label
        with gateway_class(provider, receipts) as gateway:
            report = scan(source(8), gateway, Config(whole_file=False, **options))
        saved = [scrub(json.loads(path.read_text(encoding="utf-8")))
                 for path in receipts.glob("*.json")]
        return scrub(report), sorted(canonical(item) for item in saved)

    # (a) legacy-path oracle -------------------------------------------------
    def test_legacy_engine_path_matches_fast_path(self):
        for policy in ("legacy-v1", "scoped-v2-beta"):
            for canaries in ("on", "off"):
                with self.subTest(policy=policy, canaries=canaries):
                    fast = self.run_scan(ValidatedGateway, f"fast-{policy}-{canaries}",
                                         search_policy=policy, canaries=canaries)
                    legacy = self.run_scan(_Legacy, f"legacy-{policy}-{canaries}",
                                           search_policy=policy, canaries=canaries)
                    self.assertTrue(fast[1], "the scan must persist receipts")
                    self.assertEqual(fast[0], legacy[0])
                    self.assertEqual(fast[1], legacy[1])

    def test_engine_reads_summary_not_full_stats_on_fast_path(self):
        def refuse(_gateway):
            raise AssertionError("the engine must not copy the full receipt")

        with patch.object(ValidatedGateway, "last_call_stats", property(refuse)):
            report, receipts = self.run_scan(ValidatedGateway, "summary-only",
                                             search_policy="legacy-v1", canaries="on")
        self.assertTrue(receipts)
        self.assertIn("findings", report)

    # Summary contents -------------------------------------------------------
    def test_summary_has_the_engine_fields_and_only_those(self):
        gateway = self.gateway(SyntheticProvider(ProviderResponse(self.good)))
        self.assertIsNone(gateway.last_call_summary)
        self.evaluate(gateway)
        stats = gateway.last_call_stats
        summary = gateway.last_call_summary
        self.assertEqual(set(summary), SUMMARY_FIELDS)
        self.assertEqual(summary, {name: stats[name] for name in SUMMARY_FIELDS})

    def test_summary_omits_keys_the_receipt_lacks(self):
        provider = SyntheticProvider(failure=KeyboardInterrupt())
        gateway = self.gateway(provider)
        with self.assertRaises(KeyboardInterrupt):
            self.evaluate(gateway)
        stats = gateway.last_call_stats
        summary = gateway.last_call_summary
        self.assertNotIn("logical_usage", stats)
        self.assertNotIn("logical_usage", summary)
        self.assertEqual(set(summary), SUMMARY_FIELDS - {"logical_usage"})
        self.assertIsNone(summary["usage"])

    def test_summary_is_none_for_other_threads(self):
        gateway = self.gateway(SyntheticProvider(ProviderResponse(self.good)))
        self.evaluate(gateway)
        seen = []
        worker = threading.Thread(target=lambda: seen.append(
            (gateway.last_call_stats, gateway.last_call_summary)))
        worker.start()
        worker.join()
        self.assertEqual(seen, [(None, None)])

    # (b) ownership ----------------------------------------------------------
    def test_returned_stats_and_summary_are_owned_by_the_caller(self):
        gateway = self.gateway(SyntheticProvider(ProviderResponse(self.good)))
        self.evaluate(gateway)
        before_stats = canonical(gateway.last_call_stats)
        before_summary = canonical(gateway.last_call_summary)
        scramble(gateway.last_call_stats)
        scramble(gateway.last_call_summary)
        self.assertEqual(canonical(gateway.last_call_stats), before_stats)
        self.assertEqual(canonical(gateway.last_call_summary), before_summary)

    # (c) caller questions ---------------------------------------------------
    def test_answers_are_validated_against_the_questions_at_call_time(self):
        questions = {"q": deepcopy(QUESTION)}
        provider = MutatingSynthetic(questions, response=ProviderResponse(self.good))
        gateway = self.gateway(provider)
        answers = self.evaluate(gateway, questions)
        self.assertEqual(answers["q"]["type"], "noul")
        self.assertEqual(questions["q"]["type"], "choice")
        self.assertEqual(gateway.last_call_stats["question_count"], 1)
        questions["q"]["instructions"] = "changed after evaluate"
        self.assertEqual(gateway.last_call_stats["status"], "validated")

    # (d) copy count ---------------------------------------------------------
    def test_successful_evaluate_makes_no_deepcopy_call(self):
        gateway = self.gateway(SyntheticProvider(ProviderResponse(self.good)))
        calls = []
        real_deepcopy = providers.deepcopy

        def counting(value, memo=None):
            calls.append(type(value))
            return real_deepcopy(value, memo)

        with patch.object(providers, "deepcopy", counting):
            self.evaluate(gateway)
        self.assertEqual(calls, [])

    def test_tree_copy_keeps_shapes_shares_leaves_and_falls_back(self):
        leaf = Decimal("1.5")
        tree = {"a": [1, "x", None, leaf], "b": (2, {"c": [3.5]}), "d": True}
        copied = _tree_copy(tree)
        self.assertEqual(copied, tree)
        self.assertIsNot(copied["a"], tree["a"])
        self.assertIsInstance(copied["b"], tuple)
        self.assertIsNot(copied["b"][1]["c"], tree["b"][1]["c"])
        self.assertIs(copied["a"][3], leaf)

        class Mapping(dict):
            pass

        subclass = Mapping(k=[1])
        fallback = _tree_copy(subclass)
        self.assertIsInstance(fallback, Mapping)
        self.assertIsNot(fallback["k"], subclass["k"])

    def test_invalid_questions_raise_the_same_code_before_any_copy(self):
        for label, gateway_class in (("fast", ValidatedGateway), ("legacy", _Legacy)):
            with self.subTest(path=label):
                gateway = self.gateway(SyntheticProvider(ProviderResponse(self.good)),
                                       label=f"invalid-{label}", gateway_class=gateway_class)
                with self.assertRaises(ProviderError) as raised:
                    self.evaluate(gateway, {"q": (1, 2)})
                self.assertEqual(raised.exception.code, "invalid_request")
                self.assertEqual(gateway.logical_requests, 0)

    # (e) failure paths ------------------------------------------------------
    def test_interrupt_from_provider_leaves_persisted_receipt_as_stats(self):
        gateway = self.gateway(SyntheticProvider(failure=KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            self.evaluate(gateway)
        stats = gateway.last_call_stats
        self.assertEqual(stats["status"], "failed")
        self.assertEqual(stats["error"], "interrupted")
        self.assertEqual(stats, self.saved(gateway))

    def test_failing_dispatch_write_leaves_persisted_receipt_as_stats(self):
        gateway = self.gateway(SyntheticProvider(ProviderResponse(self.good)))
        real_write = providers._write_receipt
        writes = []

        def flaky(path, receipt):
            writes.append(path)
            if len(writes) == 1:
                raise OSError("disk full")
            return real_write(path, receipt)

        with patch.object(providers, "_write_receipt", flaky):
            with self.assertRaises(ProviderError) as raised:
                self.evaluate(gateway)
        self.assertEqual(raised.exception.code, "receipt_failed")
        stats = gateway.last_call_stats
        self.assertEqual(stats["error"], "receipt_failed")
        self.assertEqual(stats["submission"], "not_sent")
        self.assertEqual(stats, self.saved(gateway))

    def test_retry_then_success_reports_the_last_persisted_receipt(self):
        provider = FlakySynthetic([ProviderError("http_rate_limited")],
                                  response=ProviderResponse(self.good))
        gateway = self.gateway(provider, sleep=lambda seconds: None,
                               rng=random.Random(3))
        answers = self.evaluate(gateway)
        self.assertEqual(answers["q"]["type"], "noul")
        stats = gateway.last_call_stats
        self.assertEqual(stats["attempt"], 2)
        self.assertEqual(stats["logical_attempts"], 2)
        self.assertEqual(stats["logical_status"], "validated")
        self.assertEqual(stats, self.saved(gateway))
        self.assertEqual(gateway.last_call_summary["usage"], stats["usage"])


if __name__ == "__main__":
    unittest.main()
