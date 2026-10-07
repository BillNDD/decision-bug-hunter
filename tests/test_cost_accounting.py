"""Cost accounting, --max-cost and receipt fsync (ADR-9, WP-08 / rev-3 WP-07).

Offline only: scripted sockets or in-process providers, no key, no network,
no wall-clock waits. Amounts are compared exactly in Decimal.
"""
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import decisions, providers
from decision_bug_hunter.core import Config, Source
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.engine import Search
from decision_bug_hunter.hosted import PRICE_TABLE_DATE, ModelSpec
from decision_bug_hunter.openrouter import ROUTE as OPENROUTER_ROUTE
from decision_bug_hunter.protocol import ERROR_CODES, QUESTION, ProviderError, encode_request
from decision_bug_hunter.providers import (ProviderIdentity, ProviderResponse, RetryPolicy,
                                           ValidatedGateway, attempt_cost_bound, classify,
                                           usd, validate_max_cost)
from tests.fakes import FakeClock, FakeSleep, Reply, ScriptedHTTPS, seeded_rng
from tests.support import FixtureProvider, clean_provider_env, openrouter_body
from tests.test_decisions import KEY as OPENAI_KEY
from tests.test_decisions import QUESTIONS as OPENAI_QUESTIONS
from tests.test_decisions import STATE as OPENAI_STATE
from tests.test_decisions import documented
from tests.test_openrouter import ANSWERS, Harness, error_body, reply

ROOT = Path(__file__).resolve().parents[1]
SPEC = ModelSpec("offline-priced", price_in_per_mtok=Decimal("0.10"),
                 price_out_upper_per_mtok=Decimal("0"))
STATE = {"file": "cost.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "cost sample line"}]}],
         "context_scope": "declared_standalone"}
ONE = {"q": QUESTION}
NOUL = {"type": "noul", "noul": Decimal("0.5")}


def failure(code, **kwargs):
    return ProviderError(code, classification=classify(code, **kwargs))


def bound_for(state=STATE, questions=ONE, spec=SPEC):
    wire = encode_request(state, questions)
    return attempt_cost_bound(len(wire), len(questions), spec.price_in_per_mtok,
                              spec.price_out_upper_per_mtok)


def answered(request, usage=None, cost=None):
    names = json.loads(request.payload)["questions"]
    return ProviderResponse({name: dict(NOUL) for name in names}, usage, cost_usd=cost)


class PricedProvider:
    """In-process provider with a price table; replays outcomes, then answers.

    Each outcome is an exception to raise, a ``ProviderResponse``, or a
    callable taking the request. Afterwards ``respond(request)`` answers.
    """

    identity = ProviderIdentity("offline-priced", model="offline-priced", synthetic=True)

    def __init__(self, outcomes=(), *, spec=SPEC, respond=None):
        self.outcomes = list(outcomes)
        self.model_spec = spec
        self.respond = respond or (lambda request: answered(
            request, {"input_tokens": 1000, "output_tokens": 0}, Decimal("0.0001")))
        self.requests = []

    def require_available(self):
        return None

    def check_sensitive(self, *values):
        return None

    def decide(self, request):
        self.requests.append(request)
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome(request) if callable(outcome) else outcome
        return self.respond(request)

    def close(self):
        return None


class UnpricedProvider(PricedProvider):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.model_spec = None


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.clock = FakeClock()
        self.sleep = FakeSleep(self.clock)
        env = clean_provider_env()
        env.__enter__()
        self.addCleanup(env.__exit__, None, None, None)

    def gateway(self, provider, **kwargs):
        kwargs.setdefault("clock", self.clock)
        kwargs.setdefault("sleep", self.sleep)
        kwargs.setdefault("rng", seeded_rng(11))
        gateway = ValidatedGateway(provider, self.root / "receipts", **kwargs)
        self.addCleanup(gateway.close)
        return gateway

    def call(self, gateway, sequence=1, questions=ONE):
        try:
            return gateway.evaluate({**STATE, "total_lines": sequence}, questions,
                                    metadata={"sequence": sequence, "phase": "test"})
        except ProviderError as exc:
            return exc

    def last(self, gateway):
        return json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))

    def saved(self, directory=None):
        directory = self.root / "receipts" if directory is None else directory
        if not directory.exists():
            return []
        return [json.loads(path.read_text(encoding="utf-8"))
                for path in sorted(directory.glob("*.json"))]


def reconcile(testcase, receipts, spend):
    """Spend equals the sums of the receipts' cost fields, exactly."""
    sums = {"provider_reported": Decimal(0), "list_price_estimate": Decimal(0)}
    bound = Decimal(0)
    for receipt in receipts:
        testcase.assertIn(receipt["cost_source"], providers.COST_SOURCES)
        if receipt["cost_source"] in sums:
            sums[receipt["cost_source"]] += Decimal(receipt["cost_usd"])
        else:
            testcase.assertIsNone(receipt["cost_usd"])
        bound += Decimal(receipt["cost_bound_usd"])
    testcase.assertEqual(Decimal(spend["provider_reported_usd"]), sums["provider_reported"])
    testcase.assertEqual(Decimal(spend["estimated_usd"]), sums["list_price_estimate"])
    testcase.assertEqual(Decimal(spend["unknown_usage_upper_bound_usd"]), bound)
    testcase.assertEqual(Decimal(spend["upper_bound_usd"]),
                         sums["provider_reported"] + sums["list_price_estimate"] + bound)


class ReportedCostTests(Base):
    def test_reported_cost_decimal_summed(self):
        harness = Harness(self, [
            reply(openrouter_body(ANSWERS, input_tokens=8457, cost=0.0008457)),
            reply(openrouter_body(ANSWERS, input_tokens=3, cost=3e-7)),
            reply(openrouter_body(ANSWERS, input_tokens=1, cost=0.1))])
        costs = []
        for _ in range(3):
            outcome, receipt = harness.evaluate()
            self.assertNotIsInstance(outcome, ProviderError)
            self.assertEqual(receipt["cost_source"], "provider_reported")
            self.assertEqual(receipt["cost_bound_usd"], "0")
            costs.append(receipt["cost_usd"])
        self.assertEqual(costs, ["0.0008457", "0.0000003", "0.1"])
        spend = harness.gateway.spend
        # Exact Decimal sum; the float sum of the same values is not exact.
        self.assertEqual(Decimal(spend["provider_reported_usd"]), Decimal("0.1008460"))
        self.assertEqual((spend["estimated_usd"], spend["unknown_usage_upper_bound_usd"]),
                         ("0", "0"))
        self.assertEqual(spend["price_table_date"], PRICE_TABLE_DATE)
        self.assertEqual(PRICE_TABLE_DATE, "2026-10-06")
        self.assertEqual(spend["attempts"]["provider_reported"], 3)
        self.assertIsNone(spend["max_cost_usd"])

    def test_openai_usage_priced_at_list_price(self):
        script = ScriptedHTTPS([Reply(body=documented())], clock=self.clock,
                               host=decisions.HOST)
        provider = DecisionsProvider(OPENAI_KEY, environ={},
                                     exchange=script.exchange(decisions.HOST, decisions.PATH))
        gateway = self.gateway(provider)
        gateway.evaluate(OPENAI_STATE, OPENAI_QUESTIONS, metadata={"sequence": 1})
        receipt = self.last(gateway)
        # 42 input tokens at $0.10 per million; Luna bills no output.
        self.assertEqual(receipt["cost_source"], "list_price_estimate")
        self.assertEqual(Decimal(receipt["cost_usd"]), Decimal("0.0000042"))
        self.assertEqual(Decimal(gateway.spend["estimated_usd"]), Decimal("0.0000042"))
        self.assertEqual(gateway.spend["provider_reported_usd"], "0")

    def test_malformed_cost_unknown_not_zero(self):
        for bad in ("0.001", -1, 11, True, None):
            with self.subTest(cost=bad):
                body = json.loads(openrouter_body(ANSWERS, input_tokens=100))
                body["usage"]["cost"] = bad
                harness = Harness(self, [reply(json.dumps(body).encode())])
                outcome, receipt = harness.evaluate()
                self.assertNotIsInstance(outcome, ProviderError)
                self.assertEqual(receipt["provider_error"], {"cost_error": "invalid"})
                self.assertEqual((receipt["cost_usd"], receipt["cost_source"]), (None, "none"))
                bound = Decimal(receipt["cost_bound_usd"])
                # Never zero: at least the dispatch bound, and at least the
                # list price of the usage that was reported.
                self.assertGreater(bound, 0)
                self.assertGreaterEqual(bound, Decimal(100) * Decimal("0.10") / 1000000)
                spend = harness.gateway.spend
                self.assertEqual(spend["provider_reported_usd"], "0")
                self.assertEqual(spend["estimated_usd"], "0")
                self.assertEqual(Decimal(spend["unknown_usage_upper_bound_usd"]), bound)
                self.assertEqual(spend["attempts"]["unknown_bounded"], 1)
        # A custom provider's out-of-range or non-Decimal cost is caught too.
        for bad in (Decimal("NaN"), Decimal("-0.01"), Decimal("10"), 0.0001):
            with self.subTest(custom=bad):
                provider = PricedProvider(respond=lambda request, bad=bad: answered(
                    request, {"input_tokens": 10, "output_tokens": 0}, bad))
                gateway = ValidatedGateway(provider, self.root / f"r-{len(str(bad))}-{bad!s}")
                self.addCleanup(gateway.close)
                gateway.evaluate(STATE, ONE, metadata={"sequence": 1})
                receipt = self.last(gateway)
                self.assertEqual(receipt["provider_error"], {"cost_error": "invalid"})
                self.assertEqual(receipt["cost_source"], "none")
                self.assertEqual(Decimal(receipt["cost_bound_usd"]), bound_for())
                self.assertEqual(gateway.spend["provider_reported_usd"], "0")


class UnknownUsageBoundTests(Base):
    def test_unknown_usage_bound_excludes_not_sent_rejected_and_4xx(self):
        bound = bound_for()
        cases = [
            ("http_rejected", failure("http_rejected"), Decimal(0)),
            ("transport_failed", failure("transport_failed"), bound),
            ("request_too_large", failure("request_too_large"), Decimal(0)),
            ("http_server_error", failure("http_server_error"), bound),
            ("connect_failed", failure("connect_failed"), Decimal(0)),
            ("http_rate_limited", failure("http_rate_limited"), Decimal(0)),
            ("provider_moderated", failure("provider_moderated"), Decimal(0)),
            ("ok_without_usage", lambda request: answered(request), bound),
        ]
        provider = PricedProvider([outcome for _, outcome, _ in cases])
        gateway = self.gateway(provider, retry_policy=RetryPolicy.none())
        for sequence, (name, _, expected) in enumerate(cases, start=1):
            with self.subTest(case=name):
                self.call(gateway, sequence)
                receipt = self.last(gateway)
                self.assertIsNone(receipt["usage"])
                self.assertEqual((receipt["cost_usd"], receipt["cost_source"]), (None, "none"))
                self.assertEqual(Decimal(receipt["cost_bound_usd"]), expected)
        spend = gateway.spend
        self.assertEqual(Decimal(spend["unknown_usage_upper_bound_usd"]), 3 * bound)
        self.assertEqual(spend["attempts"]["unknown_bounded"], 3)
        self.assertEqual(spend["attempts"]["not_billable"], 5)
        reconcile(self, self.saved(), spend)
        # A real terminal 4xx from the hosted route adds nothing either.
        harness = Harness(self, [reply(error_body(400), status=400)])
        outcome, receipt = harness.evaluate()
        self.assertEqual(outcome.code, "http_rejected")
        self.assertEqual(receipt["cost_bound_usd"], "0")
        self.assertEqual(harness.gateway.spend["unknown_usage_upper_bound_usd"], "0")

    def test_output_bound_uses_model_spec_price(self):
        spec = ModelSpec("offline-priced", price_in_per_mtok=Decimal("0.10"),
                         price_out_upper_per_mtok=Decimal("2.5"))
        two = {"q": QUESTION, "r": QUESTION}
        provider = PricedProvider(respond=answered, spec=spec)
        gateway = self.gateway(provider)
        self.call(gateway, 1, two)
        wire = encode_request({**STATE, "total_lines": 1}, two)
        allowance = 64 * 2
        expected = (Decimal(len(wire) + allowance) * Decimal("0.10")
                    + Decimal(allowance) * Decimal("2.5")) / Decimal(1000000)
        receipt = self.last(gateway)
        self.assertEqual(Decimal(receipt["cost_bound_usd"]), expected)
        self.assertEqual(receipt["cost_bound_usd"], usd(expected))
        # Both shipped routes price Luna output at zero.
        self.assertEqual(OPENROUTER_ROUTE.model().price_out_upper_per_mtok, Decimal(0))
        self.assertEqual(decisions.ROUTE.model().price_out_upper_per_mtok, Decimal(0))
        # The hosted adapter's wire size, not the local envelope, sizes the bound.
        script = ScriptedHTTPS([Reply(body=documented(usage=None))], clock=self.clock,
                               host=decisions.HOST)
        hosted = DecisionsProvider(OPENAI_KEY, environ={},
                                   exchange=script.exchange(decisions.HOST, decisions.PATH))
        envelope = encode_request(OPENAI_STATE, OPENAI_QUESTIONS)
        size = hosted.wire_size(envelope)
        self.assertEqual(size, len(hosted.encode(envelope)[0]))
        self.assertIsNone(hosted.wire_size(b"not an envelope"))
        self.assertIsNone(hosted.wire_size("text"))
        gateway = ValidatedGateway(hosted, self.root / "openai-receipts")
        self.addCleanup(gateway.close)
        try:
            gateway.evaluate(OPENAI_STATE, OPENAI_QUESTIONS, metadata={"sequence": 1})
        except ProviderError:
            pass
        receipt = self.last(gateway)
        model = decisions.ROUTE.model()
        self.assertEqual(Decimal(receipt["cost_bound_usd"]), attempt_cost_bound(
            max(size, len(envelope)), 2, model.price_in_per_mtok,
            model.price_out_upper_per_mtok))

    def test_unpriced_provider_reports_unknown_estimates(self):
        provider = UnpricedProvider()
        gateway = self.gateway(provider)
        self.call(gateway)
        receipt = self.last(gateway)
        self.assertEqual(receipt["cost_source"], "provider_reported")
        self.assertIsNone(receipt["cost_bound_usd"])
        spend = gateway.spend
        self.assertEqual(spend["provider_reported_usd"], "0.0001")
        for name in ("estimated_usd", "unknown_usage_upper_bound_usd", "upper_bound_usd",
                     "price_table_date"):
            self.assertIsNone(spend[name])


class BudgetTests(Base):
    def test_error_code_and_classification(self):
        self.assertIn("cost_budget_exhausted", ERROR_CODES)
        self.assertIn("cost_budget_exhausted", providers.STOP_REASONS)
        classification = classify("cost_budget_exhausted")
        self.assertEqual(classification.submission, "not_sent")
        self.assertFalse(classification.blocking)
        self.assertFalse(classification.submission_possible)

    def test_max_cost_validation(self):
        self.assertIsNone(validate_max_cost(None))
        self.assertEqual(validate_max_cost(Decimal("0.001")), Decimal("0.001"))
        self.assertEqual(validate_max_cost(5), Decimal(5))
        for bad in (Decimal(0), Decimal("-1"), Decimal("NaN"), Decimal("Infinity"),
                    Decimal("1000.01"), 0.5, "1", True):
            with self.subTest(value=bad), self.assertRaises(ProviderError) as caught:
                validate_max_cost(bad)
            self.assertEqual(caught.exception.code, "invalid_request")
        # A budget needs a price table to bound unknown usage.
        with self.assertRaises(ProviderError) as caught:
            ValidatedGateway(UnpricedProvider(), self.root / "x", max_cost=Decimal("1"))
        self.assertEqual(caught.exception.code, "invalid_request")
        self.assertFalse((self.root / "x").exists())

    def test_max_cost_stops_before_dispatch_including_retries(self):
        bound = bound_for()
        # The first attempt alone could exceed the budget: nothing is sent,
        # no receipt is written and the gateway stops.
        provider = PricedProvider()
        gateway = self.gateway(provider, max_cost=bound / 2)
        outcome = self.call(gateway)
        self.assertEqual(outcome.code, "cost_budget_exhausted")
        self.assertEqual(outcome.classification.submission, "not_sent")
        self.assertEqual((provider.requests, self.saved()), ([], []))
        self.assertEqual(gateway.stop_reason, "cost_budget_exhausted")
        self.assertEqual(gateway.attempts, 0)
        self.assertEqual(self.call(gateway, 2).code, "provider_stopped")
        self.assertEqual(provider.requests, [])
        # A budget of exactly one bound allows that attempt.
        provider = PricedProvider([lambda request: answered(request)])
        gateway = ValidatedGateway(provider, self.root / "exact", max_cost=bound)
        self.addCleanup(gateway.close)
        gateway.evaluate(STATE, ONE, metadata={"sequence": 1})
        self.assertEqual(len(provider.requests), 1)
        # A retry is checked too: after a possible submission without usage
        # (its bound is now spent), the retry's own bound does not fit.
        provider = PricedProvider([failure("transport_failed")])
        gateway = ValidatedGateway(provider, self.root / "retry",
                                   retry_policy=RetryPolicy(possible=1),
                                   max_cost=bound * Decimal("1.5"),
                                   clock=self.clock, sleep=self.sleep, rng=seeded_rng(3))
        self.addCleanup(gateway.close)
        with self.assertRaises(ProviderError) as caught:
            gateway.evaluate(STATE, ONE, metadata={"sequence": 1})
        self.assertEqual(caught.exception.code, "transport_failed")
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(self.sleep.calls, [])
        receipts = self.saved(self.root / "retry")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["retry_abandoned"], "cost_budget")
        self.assertEqual(receipts[0]["logical_attempts"], 1)
        self.assertEqual(gateway.stop_reason, "cost_budget_exhausted")
        with self.assertRaises(ProviderError) as caught:
            gateway.evaluate(STATE, ONE, metadata={"sequence": 2})
        self.assertEqual(caught.exception.code, "provider_stopped")
        self.assertEqual(len(provider.requests), 1)
        self.assertLessEqual(Decimal(gateway.spend["upper_bound_usd"]), bound * Decimal("1.5"))
        self.assertEqual(gateway.spend["max_cost_usd"], usd(bound * Decimal("1.5")))
        # With room for it, the same retry is sent.
        provider = PricedProvider([failure("transport_failed")])
        gateway = ValidatedGateway(provider, self.root / "room",
                                   retry_policy=RetryPolicy(possible=1),
                                   max_cost=bound * 3, clock=self.clock, sleep=self.sleep,
                                   rng=seeded_rng(3))
        self.addCleanup(gateway.close)
        gateway.evaluate(STATE, ONE, metadata={"sequence": 1})
        self.assertEqual(len(provider.requests), 2)
        self.assertIsNone(gateway.stop_reason)

    def test_max_cost_bounds_a_1000_call_gateway_loop(self):
        limit = Decimal("0.001")
        provider = PricedProvider(respond=lambda request: answered(
            request, {"input_tokens": len(request.payload),
                      "output_tokens": 0},
            Decimal(len(request.payload)) * Decimal("1E-7")))
        gateway = self.gateway(provider, max_cost=limit)
        refused = None
        for sequence in range(1, 1001):
            outcome = self.call(gateway, sequence)
            if isinstance(outcome, ProviderError):
                refused = (sequence, outcome.code)
                break
        self.assertIsNotNone(refused)
        self.assertEqual(refused[1], "cost_budget_exhausted")
        self.assertLess(len(provider.requests), 1000)
        spent = Decimal(gateway.spend["upper_bound_usd"])
        self.assertLessEqual(spent, limit)
        # The refused attempt would have crossed the limit.
        self.assertGreater(spent + bound_for({**STATE, "total_lines": refused[0]}), limit)
        reconcile(self, self.saved(), gateway.spend)


class CliBudgetTests(unittest.TestCase):
    #: Nine fixture requests of up to 24 KiB without a budget.
    LINES = 60

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.target = self.root / "target.py"
        self.target.write_text("".join(f"value_{i} = {i} + 1\n" for i in range(self.LINES)),
                               encoding="utf-8")

    def provider(self):
        fixture = FixtureProvider()

        def respond(request):
            data = json.loads(request.payload)
            tokens = len(request.payload) // 3
            return ProviderResponse(
                {qid: fixture.answer(qid, q, data["state"])
                 for qid, q in data["questions"].items()},
                {"input_tokens": tokens, "output_tokens": 0},
                cost_usd=Decimal(tokens) * Decimal("1E-7"))

        return PricedProvider(respond=respond, spec=OPENROUTER_ROUTE.model())

    def run_cli(self, out, *flags):
        provider = self.provider()
        stdout, stderr = io.StringIO(), io.StringIO()
        with clean_provider_env(), patch.object(cli, "make_provider", return_value=provider), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = cli.main([str(self.target), "--scope", "isolate", "--provider",
                                 "openrouter", "--output-dir", str(out), "--max-calls", "1000",
                                 *flags])
            except SystemExit as exc:
                code = exc.code
        runs = sorted(out.glob("run-*")) if out.exists() else []
        report = (json.loads((runs[0] / "report.json").read_text(encoding="utf-8"))
                  if runs else None)
        return code, stderr.getvalue(), report, runs, provider

    def test_max_cost_0_001_stops_a_1000_call_fixture_run(self):
        code, err, free, _, unbounded = self.run_cli(self.root / "free")
        self.assertIsNone(free["stop_reason"])
        self.assertIsNone(free["spend"]["max_cost_usd"])
        self.assertIn("Spend (USD): provider-reported ", err)
        self.assertGreater(Decimal(free["spend"]["upper_bound_usd"]), Decimal("0.005"))
        # The acceptance budget: one full 24 KiB request alone is bounded at
        # about $0.0025, so the run stops before such a request is sent.
        code, err, report, runs, provider = self.run_cli(self.root / "acceptance",
                                                          "--max-cost", "0.001")
        self.assertEqual(code, 2)
        self.assertEqual(report["stop_reason"], "cost_budget_exhausted")
        self.assertLessEqual(Decimal(report["spend"]["upper_bound_usd"]), Decimal("0.001"))
        self.assertLess(len(provider.requests), len(unbounded.requests))
        receipts = [json.loads(path.read_text(encoding="utf-8"))
                    for path in (runs[0] / "receipts").glob("*.json")]
        reconcile(self, receipts, report["spend"])
        # A budget that affords part of the run stops it midway.
        code, err, report, runs, provider = self.run_cli(self.root / "capped",
                                                          "--max-cost", "0.005")
        self.assertEqual(code, 2)
        self.assertEqual(report["stop_reason"], "cost_budget_exhausted")
        self.assertIn("Provider stopped (cost_budget_exhausted)", err)
        spend = report["spend"]
        self.assertEqual(spend["max_cost_usd"], "0.005")
        self.assertLessEqual(Decimal(spend["upper_bound_usd"]), Decimal("0.005"))
        self.assertGreater(len(provider.requests), 0)
        self.assertLess(len(provider.requests), len(unbounded.requests))
        self.assertEqual(report["calls_attempted"], len(provider.requests))
        codes = {issue["code"] for issue in report["issues"]}
        self.assertIn("cost_budget_exhausted", codes)
        self.assertNotIn("provider_stopped", codes)
        self.assertEqual(report["status"], "incomplete")
        receipts = [json.loads(path.read_text(encoding="utf-8"))
                    for path in (runs[0] / "receipts").glob("*.json")]
        self.assertEqual(len(receipts), len(provider.requests))
        reconcile(self, receipts, spend)

    def test_invalid_max_cost_fails_before_any_output(self):
        for value, expected in (("0", "Scan failed (invalid_request)."),
                                ("-1", "Scan failed (invalid_request)."),
                                ("1001", "Scan failed (invalid_request)."),
                                ("nan", "Invalid command-line arguments"),
                                ("abc", "Invalid command-line arguments")):
            with self.subTest(value=value):
                out = self.root / ("out-" + value)
                code, err, report, runs, provider = self.run_cli(out, "--max-cost", value)
                self.assertEqual(code, 2)
                self.assertIn(expected, err)
                self.assertFalse(out.exists())
                self.assertEqual(provider.requests, [])
        self.assertIsNone(cli.parser().parse_args(["x"]).max_cost)


class EngineSpendTests(Base):
    def search(self, gateway, lines=30):
        source = Source.from_text("\n".join(f"line {i}" for i in range(lines)), "a.txt")
        return Search(source, gateway, Config(), None, context_scope="declared_standalone")

    def test_engine_cost_refusal_is_not_a_call(self):
        provider = PricedProvider()
        gateway = self.gateway(provider, max_cost=Decimal("0.000001"))
        result = self.search(gateway).run()
        self.assertEqual(provider.requests, [])
        self.assertEqual((result["calls_attempted"], result["requests"]), (0, []))
        self.assertEqual(result["stop_reason"], "cost_budget_exhausted")
        codes = [issue["code"] for issue in result["issues"]]
        self.assertIn("cost_budget_exhausted", codes)
        self.assertNotIn("provider_stopped", codes)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["spend"]["max_cost_usd"], "0.000001")

    def test_report_spend_reconciles_with_receipts(self):
        fixture = FixtureProvider()
        turn = [0]

        def respond(request):
            turn[0] += 1
            data = json.loads(request.payload)
            answers = {qid: fixture.answer(qid, q, data["state"])
                       for qid, q in data["questions"].items()}
            kind = turn[0] % 3
            if kind == 1:
                return ProviderResponse(answers, {"input_tokens": 777, "output_tokens": 0},
                                        cost_usd=Decimal("0.0000777"))
            if kind == 2:
                return ProviderResponse(answers, {"input_tokens": 1234, "output_tokens": 0})
            return ProviderResponse(answers, None)

        provider = PricedProvider([failure("transport_failed"), failure("connect_failed")],
                                  respond=respond)
        gateway = self.gateway(provider)
        result = self.search(gateway).run()
        spend = result["spend"]
        self.assertEqual(spend, gateway.spend)
        reconcile(self, self.saved(), spend)
        attempts = spend["attempts"]
        self.assertGreater(attempts["provider_reported"], 0)
        self.assertGreater(attempts["list_price_estimate"], 0)
        self.assertGreater(attempts["unknown_bounded"], 0)
        self.assertEqual(attempts["not_billable"], 1)
        self.assertEqual(sum(attempts.values()), len(self.saved()))
        # A custom gateway without accounting reports no spend.
        search = Search(Source.from_text("alpha\nbeta"), FixtureProvider(), Config(), None,
                        context_scope="declared_standalone")
        self.assertIsNone(search.run()["spend"])

    def test_progress_line_shows_spend_bound(self):
        stream = io.StringIO()
        gateway = self.gateway(PricedProvider(), progress=stream)
        gateway.PROGRESS_EVERY_CALLS = 2
        self.call(gateway, 1)
        self.call(gateway, 2)
        line = stream.getvalue().strip()
        self.assertRegex(line, r"\Aprogress: calls=2 attempts=2 elapsed=\d+s "
                               r"remaining=none spend<=\$0\.000200\Z")


class ReceiptSyncTests(Base):
    def test_settlement_skips_dir_fsync_posix(self):
        provider = PricedProvider([failure("connect_failed")])
        gateway = ValidatedGateway(provider, self.root / "receipts", clock=self.clock,
                                   sleep=self.sleep, rng=seeded_rng(5))
        real_fsync = os.fsync
        with patch.object(providers, "_sync_directory") as directory_sync, \
                patch.object(providers.os, "fsync", side_effect=real_fsync) as file_sync:
            self.call(gateway, 1)
            self.call(gateway, 2)
            # Three attempts: one directory sync per dispatching write only,
            # and the file fsync on both writes of every attempt.
            self.assertEqual(gateway.attempts, 3)
            self.assertEqual(directory_sync.call_count, 3)
            self.assertEqual(file_sync.call_count, 6)
            gateway.close()
            self.assertEqual(directory_sync.call_count, 4)
            directory_sync.assert_called_with(self.root / "receipts")
            gateway.close()
            self.assertEqual(directory_sync.call_count, 4)
            # A gateway that never dispatched has nothing to sync.
            idle = ValidatedGateway(PricedProvider(), self.root / "idle")
            idle.close()
            self.assertEqual(directory_sync.call_count, 4)

    def test_sync_directory_is_posix_only(self):
        if os.name == "posix":
            real_fsync = os.fsync
            with patch.object(providers.os, "fsync", side_effect=real_fsync) as fsync:
                providers._sync_directory(self.root)
            self.assertEqual(fsync.call_count, 1)
        else:
            with patch.object(providers.os, "open",
                              side_effect=AssertionError("no directory handle")):
                providers._sync_directory(self.root)

    def test_crash_after_settlement_keeps_dispatching_receipt(self):
        provider = PricedProvider()
        gateway = self.gateway(provider)
        real_replace = os.replace
        calls = []

        def crash_on_settlement(source, target):
            calls.append(target)
            if len(calls) == 2:
                raise KeyboardInterrupt("simulated crash before the settlement rename")
            real_replace(source, target)

        with patch.object(providers.os, "replace", side_effect=crash_on_settlement):
            with self.assertRaises(KeyboardInterrupt):
                self.call(gateway)
        self.assertEqual(len(provider.requests), 1)
        files = list((self.root / "receipts").iterdir())
        self.assertEqual([path.suffix for path in files], [".json"])
        receipt = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "dispatching")
        self.assertEqual(receipt["submission"], "possible")
        self.assertIs(receipt["submission_possible"], True)
        self.assertIsNone(receipt["usage"])
        self.assertEqual(Decimal(receipt["cost_bound_usd"]), bound_for())
        # The interrupted gateway refuses further work.
        self.assertEqual(self.call(gateway, 2).code, "interrupted")

    def test_close_directory_sync_failure_is_receipt_failed(self):
        gateway = ValidatedGateway(PricedProvider(), self.root / "receipts")
        with patch.object(providers, "_sync_directory", side_effect=[None, OSError("disk")]):
            self.call(gateway)
            with self.assertRaises(ProviderError) as caught:
                gateway.close()
        self.assertEqual(caught.exception.code, "receipt_failed")


class BenchToolTests(unittest.TestCase):
    def test_bench_receipts_runs_locally(self):
        path = ROOT / "tools" / "bench_receipts.py"
        spec = importlib.util.spec_from_file_location("dbh_bench_receipts_under_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        write, sync = providers._write_receipt, providers._sync_directory
        with tempfile.TemporaryDirectory() as temp, clean_provider_env():
            result = module.bench(3, Path(temp))
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["threshold_ms"], 94.0)
        self.assertIn(result["verdict"], {"keep_json_receipts", "jsonl_journal_b2"})
        self.assertLessEqual(result["p50_ms"], result["max_ms"])
        self.assertIs(providers._write_receipt, write)
        self.assertIs(providers._sync_directory, sync)


if __name__ == "__main__":
    unittest.main()
