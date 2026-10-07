"""Submission classes, retries, breaker, reserve and engine stop (ADR-2(3)-(10)).

Offline only: scripted sockets or a scripted provider, a fake clock, a fake
sleep and a seeded generator. No test waits on the wall clock.
"""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from email.utils import format_datetime
import io
import json
from pathlib import Path
import re
import socket
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import decisions, openrouter
from decision_bug_hunter.core import Config, Source, Span
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.engine import Search
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import ERROR_CODES, QUESTION, ProviderError
from decision_bug_hunter.providers import (BREAKER_LIMITS, Breaker, ProviderIdentity,
                                           ProviderResponse, RetryPolicy, ValidatedGateway,
                                           classify)
from tests.fakes import (ConnectFailure, Delay, FakeClock, FakeSleep, Raise, Reply,
                         ScriptedHTTPS, seeded_rng)
from tests.support import FixtureProvider, clean_provider_env, openrouter_body
from tests.test_decisions import KEY, METADATA, QUESTIONS, STATE, documented

NOUL = {"q": {"type": "noul", "noul": Decimal("0.9")}}
#: Answers to test_decisions' QUESTIONS, which the fixture does not know.
FIXED = {"screen": {"type": "noul", "noul": 0.9},
         "where": {"type": "choice", "choice": "L1-1",
                   "probabilities": {"L1-1": 0.9, "none": 0.1}, "confidence": 0.8}}


def receipts(gateway):
    return [json.loads(Path(path).read_text(encoding="utf-8"))
            for path in gateway.last_receipts]


class ScriptedProvider:
    """A DecisionProvider replaying outcomes, then answering from a fixture.

    Each outcome is a ``ProviderResponse`` or an exception to raise. Once the
    script is empty, a ``FixtureProvider`` answers every question.
    """

    identity = ProviderIdentity("offline-scripted", synthetic=True)

    def __init__(self, outcomes=(), *, clock=None, elapsed=0.0):
        self.outcomes = list(outcomes)
        self.fixture = FixtureProvider()
        self.requests = []
        self.clock = clock
        self.elapsed = elapsed

    def require_available(self):
        return None

    def check_sensitive(self, *values):
        return None

    def decide(self, request):
        self.requests.append(request)
        if self.clock is not None and self.elapsed:
            self.clock.advance(self.elapsed)
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        data = json.loads(request.payload)
        return ProviderResponse({qid: FIXED.get(qid) or self.fixture.answer(qid, q, data["state"])
                                 for qid, q in data["questions"].items()},
                                {"input_tokens": 100, "output_tokens": 0})

    def close(self):
        return None


def failure(code, **kwargs):
    return ProviderError(code, classification=classify(code, **kwargs))


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.clock = FakeClock()
        self.sleep = FakeSleep(self.clock)
        guard = patch.object(socket, "create_connection",
                             side_effect=AssertionError("network forbidden"))
        guard.start()
        self.addCleanup(guard.stop)

    def gateway(self, provider, **kwargs):
        kwargs.setdefault("clock", self.clock)
        kwargs.setdefault("sleep", self.sleep)
        kwargs.setdefault("rng", seeded_rng(7))
        gateway = ValidatedGateway(provider, self.root / "receipts", **kwargs)
        self.addCleanup(gateway.close)
        return gateway

    def openai(self, steps, **kwargs):
        script = ScriptedHTTPS(list(steps), clock=self.clock, host=decisions.HOST)
        provider = DecisionsProvider(KEY, environ={},
                                     exchange=script.exchange(decisions.HOST, decisions.PATH))
        return script, self.gateway(provider, **kwargs)

    def call(self, gateway, sequence=1):
        try:
            return gateway.evaluate({**STATE, "sequence": sequence}, QUESTIONS,
                                    metadata={**METADATA, "sequence": sequence})
        except ProviderError as exc:
            return exc


class RetryTimingTests(Base):
    def test_not_sent_retries_three_with_full_jitter_capped(self):
        steps = [ConnectFailure(socket.gaierror("private-host")) for _ in range(4)]
        script, gateway = self.openai(steps)
        outcome = self.call(gateway)
        self.assertEqual(outcome.code, "connect_failed")
        self.assertEqual(len(script.connects), 4)
        self.assertEqual(len(self.sleep.calls), 3)
        # Full jitter: uniform(0, min(8, 0.5 * 2**retry)) for retries 1..3.
        for retry, wait in enumerate(self.sleep.calls, start=1):
            self.assertGreaterEqual(wait, 0.0)
            self.assertLessEqual(wait, min(8.0, 0.5 * 2 ** retry))
        saved = receipts(gateway)
        self.assertEqual([r["attempt"] for r in saved], [1, 2, 3, 4])
        self.assertEqual({r["submission"] for r in saved}, {"not_sent"})
        self.assertEqual({r["logical_id"] for r in saved}, {saved[0]["logical_id"]})
        self.assertEqual([r["waited_seconds"] for r in saved[1:]], self.sleep.calls)
        self.assertEqual(saved[-1]["logical_status"], "failed")
        self.assertTrue(all("logical_status" not in r for r in saved[:-1]))
        self.assertIsNone(gateway.stop_reason)
        # The cap holds for later retries too.
        policy = RetryPolicy(not_sent=6)
        script, gateway = self.openai([ConnectFailure() for _ in range(7)],
                                      retry_policy=policy, rng=seeded_rng(1))
        self.sleep.calls.clear()
        self.call(gateway)
        self.assertEqual(len(self.sleep.calls), 6)
        self.assertTrue(all(wait <= 8.0 for wait in self.sleep.calls))

    def test_retry_after_seconds_and_date_honored_capped(self):
        headers = [("Content-Type", "application/json"), ("Content-Length", "0")]
        for value, low, high in (("7", 7.0, 7.0), ("120", 60.0, 60.0)):
            with self.subTest(value=value):
                self.sleep.calls.clear()
                script, gateway = self.openai([
                    Reply(status=429, body=b"", headers=[*headers, ("Retry-After", value)]),
                    Reply(body=documented())])
                answers = self.call(gateway)
                self.assertEqual(answers["where"]["choice"], "L1-1")
                self.assertEqual(len(self.sleep.calls), 1)
                self.assertTrue(low <= self.sleep.calls[0] <= high)
                self.assertEqual(receipts(gateway)[0]["retry_after_seconds"], low)
        # An HTTP-date is read against the wall clock; allow for test runtime.
        when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=20), usegmt=True)
        self.sleep.calls.clear()
        script, gateway = self.openai([
            Reply(status=429, body=b"", headers=[*headers, ("Retry-After", when)]),
            Reply(body=documented())])
        self.call(gateway)
        self.assertTrue(10.0 <= self.sleep.calls[0] <= 20.0, self.sleep.calls)
        # Without Retry-After, rejected requests use uniform(0, min(30, 2**retry)).
        self.sleep.calls.clear()
        script, gateway = self.openai([Reply(status=429, body=b"", headers=headers)
                                       for _ in range(4)])
        self.assertEqual(self.call(gateway).code, "http_rate_limited")
        self.assertEqual(len(self.sleep.calls), 3)
        for retry, wait in enumerate(self.sleep.calls, start=1):
            self.assertLessEqual(wait, min(30.0, 2.0 ** retry))

    def test_possible_timeout_not_retried(self):
        script, gateway = self.openai([Reply(body=documented(), delay_before=120.0),
                                       Reply(body=documented())])
        outcome = self.call(gateway)
        self.assertEqual(outcome.code, "deadline_exceeded")
        self.assertEqual((len(script.requests), self.sleep.calls), (1, []))
        saved = receipts(gateway)
        self.assertEqual(len(saved), 1)
        self.assertIs(saved[0]["submission_possible"], True)
        self.assertIsNone(gateway.stop_reason)

    def test_wait_never_crosses_run_budget(self):
        headers = [("Content-Type", "application/json"), ("Content-Length", "0"),
                   ("Retry-After", "30")]
        script, gateway = self.openai([Reply(status=429, body=b"", headers=headers),
                                       Reply(body=documented())])
        gateway.set_run_deadline(self.clock() + 20.0)
        outcome = self.call(gateway)
        self.assertEqual(outcome.code, "http_rate_limited")
        self.assertEqual(self.sleep.calls, [])
        saved = receipts(gateway)
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["retry_abandoned"], "run_deadline")
        # Jittered waits stop short of the deadline minus the reserve.
        deadline = self.clock() + 6.0
        script, gateway = self.openai([ConnectFailure() for _ in range(4)],
                                      rng=seeded_rng(3))
        gateway.set_run_deadline(deadline)
        self.call(gateway)
        self.assertLessEqual(self.clock(), deadline - gateway.reserve_seconds())


class StaleConnectionTests(Base):
    def reused(self, failing, *later):
        """A first call that leaves a kept-alive socket, then ``failing``."""
        script, gateway = self.openai([Reply(body=documented()), failing, *later])
        self.assertEqual(self.call(gateway)["where"]["choice"], "L1-1")
        outcome = self.call(gateway, 2)
        return script, gateway, outcome

    def test_stale_reused_connection_retried_once_flagged(self):
        for label, failing in (("reset", Reply(events=[Raise(ConnectionResetError("x"))])),
                               ("eof", Reply(events=[], close_after=True))):
            with self.subTest(label=label):
                script, gateway, answers = self.reused(failing, Reply(body=documented()))
                self.assertEqual(answers["where"]["choice"], "L1-1")
                self.assertEqual(len(script.connects), 2)
                self.assertEqual(self.sleep.calls, [])
                first, second = receipts(gateway)
                self.assertEqual(first["error"], "transport_failed")
                self.assertIs(first["provider_error"]["reused"], True)
                self.assertEqual(second["retry_reason"], "stale_connection")
                self.assertIs(second["duplicate_billing_possible"], True)
                self.assertEqual(second["logical_status"], "validated")
                self.assertEqual(gateway.retries, 1)
        # Only once: the retry runs on a fresh connection, so its own reset
        # is an ordinary possible-submission failure and final.
        script, gateway, outcome = self.reused(
            Reply(events=[Raise(ConnectionResetError("x"))]),
            Reply(events=[Raise(ConnectionResetError("x"))]))
        self.assertEqual(outcome.code, "transport_failed")
        self.assertEqual([r["error"] for r in receipts(gateway)],
                         ["transport_failed", "transport_failed"])
        self.assertEqual(receipts(gateway)[1]["logical_status"], "failed")

    def test_reused_connection_timeout_not_retried(self):
        script, gateway, outcome = self.reused(Reply(events=[Raise(TimeoutError("x"))]),
                                               Reply(body=documented()))
        self.assertEqual(outcome.code, "deadline_exceeded")
        self.assertEqual(len(receipts(gateway)), 1)
        self.assertEqual(len(script.requests), 2)

    def test_reused_connection_reset_after_1s_not_retried(self):
        script, gateway, outcome = self.reused(
            Reply(events=[Delay(1.5), Raise(ConnectionResetError("x"))]),
            Reply(body=documented()))
        self.assertEqual(outcome.code, "transport_failed")
        self.assertEqual(len(receipts(gateway)), 1)

    def test_reused_connection_partial_response_not_retried(self):
        script, gateway, outcome = self.reused(
            Reply(events=[b"HTTP/1.1 200 OK\r\n", Raise(ConnectionResetError("x"))]),
            Reply(body=documented()))
        self.assertEqual(outcome.code, "transport_failed")
        self.assertEqual(len(receipts(gateway)), 1)

    def test_no_retry_flag_single_attempt(self):
        script, gateway = self.openai([ConnectFailure(), Reply(body=documented())],
                                      retry_policy=RetryPolicy.none())
        self.assertEqual(self.call(gateway).code, "connect_failed")
        self.assertEqual((len(script.connects), self.sleep.calls), (1, []))
        # The stale keep-alive retry is off too.
        script, gateway = self.openai(
            [Reply(body=documented()), Reply(events=[Raise(ConnectionResetError("x"))]),
             Reply(body=documented())], retry_policy=RetryPolicy.none())
        self.call(gateway)
        self.assertEqual(self.call(gateway, 2).code, "transport_failed")
        self.assertEqual(len(receipts(gateway)), 1)
        # The CLI flag selects that policy; the default keeps retries.
        captured = []

        def make_gateway(provider, receipt_dir, **kwargs):
            captured.append(kwargs)
            raise ProviderError("internal_error")

        with tempfile.TemporaryDirectory() as td, clean_provider_env(OPENAI_API_KEY=KEY):
            target = Path(td) / "a.txt"
            target.write_text("alpha\n", encoding="utf-8")
            for flags, expected in ((["--no-retry"], RetryPolicy.none()), ([], RetryPolicy())):
                with patch.object(cli, "make_gateway", side_effect=make_gateway), \
                        redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                    cli.main([str(target), "--scope", "isolate", "--provider", "openai",
                              "--output-dir", str(Path(td) / "out"), *flags])
                self.assertEqual(captured[-1]["retry_policy"], expected)
        self.assertEqual(cli.parser().parse_args(["x"]).run_deadline_seconds, 1800.0)
        self.assertEqual(Config().run_deadline_seconds, 1800.0)


class BreakerTests(Base):
    def test_breaker_trips_each_reason(self):
        cases = {
            "rate_limit_sustained": classify("http_rate_limited"),
            "provider_degraded": classify("http_server_error"),
            "network_unreachable": classify("connect_failed"),
            "contract_mismatch": classify("response_schema"),
        }
        for reason, outcome in cases.items():
            with self.subTest(reason=reason):
                breaker = Breaker()
                for _ in range(BREAKER_LIMITS[reason] - 1):
                    self.assertIsNone(breaker.record(outcome.code, outcome))
                # A success ends the streak.
                breaker.record(None, None)
                for _ in range(BREAKER_LIMITS[reason] - 1):
                    self.assertIsNone(breaker.record(outcome.code, outcome))
                self.assertEqual(breaker.record(outcome.code, outcome), reason)
        # Degraded counts every possible-submission failure kind together.
        breaker = Breaker()
        for code in ("transport_failed", "http_unavailable", "provider_error_in_body"):
            breaker.record(code, classify(code))
        self.assertEqual(breaker.stop_reason, "provider_degraded")
        # Moderation: 8 of the last 10, interleaving allowed.
        breaker = Breaker()
        moderated = classify("provider_moderated")
        for index in range(10):
            if index in (3, 6):
                breaker.record(None, None)
            else:
                breaker.record("provider_moderated", moderated)
        self.assertEqual(breaker.stop_reason, "provider_moderation_sustained")
        # Blocking codes stop at once; local refusals are neutral.
        breaker = Breaker()
        breaker.record("sensitive_input", classify("sensitive_input"))
        breaker.record("connect_failed", classify("connect_failed"))
        breaker.record("run_deadline_reserved", classify("run_deadline_reserved"))
        breaker.record("connect_failed", classify("connect_failed"))
        self.assertIsNone(breaker.stop_reason)
        breaker.record("http_unauthorized", classify("http_unauthorized"))
        self.assertEqual(breaker.stop_reason, "blocked:http_unauthorized")
        # Through the gateway: three degraded logical requests stop dispatch.
        provider = ScriptedProvider([failure("http_server_error") for _ in range(3)])
        gateway = self.gateway(provider)
        for sequence in (1, 2, 3):
            self.assertEqual(self.call(gateway, sequence).code, "http_server_error")
        self.assertEqual((gateway.stop_reason, gateway.stopped_at_sequence),
                         ("provider_degraded", 3))
        self.assertEqual(self.call(gateway, 4).code, "provider_stopped")
        self.assertEqual(len(provider.requests), 3)

    def test_openrouter_503_routing_blocks_not_rate_limit(self):
        def harness(steps):
            script = ScriptedHTTPS(list(steps), clock=self.clock, host=openrouter.HOST)
            provider = OpenRouterProvider(KEY, environ={}, exchange=script.exchange(
                openrouter.HOST, openrouter.PATH))
            return script, self.gateway(provider)

        routing = json.dumps({"error": {"code": 503, "message": "private",
                                        "metadata": {"failed_routing_step": "x"}}}).encode()
        script, gateway = harness([Reply(status=503, body=routing), Reply(status=503, body=routing)])
        self.assertEqual(self.call(gateway).code, "routing_no_endpoint")
        self.assertEqual((len(script.requests), self.sleep.calls), (1, []))
        self.assertEqual(gateway.stop_reason, "blocked:routing_no_endpoint")
        self.assertEqual(self.call(gateway, 2).code, "routing_no_endpoint")
        self.assertEqual(len(script.requests), 1)
        plain = json.dumps({"error": {"code": 503, "message": "private"}}).encode()
        script, gateway = harness([Reply(status=503, body=plain),
                                   Reply(body=openrouter_body(FIXED))])
        self.assertEqual(self.call(gateway)["where"]["choice"], "L1-1")
        self.assertEqual(len(script.requests), 2)
        self.assertEqual(receipts(gateway)[0]["error"], "http_unavailable")
        self.assertIsNone(gateway.stop_reason)


class ReceiptAndReserveTests(Base):
    def test_one_receipt_per_attempt_final_sums_usage(self):
        provider = ScriptedProvider([
            ProviderResponse({}, {"input_tokens": 7, "output_tokens": 1},
                             error="http_server_error"),
            ProviderResponse(NOUL, {"input_tokens": 5, "output_tokens": 2})])
        gateway = self.gateway(provider, retry_policy=RetryPolicy(possible=1))
        search = Search(Source.from_text("alpha"), gateway, Config(), None)
        answers = search.ask({"excerpts": []}, {"q": QUESTION}, Span(1, 1), "test")
        self.assertIn("q", answers)
        saved = receipts(gateway)
        self.assertEqual(len(saved), 2)
        self.assertEqual([r["attempt"] for r in saved], [1, 2])
        self.assertIs(saved[1]["duplicate_billing_possible"], True)
        self.assertEqual(saved[1]["logical_usage"], {"input_tokens": 12, "output_tokens": 3})
        for name in ("input_tokens", "output_tokens"):
            self.assertEqual(search.usage[name], sum(r["usage"][name] for r in saved))
        self.assertEqual((gateway.attempts_transmitted, gateway.retries), (2, 1))
        self.assertEqual(search.calls, 1)

    def test_reserve_refuses_dispatch_not_submitted(self):
        provider = ScriptedProvider()
        gateway = self.gateway(provider)
        gateway.set_run_deadline(self.clock() + 2.5)
        outcome = self.call(gateway)
        self.assertEqual(outcome.code, "run_deadline_reserved")
        self.assertIs(outcome.classification.submission_possible, False)
        self.assertEqual(provider.requests, [])
        self.assertFalse((self.root / "receipts").exists())
        self.assertIsNone(gateway.stop_reason)
        # The reserve grows with observed attempt durations: 1.5 x p95.
        provider = ScriptedProvider(clock=self.clock, elapsed=4.0)
        gateway = self.gateway(provider)
        gateway.set_run_deadline(self.clock() + 100.0)
        self.call(gateway)
        self.assertEqual(gateway.reserve_seconds(), 6.0)
        gateway.set_run_deadline(self.clock() + 5.0)
        self.assertEqual(self.call(gateway, 2).code, "run_deadline_reserved")
        self.assertEqual(len(provider.requests), 1)
        self.assertIn("run_deadline_reserved", ERROR_CODES)

    def test_dns_failure_does_not_end_run(self):
        steps = [ConnectFailure(socket.gaierror("x")) for _ in range(4)]
        script, gateway = self.openai([*steps, Reply(body=documented())])
        self.assertEqual(self.call(gateway).code, "connect_failed")
        self.assertIsNone(gateway.stop_reason)
        self.assertEqual(self.call(gateway, 2)["where"]["choice"], "L1-1")

    def test_interrupt_during_backoff_not_submitted(self):
        def interrupt(seconds):
            raise KeyboardInterrupt

        script, gateway = self.openai([ConnectFailure(), Reply(body=documented())],
                                      sleep=interrupt)
        with self.assertRaises(KeyboardInterrupt):
            self.call(gateway)
        first, last = receipts(gateway)
        self.assertEqual((first["error"], first["submission"]), ("connect_failed", "not_sent"))
        self.assertEqual(last["attempt"], 2)
        self.assertEqual((last["error"], last["submission"]), ("interrupted", "not_sent"))
        self.assertIs(last["submission_possible"], False)
        self.assertEqual(last["logical_status"], "failed")
        self.assertEqual(self.call(gateway, 2).code, "interrupted")
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        self.assertEqual(len(script.connects), 1)

    def test_progress_line_counts_only(self):
        stream = io.StringIO()
        provider = ScriptedProvider()
        gateway = self.gateway(provider, progress=stream)
        self.assertEqual((gateway.PROGRESS_EVERY_CALLS, gateway.PROGRESS_EVERY_SECONDS),
                         (100, 30.0))
        # A smaller call cadence keeps the test fast; the rule is the same.
        gateway.PROGRESS_EVERY_CALLS = 10
        gateway.set_run_deadline(self.clock() + 1800.0)
        for sequence in range(1, 10):
            self.call(gateway, sequence)
        self.assertEqual(stream.getvalue(), "")
        self.call(gateway, 10)
        self.clock.advance(31.0)
        self.call(gateway, 11)
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            # The scripted provider has no price table, so the spend bound
            # (ADR-9(5), added by WP-08) is unknown; priced runs show $X.
            self.assertRegex(line, r"\Aprogress: calls=\d+ attempts=\d+ elapsed=\d+s "
                                   r"remaining=\d+s spend<=unknown\Z")
        self.assertTrue(lines[0].startswith("progress: calls=10 attempts=10 "))
        self.assertTrue(lines[1].startswith("progress: calls=11 attempts=11 elapsed=31s "))
        self.assertNotIn(KEY, stream.getvalue())
        self.assertNotIn(str(self.root), stream.getvalue())


class EngineStopTests(Base):
    def scan(self, provider, lines=40, **config):
        gateway = self.gateway(provider)
        source = Source.from_text("\n".join(f"line {i}" for i in range(lines)), "a.txt")
        search = Search(source, gateway, Config(**config), None,
                        context_scope="declared_standalone")
        return search.run(), gateway

    def test_blocked_gateway_does_not_consume_calls(self):
        provider = ScriptedProvider([failure("http_unauthorized")])
        result, gateway = self.scan(provider)
        self.assertEqual(result["calls_attempted"], 1)
        self.assertEqual(len(result["requests"]), 1)
        self.assertEqual(len(provider.requests), 1)
        stopped = [i for i in result["issues"] if i["code"] == "provider_stopped"]
        self.assertEqual(stopped, [{"code": "provider_stopped", "range": [1, 40],
                                    "phase": "provider", "affects_completion": True}])
        self.assertEqual(result["stop_reason"], "blocked:http_unauthorized")
        self.assertEqual(result["stopped_at_sequence"], 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["usage"]["attempts_with_unknown_usage"], 1)
        self.assertEqual((result["attempts_transmitted"], result["retries"]), (1, 0))
        # A breaker stop ends the run the same way.
        provider = ScriptedProvider([failure("http_server_error") for _ in range(3)])
        result, gateway = self.scan(provider)
        self.assertEqual(result["stop_reason"], "provider_degraded")
        self.assertEqual(result["calls_attempted"], 3)
        self.assertEqual(sum(i["code"] == "provider_stopped" for i in result["issues"]), 1)
        # A reserve refusal is not a call and ends dispatch.
        provider = ScriptedProvider()
        gateway = self.gateway(provider)
        search = Search(Source.from_text("alpha\nbeta"), gateway, Config(), None,
                        deadline_at=None)
        gateway.set_run_deadline(self.clock() + 1.0)
        self.assertEqual(search.ask({"excerpts": []}, {"q": QUESTION}, Span(1, 1), "t"), {})
        self.assertEqual((search.calls, search.trace, provider.requests), (0, [], []))
        self.assertTrue(search.expired(Span(1, 1), "t"))

    def test_transient_failure_reasked_once_permanent_never(self):
        for code, expected in (("http_server_error", 2), ("response_schema", 1)):
            with self.subTest(code=code):
                provider = ScriptedProvider([failure(code) for _ in range(5)])
                gateway = self.gateway(provider)
                search = Search(Source.from_text("alpha"), gateway, Config(), None)
                for _ in range(3):
                    search.ask({"excerpts": []}, {"q": QUESTION}, Span(1, 1), "t")
                self.assertEqual(len(provider.requests), expected)
                phases = [e["phase"] for e in search.events]
                self.assertEqual(phases.count("failed_request_reasked"), expected - 1)
                self.assertEqual(phases.count("failed_request_not_retried"), 3 - expected)

    def test_custom_gateway_report_fields_are_none(self):
        source = Source.from_text("alpha\nbeta", "a.txt")
        result = Search(source, FixtureProvider(), Config(), None).run()
        for field in ("stop_reason", "stopped_at_sequence", "attempts_transmitted",
                      "retries"):
            self.assertIsNone(result[field])
        self.assertTrue(re.fullmatch(r"\d+", str(result["calls_attempted"])))


if __name__ == "__main__":
    unittest.main()
