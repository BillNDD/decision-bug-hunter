"""Offline Decisions adapter contracts: scripted sockets, no network, no key.

Fixtures follow the request and response shapes documented on 2026-10-06.
Passing them establishes local translation, framing and failure handling only,
never live-service compatibility, calibration or detection effectiveness.
"""
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import decisions, providers
from decision_bug_hunter.decisions import (DecisionsProvider, translate_request,
                                           translate_response)
from decision_bug_hunter.protocol import ProviderError, QUESTION, _json, encode_request
from decision_bug_hunter.providers import ProviderRequest, RetryPolicy, ValidatedGateway
from tests.fakes import (ConnectFailure, FakeClock, FakeSleep, Raise, Reply, ScriptedHTTPS,
                         SendFailure, seeded_rng)
from tests.support import FixtureProvider, clean_provider_env


KEY = "offline-sentinel-credential-7c2e"
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
USAGE = {"input_tokens": 42, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
         "output_tokens": 0, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 42}
PREDICATE = {"type": "predicate", "name": "screen", "probability": 0.95}
CHOSEN = {"type": "choice", "name": "where", "choice": "L1-1",
          "probabilities": [{"value": "L1-1", "probability": 0.95},
                            {"value": "none", "probability": 0.05}],
          "confidence": 0.93}
METADATA = {"sequence": 1, "phase": "test"}


def documented(answers=(PREDICATE, CHOSEN), usage=USAGE, model=decisions.MODEL, **extra):
    data = {"model": model, "answers": list(answers), "usage": usage, **extra}
    if model is None:
        del data["model"]
    if usage is None:
        del data["usage"]
    return json.dumps(data).encode()


def reply(body, status=200, headers=None):
    """A scripted response; ``headers`` is a raw ``Name: value`` block."""
    if headers is not None:
        headers = [tuple(part.strip() for part in line.split(":", 1))
                   for line in headers.split("\r\n")]
    # The peer closes after the reply, so a short body ends in EOF.
    return Reply(status=status, body=body, headers=headers, close_after=True)


def scripted(steps=()):
    """A script for the fixed OpenAI origin and an exchange over it."""
    script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=decisions.HOST)
    return script, script.exchange(decisions.HOST, decisions.PATH)


def no_network():
    return patch.object(socket, "create_connection",
                        side_effect=AssertionError("network forbidden"))


class TranslationTests(unittest.TestCase):
    def test_local_envelope_maps_to_documented_request(self):
        wire = translate_request(encode_request(STATE, QUESTIONS))
        body = json.loads(wire)
        self.assertEqual(set(body), {"model", "input", "questions"})
        self.assertEqual(body["model"], "gpt-6-luna")
        self.assertEqual(body["input"], _json(STATE).decode("utf-8"))
        self.assertEqual(json.loads(body["input"]), STATE)
        screen, where = body["questions"]
        self.assertEqual(set(screen), {"type", "name", "instructions"})
        self.assertEqual((screen["type"], screen["name"]), ("predicate", "screen"))
        self.assertTrue(screen["instructions"].startswith(QUESTION["instructions"]))
        for text in QUESTION["criteria"].values():
            self.assertIn(text, screen["instructions"])
        self.assertEqual(where, {
            "type": "choice", "name": "where", "instructions": CHOICE["instructions"],
            "choices": [{"value": "L1-1", "description": "lines 1 through 1"},
                        {"value": "none", "description": "No supported suspicion."}]})
        self.assertNotIn(b"\n", wire)
        self.assertNotIn(b"dbh-judge-v1", wire)

    def test_foreign_or_oversized_envelopes_are_rejected_before_transport(self):
        valid = {"contract": "dbh-judge-v1", "state": {}, "questions": {"q": QUESTION}}
        for payload in (b"{}", b"[]", b"\xff", "text",
                        _json({**valid, "contract": "other"}),
                        _json({**valid, "state": []}),
                        _json({**valid, "questions": {}}),
                        _json({**valid, "extra": 1})):
            with self.subTest(payload=payload[:16]):
                with self.assertRaises(ProviderError) as caught:
                    translate_request(payload)
                self.assertEqual(caught.exception.code, "invalid_request")
        with patch.object(decisions, "MAX_BODY_BYTES", 64):
            with self.assertRaises(ProviderError) as caught:
                translate_request(encode_request(STATE, QUESTIONS))
            self.assertEqual(caught.exception.code, "request_too_large")

    def test_documented_examples_normalize_exactly_in_any_order(self):
        response = translate_response(documented(), QUESTIONS)
        self.assertIsNone(response.error)
        self.assertTrue(response.complete)
        self.assertEqual(response.usage, {"input_tokens": 42, "output_tokens": 0})
        self.assertEqual(response.answers["screen"], {"type": "noul", "noul": Decimal("0.95")})
        self.assertIs(type(response.answers["screen"]["noul"]), Decimal)
        self.assertEqual(response.answers["where"], {
            "type": "choice", "choice": "L1-1", "confidence": Decimal("0.93"),
            "probabilities": {"L1-1": Decimal("0.95"), "none": Decimal("0.05")}})
        self.assertEqual(response.order_mismatch, 0)
        reordered = translate_response(documented(answers=(CHOSEN, PREDICATE)), QUESTIONS)
        self.assertEqual(reordered.answers, response.answers)
        # Association is by name; a different order is counted, never fatal.
        self.assertEqual(reordered.order_mismatch, 1)
        self.assertEqual(list(reordered.answers), ["screen", "where"])

    def test_usage_is_known_only_from_documented_counters(self):
        self.assertIsNone(translate_response(documented(usage=None), QUESTIONS).usage)
        partial = translate_response(documented(usage={"input_tokens": 3}), QUESTIONS).usage
        self.assertEqual(partial, {"input_tokens": 3, "output_tokens": None})
        self.assertEqual(translate_response(documented(usage="42"), QUESTIONS).usage,
                         {"input_tokens": None, "output_tokens": None})


class AdapterExchangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def exchange(self, body=None, *, status=200, headers=None, failure=None,
                 state=STATE, environ=None, later=(), retry_policy=None, sleep=None):
        """One gateway call through a scripted HTTPS connection.

        ``failure`` is raised by the first receive after the request is sent;
        ``later`` scripts further steps for follow-up calls. The gateway makes
        one attempt unless ``retry_policy`` says otherwise: these tests map
        statuses to codes, and retries are pinned in test_retries.
        """
        if failure is not None:
            first = Reply(events=[Raise(failure)])
        else:
            first = reply(documented() if body is None else body, status, headers)
        script, exchange = scripted([first, *later])
        provider = DecisionsProvider(KEY, environ={} if environ is None else environ,
                                     exchange=exchange)
        gateway = ValidatedGateway(
            provider, self.root / "receipts",
            retry_policy=RetryPolicy.none() if retry_policy is None else retry_policy,
            sleep=sleep, rng=seeded_rng())
        self.addCleanup(gateway.close)
        # A frozen gateway clock: the call deadline is absolute from before the
        # dispatching receipt, so journal time would otherwise shrink it.
        with no_network(), \
                patch("decision_bug_hunter.providers.time.monotonic", return_value=100.0):
            try:
                outcome = gateway.evaluate(state, QUESTIONS, metadata=METADATA)
            except ProviderError as exc:
                outcome = exc
        receipt = None
        if gateway.last_receipt:
            receipt = json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))
        return outcome, receipt, script, provider, gateway

    def test_fixed_origin_headers_credential_and_receipt_contents(self):
        answers, receipt, script, provider, gateway = self.exchange(
            later=[reply(documented())])
        self.assertEqual(answers["screen"]["noul"], Decimal("0.95"))
        # The connect timeout is the whole remaining call deadline.
        self.assertEqual(script.connects[0], (("api.openai.com", 443), 30.0))
        self.assertEqual(script.server_hostnames, ["api.openai.com"])
        self.assertIsInstance(script.contexts[0], ssl.SSLContext)
        (request,) = script.requests
        self.assertEqual((request.method, request.target), ("POST", "/v1/decisions"))
        self.assertEqual(request.header("Host"), "api.openai.com")
        self.assertEqual(request.header("Authorization"), "Bearer " + KEY)
        self.assertEqual(request.header("Content-Type"), "application/json")
        self.assertEqual(request.header("Accept-Encoding"), "identity")
        self.assertIsNone(request.header("OpenAI-Organization"))
        self.assertIsNone(request.header("Connection"))
        self.assertNotIn(KEY.encode(), request.body)
        self.assertEqual(json.loads(request.body)["model"], "gpt-6-luna")
        # A complete 200 leaves the connection open for reuse ...
        self.assertEqual(script.closed, [])
        # ... and a second call (the peer closed the first connection) uses
        # the provider's same single TLS context.
        gateway.evaluate({**STATE, "sequence": 2}, QUESTIONS, metadata=METADATA)
        self.assertEqual(len(script.contexts), 2)
        self.assertIs(script.contexts[0], script.contexts[1])
        provider.close()
        self.assertEqual(script.closed, [0, 1])
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual((receipt["provider"], receipt["model"], receipt["synthetic"]),
                         ("openai-decisions", "gpt-6-luna", False))
        self.assertEqual(receipt["usage"], {"input_tokens": 42, "output_tokens": 0})
        saved = json.dumps(receipt)
        for private in (KEY, "private-sample-line", "example.txt", "total_tokens"):
            self.assertNotIn(private, saved)

    def test_routing_headers_come_only_from_a_sane_environment(self):
        _, _, script, _, _ = self.exchange(
            environ={"OPENAI_ORG_ID": "org-sentinel", "OPENAI_PROJECT_ID": "proj-sentinel"})
        (request,) = script.requests
        self.assertEqual(request.header("OpenAI-Organization"), "org-sentinel")
        self.assertEqual(request.header("OpenAI-Project"), "proj-sentinel")
        provider = DecisionsProvider(KEY, environ={"OPENAI_ORG_ID": "bad\r\nInjected: 1"})
        with self.assertRaises(ProviderError) as caught:
            provider.require_available()
        # A credential is present; the defect is the routing id (WP-03).
        self.assertEqual(caught.exception.code, "routing_invalid")
        self.assertNotIn("Injected", str(caught.exception))

    def test_chunked_framing_is_accepted(self):
        body = documented()
        chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        _, receipt, *_ = self.exchange(
            chunked, headers="Content-Type: application/json; charset=utf-8\r\n"
                             "Transfer-Encoding: chunked")
        self.assertEqual(receipt["status"], "validated")

    def test_ambiguous_or_unsupported_framing_is_rejected(self):
        body = documented()
        size = len(body)
        common = "Content-Type: application/json\r\n"
        cases = [(common + f"Content-Length: {size}\r\nContent-Length: {size}", "response_framing"),
                 (common + f"Content-Length: {size}\r\nTransfer-Encoding: chunked", "response_framing"),
                 (common + "Transfer-Encoding: gzip", "response_framing"),
                 (common + f"Content-Length: +{size}", "response_framing"),
                 (common + f"Content-Length: {size + 1}", "response_framing"),
                 (f"Content-Type: text/plain\r\nContent-Length: {size}", "response_type"),
                 (common + f"Content-Encoding: gzip\r\nContent-Length: {size}", "response_type"),
                 (common + f"Content-Type: text/plain\r\nContent-Length: {size}", "response_framing")]
        for headers, code in cases:
            with self.subTest(headers=headers.replace("\r\n", " | ")):
                outcome, receipt, *_ = self.exchange(body, headers=headers)
                self.assertEqual(outcome.code, code)
                self.assertIsNone(receipt["answers"])

    def test_status_codes_map_to_fixed_codes_and_error_bodies_are_bounded(self):
        # A body that echoes the key is withheld before parsing; nothing of it,
        # nor the Location value, reaches the receipt (ADR-8).
        body = KEY.encode() + b" private error body"
        headers = (f"Location: https://elsewhere.invalid/{KEY}\r\n"
                   f"Content-Type: application/json\r\nContent-Length: {len(body)}")
        for status, code, possible in (
                (301, "http_redirect", True), (302, "http_redirect", True),
                (400, "http_rejected", True), (401, "http_unauthorized", True),
                (402, "http_rejected", True), (403, "http_forbidden", True),
                (404, "route_unavailable", True), (408, "http_request_timeout", False),
                (413, "request_too_large", True), (429, "http_rate_limited", False),
                (500, "http_server_error", True), (503, "http_server_error", True),
                (529, "http_server_error", True)):
            with self.subTest(status=status):
                outcome, receipt, *_ = self.exchange(body, status=status, headers=headers)
                self.assertEqual(outcome.code, code)
                self.assertIsNone(outcome.__cause__)
                self.assertIsNone(outcome.__context__)
                self.assertEqual((receipt["status"], receipt["error"]), ("failed", code))
                self.assertIsNone(receipt["usage"])
                # ADR-2(2): rejected-unprocessed and not-sent classes only.
                self.assertIs(receipt["submission_possible"], possible)
                self.assertEqual(receipt["provider_error"]["error_body"], "withheld_sensitive")
                self.assertNotIn(KEY, json.dumps(receipt))
                self.assertNotIn("elsewhere", json.dumps(receipt))
        # OpenAI's 503 server_is_overloaded and the 429 quota set are matched
        # exactly on error.code or error.type; the message is never kept.
        for status, error, code in (
                (503, {"type": "server_error", "code": "server_is_overloaded"}, "http_overloaded"),
                (429, {"type": "insufficient_quota", "code": None}, "http_quota_exhausted"),
                (429, {"type": "requests", "code": "billing_not_active"}, "http_quota_exhausted"),
                (429, {"type": "requests", "code": "rate_limit_exceeded"}, "http_rate_limited")):
            with self.subTest(error=error):
                raw = json.dumps({"error": {**error, "message": "private-message"}}).encode()
                outcome, receipt, *_ = self.exchange(
                    raw, status=status,
                    headers=f"Content-Type: application/json\r\nContent-Length: {len(raw)}")
                self.assertEqual(outcome.code, code)
                self.assertEqual(receipt["provider_error"]["error_body"], "ok")
                self.assertNotIn("private-message", json.dumps(receipt))

    def test_unauthorized_blocks_the_gateway_without_a_second_request(self):
        # ADR-2(6): a blocked gateway repeats its original blocking code
        # (it used to say transport_failed) and reports the stop reason.
        outcome, _, script, _, gateway = self.exchange(
            b"", status=401, headers="Content-Type: application/json\r\nContent-Length: 0",
            retry_policy=RetryPolicy())
        self.assertEqual(outcome.code, "http_unauthorized")
        with no_network(), self.assertRaises(ProviderError) as caught:
            gateway.evaluate({**STATE, "sequence": 2}, QUESTIONS, metadata=METADATA)
        self.assertEqual(caught.exception.code, "http_unauthorized")
        self.assertEqual(gateway.stop_reason, "blocked:http_unauthorized")
        self.assertEqual((len(script.connects), len(script.requests)), (1, 1))

    def test_rate_limit_retried_after_retry_after(self):
        sleep = FakeSleep()
        answers, receipt, script, _, gateway = self.exchange(
            b"", status=429, headers="Retry-After: 1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: 0", later=[reply(documented())],
            retry_policy=RetryPolicy(), sleep=sleep)
        self.assertEqual(answers["where"]["choice"], "L1-1")
        self.assertEqual(len(gateway.last_receipts), 2)
        self.assertGreaterEqual(sleep.total, 1.0)
        first, final = (json.loads(Path(path).read_text(encoding="utf-8"))
                        for path in gateway.last_receipts)
        self.assertEqual((first["attempt"], first["error"]), (1, "http_rate_limited"))
        self.assertNotIn("logical_status", first)
        self.assertEqual((final["attempt"], final["retry_reason"]), (2, "http_rate_limited"))
        self.assertEqual(final["logical_status"], "validated")
        self.assertEqual(final["logical_id"], first["logical_id"])
        self.assertEqual(receipt, final)
        self.assertEqual(len(script.requests), 2)

    def test_rate_limit_no_retry_policy_records_once(self):
        outcome, receipt, script, _, gateway = self.exchange(
            b"", status=429, headers="Retry-After: 1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: 0", later=[reply(documented())])
        self.assertEqual(outcome.code, "http_rate_limited")
        self.assertEqual(len(script.requests), 1)
        self.assertEqual(receipt["error"], "http_rate_limited")
        with no_network():
            answers = gateway.evaluate({**STATE, "sequence": 2}, QUESTIONS, metadata=METADATA)
        self.assertEqual(answers["where"]["choice"], "L1-1")
        # The non-200 connection was dropped; the next call reconnected.
        self.assertEqual((len(script.connects), script.closed[0]), (2, 0))

    def test_timeout_and_transport_failures_have_fixed_codes_and_no_context(self):
        # Connect-phase failures and a send failure on a fresh connection
        # never delivered a complete request (ADR-2(2)).
        for step in (ConnectFailure(socket.gaierror(KEY)), ConnectFailure(ssl.SSLError(KEY)),
                     ConnectFailure(ConnectionRefusedError(KEY)), SendFailure(BrokenPipeError(KEY))):
            with self.subTest(step=type(step).__name__, error=type(step.error).__name__):
                script, exchange = scripted([step])
                # One attempt: connect_failed retries are pinned in test_retries.
                gateway = ValidatedGateway(DecisionsProvider(KEY, environ={}, exchange=exchange),
                                           self.root / "receipts",
                                           retry_policy=RetryPolicy.none())
                self.addCleanup(gateway.close)
                with no_network(), self.assertRaises(ProviderError) as caught:
                    gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
                self.assertEqual(caught.exception.code, "connect_failed")
                self.assertIsNone(caught.exception.__context__)
                receipt = json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))
                self.assertIs(receipt["submission_possible"], False)
                self.assertEqual(receipt["submission"], "not_sent")
                self.assertIn(receipt["provider_error"]["phase"], {"connect", "send"})
                self.assertNotIn(KEY, json.dumps(receipt))
        # Injected at the receive phase, after the request was sent.
        for failure, code in ((socket.timeout(KEY), "deadline_exceeded"),
                              (TimeoutError(KEY), "deadline_exceeded"),
                              (ssl.SSLError(KEY), "transport_failed"),
                              (ConnectionResetError(KEY), "transport_failed"),
                              (http.client.RemoteDisconnected(KEY), "transport_failed"),
                              (OSError(KEY), "transport_failed")):
            with self.subTest(failure=type(failure).__name__):
                outcome, receipt, script, *_ = self.exchange(failure=failure)
                self.assertEqual(len(script.requests), 1)
                self.assertEqual(outcome.code, code)
                self.assertIsNone(outcome.__cause__)
                self.assertIsNone(outcome.__context__)
                self.assertNotIn(KEY, str(outcome))
                self.assertNotIn(KEY, json.dumps(receipt))
                self.assertTrue(receipt["submission_possible"])

    def test_oversized_malformed_and_sensitive_bodies_are_rejected(self):
        escaped = documented(id=KEY).replace(KEY.encode(), rb"o" + KEY[1:].encode())
        unsized = b" " * (decisions.MAX_RESPONSE_BYTES + 1)
        chunked = f"{len(unsized):x}\r\n".encode() + unsized + b"\r\n0\r\n\r\n"
        cases = [(unsized, None, "response_too_large"),
                 (chunked, "Content-Type: application/json\r\nTransfer-Encoding: chunked",
                  "response_too_large"),
                 (b'{"answers":', None, "response_invalid_json"),
                 (b'{"x":1,"x":2}', None, "response_invalid_json"),
                 (b'{"model":"gpt-6-luna","answers":[{"type":"predicate","name":"screen",'
                  b'"probability":NaN}]}', None, "response_invalid_json"),
                 (b"\xff\xfe", None, "response_invalid_json"),
                 (documented(id=KEY), None, "response_sensitive"),
                 (escaped, None, "response_sensitive"),
                 (b"[]", None, "response_schema"),
                 (b'{"model":"gpt-6-luna"}', None, "response_schema")]
        for body, headers, code in cases:
            with self.subTest(code=code, body=body[:24]):
                outcome, receipt, *_ = self.exchange(body, headers=headers)
                self.assertEqual(outcome.code, code)
                self.assertIsNone(receipt["answers"])
                self.assertNotIn(KEY, json.dumps(receipt))

    def test_semantic_rejections_keep_usage_and_withhold_every_judgment(self):
        refusal = {"type": "refusal", "name": "where"}

        def chosen(**changes):
            return {**CHOSEN, **changes}

        cases = [
            ((PREDICATE, refusal), "response_refused"),
            ((PREDICATE,), "response_schema"),
            ((PREDICATE, CHOSEN, PREDICATE), "response_schema"),
            ((PREDICATE, CHOSEN, {"type": "predicate", "name": "extra", "probability": 0.5}),
             "response_schema"),
            (({**PREDICATE, "name": None}, CHOSEN), "response_schema"),
            ((chosen(name="screen"), CHOSEN), "response_schema"),
            (({"type": "predicate", "name": "screen"}, CHOSEN), "response_schema"),
            ((PREDICATE, {k: v for k, v in CHOSEN.items() if k != "confidence"}), "response_schema"),
            (({**PREDICATE, "probability": True}, CHOSEN), "response_probability"),
            (({**PREDICATE, "probability": "0.95"}, CHOSEN), "response_probability"),
            (({**PREDICATE, "probability": 1.5}, CHOSEN), "response_probability"),
            ((PREDICATE, chosen(probabilities=[{"value": "L1-1", "probability": 0.95},
                                                 {"value": "elsewhere", "probability": 0.05}])),
             "response_distribution"),
            ((PREDICATE, chosen(probabilities=[{"value": "L1-1", "probability": 0.5},
                                                 {"value": "L1-1", "probability": 0.5}])),
             "response_distribution"),
            ((PREDICATE, chosen(probabilities={"L1-1": 1, "none": 0})), "response_distribution"),
            ((PREDICATE, chosen(choice=True)), "response_distribution"),
            ((PREDICATE, chosen(probabilities=[{"value": "L1-1", "probability": 0.6},
                                                 {"value": "none", "probability": 0.6}])),
             "response_distribution"),
            ((PREDICATE, chosen(choice="none")), "choice_argmax_mismatch"),
        ]
        for answers, code in cases:
            with self.subTest(code=code, answers=answers):
                outcome, receipt, *_ = self.exchange(documented(answers=answers))
                self.assertEqual(outcome.code, code)
                self.assertEqual((receipt["status"], receipt["error"]), ("failed", code))
                self.assertIsNone(receipt["answers"])
                self.assertEqual(receipt["usage"], {"input_tokens": 42, "output_tokens": 0})
        for model in ("gpt-6-sol", "", None, 1, "gpt-6-lunar"):
            with self.subTest(model=model):
                outcome, receipt, *_ = self.exchange(documented(model=model))
                self.assertEqual(outcome.code, "response_model")
                self.assertEqual(receipt["usage"]["input_tokens"], 42)
        _, receipt, *_ = self.exchange(documented(model="gpt-6-luna-2026-10-06"))
        self.assertEqual(receipt["status"], "validated")

    def test_malformed_usage_is_a_limitation_not_zero_tokens(self):
        for usage in ({"input_tokens": 42}, {"input_tokens": "42", "output_tokens": 0},
                      {"input_tokens": -1, "output_tokens": 0}, "42", []):
            with self.subTest(usage=usage):
                outcome, receipt, *_ = self.exchange(documented(usage=usage))
                self.assertEqual(outcome.code, "response_usage")
                self.assertIsNone(receipt["usage"])
                self.assertIsNone(receipt["answers"])
        _, receipt, *_ = self.exchange(documented(usage=None))
        self.assertEqual(receipt["status"], "validated")
        self.assertIsNone(receipt["usage"])

    def test_undocumented_fields_are_ignored_but_never_journaled(self):
        body = documented(id="sentinel-identifier", object="sentinel-object",
                          answers=({**PREDICATE, "reasoning": "private-rationale"}, CHOSEN))
        answers, receipt, *_ = self.exchange(body)
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual(set(answers["screen"]), {"type", "noul"})
        saved = json.dumps(receipt)
        for text in ("sentinel-identifier", "sentinel-object", "private-rationale"):
            self.assertNotIn(text, saved)

    def test_expired_budget_never_opens_a_connection(self):
        script, exchange = scripted()
        provider = DecisionsProvider(KEY, environ={}, exchange=exchange)
        with no_network():
            for timeout in (0, -1.0):
                with self.assertRaises(ProviderError) as caught:
                    provider.decide(ProviderRequest(encode_request(STATE, QUESTIONS), timeout))
                self.assertEqual(caught.exception.code, "deadline_exceeded")
            with self.assertRaises(ProviderError) as caught:
                provider.decide(ProviderRequest(encode_request(STATE, QUESTIONS), float("nan")))
            self.assertEqual(caught.exception.code, "invalid_deadline")
            # Through the gateway: a budget spent by the intent journal is
            # refused before dispatch and recorded as never submitted.
            with tempfile.TemporaryDirectory() as td:
                gateway = ValidatedGateway(provider, Path(td) / "receipts")
                self.addCleanup(gateway.close)
                clock = [100.0]
                original = providers._write_receipt

                def slow_intent(path, receipt):
                    original(path, receipt)
                    clock[0] = 200.0

                with patch.object(providers.time, "monotonic", side_effect=lambda: clock[0]), \
                        patch.object(providers, "_write_receipt", side_effect=slow_intent):
                    with self.assertRaises(ProviderError) as caught:
                        gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
                self.assertEqual(caught.exception.code, "deadline_exceeded")
                receipt = json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))
                self.assertIs(receipt["submission_possible"], False)
        self.assertEqual(script.connects, [])


class AvailabilityTests(unittest.TestCase):
    def test_missing_or_malformed_credential_is_unavailable_without_network(self):
        request = ProviderRequest(encode_request(STATE, QUESTIONS), 1.0)
        for environ in ({}, {"OPENAI_API_KEY": ""}, {"OPENAI_API_KEY": "has space"},
                        {"OPENAI_API_KEY": "line\nbreak"}, {"OPENAI_API_KEY": "k" * 4097},
                        {"OPENAI_API_KEY": "non-ascii-é"}):
            with self.subTest(environ=environ):
                script, exchange = scripted()
                provider = DecisionsProvider(environ=environ, exchange=exchange)
                with no_network():
                    for operation in (provider.require_available,
                                      lambda: provider.decide(request)):
                        with self.assertRaises(ProviderError) as caught:
                            operation()
                        self.assertEqual(caught.exception.code, "provider_unavailable")
                provider.check_sensitive(KEY)
                provider.close()
                self.assertEqual((script.connects, exchange.contexts_built), ([], 0))

    def test_credential_argument_wins_and_sensitive_input_never_dispatches(self):
        script, exchange = scripted()
        provider = DecisionsProvider(KEY, environ={"OPENAI_API_KEY": "ignored-environment-value"},
                                     exchange=exchange)
        provider.require_available()
        for value in (KEY, KEY.encode(), {KEY: 1}, ("safe", [KEY]), {"k": {"n": KEY}}):
            with self.assertRaises(ProviderError) as caught:
                provider.check_sensitive("safe", value)
            self.assertEqual(caught.exception.code, "sensitive_input")
        provider.check_sensitive("safe", {"k": ["safe"]})
        with tempfile.TemporaryDirectory() as td:
            gateway = ValidatedGateway(provider, Path(td) / "receipts")
            with no_network():
                with self.assertRaises(ProviderError) as caught:
                    gateway.evaluate({"text": KEY}, QUESTIONS, metadata=METADATA)
            self.assertEqual(caught.exception.code, "sensitive_input")
            self.assertFalse((Path(td) / "receipts").exists())
            gateway.close()
        self.assertEqual(script.connects, [])

    def test_cli_without_credential_stops_before_any_source_read_or_output(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as td, clean_provider_env(), no_network(), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["secret-target-name", "--scope", "standalone",
                             "--provider", "openai",
                             "--output-dir", str(Path(td) / "outputs")])
            self.assertFalse((Path(td) / "outputs").exists())
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertIn("provider_unavailable", err.getvalue())
        self.assertIn("OPENAI_API_KEY", err.getvalue())
        self.assertNotIn("secret-target-name", err.getvalue())


class FakeDecisionsService(ScriptedHTTPS):
    """Answers documented requests with the deterministic fixture judge.

    A ``ScriptedHTTPS`` whose next reply is computed from the request just
    received, so the real exchange, framing and keep-alive paths run.
    """

    def __init__(self, fixture):
        super().__init__([], host="api.openai.com")
        self.fixture = fixture
        self.bodies = []
        self.headers = []

    def _next_step(self, kind):
        request = self.requests[-1]
        assert (request.method, request.target) == ("POST", "/v1/decisions"), request.target
        data = json.loads(request.body)
        self.bodies.append(data)
        self.headers.append(request)
        state = json.loads(data["input"])
        answers = [self.documented(q["name"], self.fixture.answer(q["name"], self.local(q), state))
                   for q in data["questions"]]
        size = max(1, len(request.body) // 4)
        raw = json.dumps({"model": "gpt-6-luna", "answers": answers,
                          "usage": {**USAGE, "input_tokens": size,
                                    "total_tokens": size}}).encode()
        return Reply(body=raw)

    @staticmethod
    def local(question):
        if question["type"] == "predicate":
            return {"type": "noul", "instructions": question["instructions"],
                    "criteria": {"true": "", "false": ""}}
        return {"type": "choice", "instructions": question["instructions"],
                "criteria": {c["value"]: c["description"] for c in question["choices"]}}

    @staticmethod
    def documented(name, answer):
        if answer["type"] == "noul":
            return {"type": "predicate", "name": name, "probability": answer["noul"]}
        return {"type": "choice", "name": name, "choice": answer["choice"],
                "probabilities": [{"value": k, "probability": v}
                                  for k, v in answer["probabilities"].items()],
                "confidence": answer["confidence"]}


class EndToEndCliTests(unittest.TestCase):
    def test_documented_shape_cli_run_reports_findings_and_leaks_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.py"
            marker = root / "executed.txt"
            target.write_text("import pathlib\npathlib.Path(" + repr(str(marker))
                              + ").touch()\nprint('private-line-three')\n", encoding="utf-8")
            service = FakeDecisionsService(FixtureProvider([(2, 2)]))

            def make_provider(args):
                # The real adapter, reading the patched environment; only the
                # network edges of its exchange are scripted.
                return DecisionsProvider(
                    exchange=service.exchange(decisions.HOST, decisions.PATH))

            out, err = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, {"OPENAI_API_KEY": KEY}), \
                    patch.object(cli, "make_provider", side_effect=make_provider), \
                    no_network(), redirect_stdout(out), redirect_stderr(err):
                code = cli.main([str(target), "--scope", "standalone", "--provider", "openai",
                                 "--output-dir", str(root / "runs"), "--no-whole-file",
                                 "--no-bug-lenses", "--max-action-steps", "0"])
            self.assertEqual(code, 1, err.getvalue())
            # Back-to-back calls share one kept-alive connection.
            self.assertEqual(len(service.connects), 1)
            self.assertEqual(service.reuse_count, len(service.bodies) - 1)
            self.assertFalse(marker.exists())
            self.assertTrue(service.bodies)
            self.assertIn("SCAN: complete", out.getvalue())
            run = next((root / "runs").glob("run-*"))
            report = json.loads((run / "report.json").read_text(encoding="utf-8"))
            self.assertEqual((report["provider"], report["model"], report["synthetic"]),
                             ("openai-decisions", "gpt-6-luna", False))
            self.assertEqual(report["status"], "complete")
            self.assertTrue(any(f["start_line"] <= 2 <= f["end_line"] for f in report["findings"]))
            self.assertGreater(report["usage"]["attempts_with_known_usage"], 0)
            self.assertEqual(report["usage"]["attempts_with_unknown_usage"], 0)
            self.assertGreater(report["usage"]["input_tokens"], 0)
            self.assertEqual(report["calls_attempted"], len(service.bodies))
            for request in service.headers:
                self.assertEqual(request.header("Authorization"), "Bearer " + KEY)
            for body in service.bodies:
                self.assertEqual(body["model"], "gpt-6-luna")
                self.assertNotIn(KEY, json.dumps(body))
                self.assertLessEqual(len(body["questions"]), 64)
            receipts = list((run / "receipts").glob("*.json"))
            self.assertEqual(len(receipts), len(service.bodies))
            for path in run.rglob("*"):
                if path.is_file():
                    text = path.read_text(encoding="utf-8")
                    self.assertNotIn(KEY, text, path.name)
                    self.assertNotIn(str(root), text, path.name)
                    if path.parent.name == "receipts":
                        self.assertNotIn("private-line-three", text, path.name)


if __name__ == "__main__":
    unittest.main()
