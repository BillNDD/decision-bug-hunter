"""Offline Decisions adapter contracts: synthetic sockets, no network, no key.

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
from unittest.mock import MagicMock, patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import decisions
from decision_bug_hunter.decisions import (DecisionsProvider, translate_request,
                                           translate_response)
from decision_bug_hunter.protocol import ProviderError, QUESTION, _json, encode_request
from decision_bug_hunter.providers import ProviderRequest, ValidatedGateway
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


def http_response(body, status=200, headers=None):
    if headers is None:
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}"
    wire = f"HTTP/1.1 {status} Test\r\n{headers}\r\n\r\n".encode() + body
    sock = MagicMock()
    sock.makefile.return_value = io.BytesIO(wire)
    parsed = http.client.HTTPResponse(sock)
    parsed.begin()
    return parsed


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
        reordered = translate_response(documented(answers=(CHOSEN, PREDICATE)), QUESTIONS)
        self.assertEqual(reordered.answers, response.answers)

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
                 state=STATE, environ=None):
        """One gateway attempt through a synthetic HTTPS connection."""
        connection = MagicMock()
        if failure is not None:
            connection.request.side_effect = failure
        else:
            parsed = http_response(documented() if body is None else body, status, headers)
            self.addCleanup(parsed.close)
            connection.getresponse.return_value = parsed
        provider = DecisionsProvider(KEY, environ={} if environ is None else environ)
        gateway = ValidatedGateway(provider, self.root / "receipts")
        self.addCleanup(gateway.close)
        with patch.object(decisions.http.client, "HTTPSConnection",
                          return_value=connection) as factory, no_network():
            try:
                outcome = gateway.evaluate(state, QUESTIONS, metadata=METADATA)
            except ProviderError as exc:
                outcome = exc
        receipt = None
        if gateway.last_receipt:
            receipt = json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))
        return outcome, receipt, connection, factory, gateway

    def test_fixed_origin_headers_credential_and_receipt_contents(self):
        answers, receipt, connection, factory, _ = self.exchange()
        self.assertEqual(answers["screen"]["noul"], Decimal("0.95"))
        self.assertEqual(factory.call_args.args, ("api.openai.com", 443))
        self.assertEqual(factory.call_args.kwargs["timeout"], 30.0)
        self.assertIsInstance(factory.call_args.kwargs["context"], ssl.SSLContext)
        call = connection.request.call_args
        self.assertEqual(call.args, ("POST", "/v1/decisions"))
        headers = call.kwargs["headers"]
        self.assertEqual(headers["Authorization"], "Bearer " + KEY)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertNotIn("OpenAI-Organization", headers)
        self.assertNotIn(KEY.encode(), call.kwargs["body"])
        self.assertEqual(json.loads(call.kwargs["body"])["model"], "gpt-6-luna")
        connection.close.assert_called_once()
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual((receipt["provider"], receipt["model"], receipt["synthetic"]),
                         ("openai-decisions", "gpt-6-luna", False))
        self.assertEqual(receipt["usage"], {"input_tokens": 42, "output_tokens": 0})
        saved = json.dumps(receipt)
        for private in (KEY, "private-sample-line", "example.txt", "total_tokens"):
            self.assertNotIn(private, saved)

    def test_routing_headers_come_only_from_a_sane_environment(self):
        _, _, connection, _, _ = self.exchange(
            environ={"OPENAI_ORG_ID": "org-sentinel", "OPENAI_PROJECT_ID": "proj-sentinel"})
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["OpenAI-Organization"], "org-sentinel")
        self.assertEqual(headers["OpenAI-Project"], "proj-sentinel")
        provider = DecisionsProvider(KEY, environ={"OPENAI_ORG_ID": "bad\r\nInjected: 1"})
        with self.assertRaises(ProviderError) as caught:
            provider.require_available()
        self.assertEqual(caught.exception.code, "provider_unavailable")

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

    def test_status_codes_map_to_fixed_codes_and_bodies_are_never_read(self):
        body = KEY.encode() + b" private error body"
        headers = (f"Location: https://elsewhere.invalid/{KEY}\r\n"
                   f"Content-Type: application/json\r\nContent-Length: {len(body)}")
        for status, code in ((301, "http_redirect"), (302, "http_redirect"),
                             (400, "http_rejected"), (401, "http_unauthorized"),
                             (403, "http_unauthorized"), (404, "http_rejected"),
                             (429, "http_rate_limited"), (500, "http_server_error"),
                             (503, "http_server_error")):
            with self.subTest(status=status):
                outcome, receipt, connection, *_ = self.exchange(body, status=status, headers=headers)
                self.assertEqual(outcome.code, code)
                self.assertIsNone(outcome.__cause__)
                self.assertIsNone(outcome.__context__)
                self.assertEqual((receipt["status"], receipt["error"]), ("failed", code))
                self.assertIsNone(receipt["usage"])
                self.assertTrue(receipt["submission_possible"])
                self.assertNotIn(KEY, json.dumps(receipt))

    def test_unauthorized_blocks_the_gateway_without_a_second_request(self):
        outcome, _, _, factory, gateway = self.exchange(
            b"", status=401, headers="Content-Type: application/json\r\nContent-Length: 0")
        self.assertEqual(outcome.code, "http_unauthorized")
        with no_network(), self.assertRaises(ProviderError) as caught:
            gateway.evaluate({**STATE, "sequence": 2}, QUESTIONS, metadata=METADATA)
        self.assertEqual(caught.exception.code, "transport_failed")
        self.assertEqual(factory.call_count, 1)

    def test_rate_limit_is_recorded_once_without_retry_or_blocking(self):
        outcome, receipt, connection, _, gateway = self.exchange(
            b"", status=429, headers="Retry-After: 1\r\nContent-Type: application/json\r\n"
                                     "Content-Length: 0")
        self.assertEqual(outcome.code, "http_rate_limited")
        self.assertEqual(connection.request.call_count, 1)
        self.assertEqual(receipt["error"], "http_rate_limited")
        later = MagicMock()
        parsed = http_response(documented())
        self.addCleanup(parsed.close)
        later.getresponse.return_value = parsed
        with patch.object(decisions.http.client, "HTTPSConnection", return_value=later), no_network():
            answers = gateway.evaluate({**STATE, "sequence": 2}, QUESTIONS, metadata=METADATA)
        self.assertEqual(answers["where"]["choice"], "L1-1")

    def test_timeout_and_transport_failures_have_fixed_codes_and_no_context(self):
        for failure, code in ((socket.timeout(KEY), "deadline_exceeded"),
                              (TimeoutError(KEY), "deadline_exceeded"),
                              (ssl.SSLError(KEY), "transport_failed"),
                              (ConnectionResetError(KEY), "transport_failed"),
                              (http.client.RemoteDisconnected(KEY), "transport_failed"),
                              (OSError(KEY), "transport_failed")):
            with self.subTest(failure=type(failure).__name__):
                outcome, receipt, *_ = self.exchange(failure=failure)
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
        provider = DecisionsProvider(KEY, environ={})
        with patch.object(decisions.http.client, "HTTPSConnection",
                          side_effect=AssertionError("no transport")):
            for timeout in (0, -1.0):
                with self.assertRaises(ProviderError) as caught:
                    provider.decide(ProviderRequest(encode_request(STATE, QUESTIONS), timeout))
                self.assertEqual(caught.exception.code, "deadline_exceeded")
            with self.assertRaises(ProviderError) as caught:
                provider.decide(ProviderRequest(encode_request(STATE, QUESTIONS), float("nan")))
            self.assertEqual(caught.exception.code, "invalid_deadline")


class AvailabilityTests(unittest.TestCase):
    def test_missing_or_malformed_credential_is_unavailable_without_network(self):
        request = ProviderRequest(encode_request(STATE, QUESTIONS), 1.0)
        for environ in ({}, {"OPENAI_API_KEY": ""}, {"OPENAI_API_KEY": "has space"},
                        {"OPENAI_API_KEY": "line\nbreak"}, {"OPENAI_API_KEY": "k" * 4097},
                        {"OPENAI_API_KEY": "non-ascii-é"}):
            with self.subTest(environ=environ):
                provider = DecisionsProvider(environ=environ)
                with no_network(), patch.object(decisions.http.client, "HTTPSConnection",
                                                side_effect=AssertionError("no transport")):
                    for operation in (provider.require_available,
                                      lambda: provider.decide(request)):
                        with self.assertRaises(ProviderError) as caught:
                            operation()
                        self.assertEqual(caught.exception.code, "provider_unavailable")
                provider.check_sensitive(KEY)
                provider.close()

    def test_credential_argument_wins_and_sensitive_input_never_dispatches(self):
        provider = DecisionsProvider(KEY, environ={"OPENAI_API_KEY": "ignored-environment-value"})
        provider.require_available()
        for value in (KEY, KEY.encode(), {KEY: 1}, ("safe", [KEY]), {"k": {"n": KEY}}):
            with self.assertRaises(ProviderError) as caught:
                provider.check_sensitive("safe", value)
            self.assertEqual(caught.exception.code, "sensitive_input")
        provider.check_sensitive("safe", {"k": ["safe"]})
        with tempfile.TemporaryDirectory() as td:
            gateway = ValidatedGateway(provider, Path(td) / "receipts")
            with patch.object(decisions.http.client, "HTTPSConnection",
                              side_effect=AssertionError("no transport")):
                with self.assertRaises(ProviderError) as caught:
                    gateway.evaluate({"text": KEY}, QUESTIONS, metadata=METADATA)
            self.assertEqual(caught.exception.code, "sensitive_input")
            self.assertFalse((Path(td) / "receipts").exists())
            gateway.close()

    def test_cli_without_credential_stops_before_any_source_read_or_output(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as td, clean_provider_env(), no_network(), \
                patch.object(decisions.http.client, "HTTPSConnection",
                             side_effect=AssertionError("no transport")), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["secret-target-name", "--scope", "standalone",
                             "--output-dir", str(Path(td) / "outputs")])
            self.assertFalse((Path(td) / "outputs").exists())
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertIn("provider_unavailable", err.getvalue())
        self.assertIn("OPENAI_API_KEY", err.getvalue())
        self.assertNotIn("secret-target-name", err.getvalue())


class FakeDecisionsService:
    """Answers documented requests with the deterministic fixture judge."""

    def __init__(self, fixture):
        self.fixture = fixture
        self.bodies = []
        self.headers = []
        self.responses = []

    def __call__(self, host, port, timeout=None, context=None):
        assert (host, port) == ("api.openai.com", 443), (host, port)
        connection = MagicMock()

        def request(method, path, body, headers):
            assert (method, path) == ("POST", "/v1/decisions"), (method, path)
            data = json.loads(body)
            self.bodies.append(data)
            self.headers.append(headers)
            state = json.loads(data["input"])
            answers = [self.documented(q["name"], self.fixture.answer(q["name"], self.local(q), state))
                       for q in data["questions"]]
            raw = json.dumps({"model": "gpt-6-luna", "answers": answers,
                              "usage": {**USAGE, "input_tokens": max(1, len(body) // 4),
                                        "total_tokens": max(1, len(body) // 4)}}).encode()
            parsed = http_response(raw)
            self.responses.append(parsed)
            connection.getresponse.return_value = parsed

        connection.request.side_effect = request
        return connection

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
            out, err = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, {"OPENAI_API_KEY": KEY}), \
                    patch.object(decisions.http.client, "HTTPSConnection", side_effect=service), \
                    no_network(), redirect_stdout(out), redirect_stderr(err):
                code = cli.main([str(target), "--scope", "standalone",
                                 "--output-dir", str(root / "runs"), "--no-whole-file",
                                 "--no-bug-lenses", "--max-action-steps", "0"])
            for parsed in service.responses:
                parsed.close()
            self.assertEqual(code, 1, err.getvalue())
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
            for headers in service.headers:
                self.assertEqual(headers["Authorization"], "Bearer " + KEY)
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
