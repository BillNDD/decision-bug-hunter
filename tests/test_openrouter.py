"""Offline OpenRouter route contracts: scripted sockets, no network, no key.

Response shapes follow the 2026-10-06 OpenRouter run (structural fields only).
Passing these establishes local encoding, decoding and failure mapping; it
says nothing about live-service compatibility or detection quality.
"""
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from decision_bug_hunter import openrouter
from decision_bug_hunter.openrouter import (OpenRouterProvider, decode_response,
                                            encode_request, routing_fragment)
from decision_bug_hunter.protocol import ProviderError, QUESTION, _json
from decision_bug_hunter.protocol import encode_request as local_envelope
from decision_bug_hunter.providers import ProviderRequest, RetryPolicy, ValidatedGateway
from tests.fakes import FakeClock, Reply, ScriptedHTTPS
from tests.support import openrouter_body


KEY = "offline-openrouter-sentinel-credential-41d9"
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
ANSWERS = {"screen": {"type": "noul", "noul": Decimal("0.95")},
           "where": {"type": "choice", "choice": "L1-1", "confidence": Decimal("0.9"),
                     "probabilities": {"L1-1": Decimal("0.95"), "none": Decimal("0.05")}}}
METADATA = {"sequence": 1, "phase": "test"}
DENY = b',"provider":{"allow_fallbacks":false,"data_collection":"deny"}'
GENERATION = "gen-dec-1759793823-offlinefixture0001"
CF_RAY = "8f1e2d3c4b5a6978-ZZZ"


def reply(body, status=200, *, generation=GENERATION, extra=()):
    """A reply with the headers OpenRouter sent, including the edge ``cf-ray``."""
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
               ("cf-ray", CF_RAY), ("Server", "cloudflare"), *extra]
    if generation is not None:
        headers.append(("x-generation-id", generation))
    return Reply(status=status, body=body, headers=headers, close_after=True)


def error_body(code, message="private-error-message", **metadata):
    error = {"code": code, "message": message}
    if metadata:
        error["metadata"] = metadata
    return json.dumps({"error": error}).encode()


class Harness:
    """One scripted OpenRouter origin, a provider over it and a gateway."""

    def __init__(self, test, steps, *, retry_policy=None, **provider_kwargs):
        self.script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=openrouter.HOST)
        exchange = self.script.exchange(openrouter.HOST, openrouter.PATH)
        self.provider = OpenRouterProvider(KEY, environ={}, exchange=exchange,
                                           **provider_kwargs)
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        # One attempt by default: these tests map statuses to codes; the
        # retry behaviour of the same statuses is pinned in test_retries.
        self.gateway = ValidatedGateway(
            self.provider, Path(tmp.name) / "receipts",
            retry_policy=RetryPolicy.none() if retry_policy is None else retry_policy)
        test.addCleanup(self.gateway.close)

    def evaluate(self, state=STATE, questions=QUESTIONS):
        try:
            outcome = self.gateway.evaluate(state, questions, metadata=METADATA)
        except ProviderError as exc:
            outcome = exc
        receipt = None
        if self.gateway.last_receipt:
            receipt = json.loads(Path(self.gateway.last_receipt).read_text(encoding="utf-8"))
        return outcome, receipt


class EncodingTests(unittest.TestCase):
    def test_endpoint_path_pinned(self):
        self.assertEqual((openrouter.HOST, openrouter.PORT, openrouter.PATH),
                         ("openrouter.ai", 443, "/api/alpha/decisions"))
        self.assertEqual(openrouter.CREDENTIAL_VARIABLE, "OPENROUTER_API_KEY")
        harness = Harness(self, [reply(openrouter_body(ANSWERS))])
        answers, receipt = harness.evaluate()
        self.assertEqual(answers["screen"]["noul"], Decimal("0.95"))
        self.assertEqual(harness.script.connects[0][0], ("openrouter.ai", 443))
        self.assertEqual(harness.script.server_hostnames, ["openrouter.ai"])
        (request,) = harness.script.requests
        self.assertEqual((request.method, request.target), ("POST", "/api/alpha/decisions"))
        self.assertEqual(request.header("Host"), "openrouter.ai")
        self.assertEqual(request.header("Authorization"), "Bearer " + KEY)
        self.assertEqual(receipt["status"], "validated")

    def test_envelope_splice_is_byte_exact(self):
        local = local_envelope(STATE, QUESTIONS)
        wire, questions = encode_request(local)
        self.assertEqual(wire, b'{"model":"openai/gpt-6-luna-decisions","state":'
                         + _json(STATE) + b',"questions":' + _json(QUESTIONS) + DENY + b"}")
        # The state and questions bytes are the local envelope's own bytes.
        self.assertIn(local[len(b'{"contract":"dbh-judge-v1","state":'):-1], wire)
        self.assertEqual(questions, QUESTIONS)
        self.assertNotIn(b"dbh-judge-v1", wire)
        self.assertEqual(json.loads(wire)["state"], STATE)
        for payload in (b"{}", local.replace(b'"state":', b'"state" :', 1),
                        local[:-1] + b',"extra":1}', "text", local + b" ",
                        _json({"contract": "dbh-judge-v1", "questions": QUESTIONS,
                               "state": STATE})):
            with self.subTest(payload=payload[:20]):
                with self.assertRaises(ProviderError) as caught:
                    encode_request(payload)
                self.assertEqual(caught.exception.code, "invalid_request")

    def test_default_routing_fragment_bytes(self):
        self.assertEqual(routing_fragment(), DENY)
        self.assertEqual(routing_fragment("deny", True),
                         b',"provider":{"allow_fallbacks":false,"data_collection":"deny",'
                         b'"zdr":true}')
        self.assertEqual(routing_fragment("account-default"), b"")
        self.assertEqual(routing_fragment("account-default", True), b',"provider":{"zdr":true}')
        for routing in ("only", "", None):
            with self.assertRaises(ProviderError) as caught:
                routing_fragment(routing)
            self.assertEqual(caught.exception.code, "invalid_request")
        with self.assertRaises(ProviderError):
            OpenRouterProvider(KEY, environ={}, routing="allow")

    def test_account_default_omits_provider_object(self):
        harness = Harness(self, [reply(openrouter_body(ANSWERS))], routing="account-default")
        harness.evaluate()
        body = json.loads(harness.script.requests[0].body)
        self.assertEqual(set(body), {"model", "state", "questions"})

    def test_no_session_user_trace_or_attribution_headers(self):
        harness = Harness(self, [reply(openrouter_body(ANSWERS))])
        harness.evaluate()
        (request,) = harness.script.requests
        names = {name.lower() for name, _ in request.headers}
        self.assertEqual(names, {"host", "authorization", "content-type", "accept",
                                 "accept-encoding", "content-length"})
        body = json.loads(request.body)
        self.assertEqual(set(body), {"model", "state", "questions", "provider"})
        self.assertEqual(body["provider"], {"allow_fallbacks": False, "data_collection": "deny"})
        for absent in (b"session_id", b'"user"', b'"trace"', b"zdr"):
            self.assertNotIn(absent, request.body)

    def test_model_allow_list(self):
        self.assertEqual(OpenRouterProvider(KEY, environ={}).identity.model,
                         "openai/gpt-6-luna-decisions")
        for model in ("gpt-6-luna", "openai/gpt-6-luna-decisions-mini", "other/model", ""):
            with self.subTest(model=model), self.assertRaises(ProviderError) as caught:
                OpenRouterProvider(KEY, environ={}, model=model)
            self.assertEqual(caught.exception.code, "invalid_request")


class DecodingTests(unittest.TestCase):
    def decode(self, body, **kwargs):
        return decode_response(body, QUESTIONS, (KEY,), **kwargs)

    def test_model_echo_exact_or_dated_suffix(self):
        for model in ("openai/gpt-6-luna-decisions", "openai/gpt-6-luna-decisions-20261006"):
            with self.subTest(model=model):
                response = self.decode(openrouter_body(ANSWERS, model=model))
                self.assertIsNone(response.error)
                self.assertEqual(response.provenance["model_returned"], model)
        for model in ("openai/gpt-6-luna-decisions-mini", "openai/gpt-6-luna-decisions-2026-10-06",
                      "openai/gpt-6-luna-decisions-2026100", "openai/gpt-6-luna",
                      "gpt-6-luna-decisions", "", 7, None):
            with self.subTest(model=model):
                response = self.decode(openrouter_body(ANSWERS, model=model))
                self.assertEqual(response.error, "response_model")
                self.assertEqual(response.answers, {})
                self.assertEqual(response.usage, {"input_tokens": 100, "output_tokens": 0})
        response = self.decode(openrouter_body(ANSWERS, omit=("model",)))
        self.assertEqual(response.error, "response_model")

    def test_answers_map_exact_keys(self):
        wire = json.loads(openrouter_body(ANSWERS))
        cases = [{"screen": wire["answers"]["screen"]},
                 {**wire["answers"], "extra": wire["answers"]["screen"]},
                 [wire["answers"]["screen"], wire["answers"]["where"]],
                 None]
        for answers in cases:
            with self.subTest(answers=str(answers)[:40]):
                body = json.dumps({**wire, "answers": answers}).encode()
                self.assertEqual(self.decode(body).error, "response_schema")
        reordered = json.dumps({**wire, "answers": {"where": wire["answers"]["where"],
                                                    "screen": wire["answers"]["screen"]}})
        response = self.decode(reordered.encode())
        self.assertIsNone(response.error)
        self.assertEqual(list(response.answers), ["screen", "where"])
        self.assertEqual(response.order_mismatch, 1)

    def test_choice_keys_subset_extra_key_batch_level(self):
        wire = json.loads(openrouter_body(ANSWERS))
        for name, change in (("where", {"reasoning": "private-rationale"}),
                             ("where", {"name": "where"}),
                             ("screen", {"confidence": 0.9})):
            with self.subTest(change=change):
                answers = {**wire["answers"], name: {**wire["answers"][name], **change}}
                response = self.decode(json.dumps({**wire, "answers": answers}).encode())
                self.assertEqual(response.error, "response_schema")
                self.assertNotIn("private-rationale", repr(response))
        no_choice = {k: v for k, v in wire["answers"]["where"].items() if k != "choice"}
        response = self.decode(json.dumps(
            {**wire, "answers": {**wire["answers"], "where": no_choice}}).encode())
        self.assertEqual(response.error, "response_schema")

    def test_unknown_answer_type_batch_schema(self):
        wire = json.loads(openrouter_body(ANSWERS))
        for name, item in (("screen", {"type": "score", "score": 1}),
                           ("screen", {"type": "predicate", "noul": 0.5}),
                           ("where", {"type": "noul", "noul": 0.5}),
                           ("where", {"type": None}),
                           ("screen", {"type": "refusal", "reason": "private-text"}),
                           ("screen", {"type": "refusal", "name": "where"})):
            with self.subTest(item=item):
                response = self.decode(json.dumps(
                    {**wire, "answers": {**wire["answers"], name: item}}).encode())
                self.assertEqual(response.error, "response_schema")
        # Only the explicit refusal type counts as a refusal: one is an
        # answer-scoped defect, two withhold the batch.
        for item in ({"type": "refusal"}, {"type": "refusal", "name": "where"}):
            response = self.decode(json.dumps(
                {**wire, "answers": {**wire["answers"], "where": item}}).encode())
            self.assertIsNone(response.error)
            self.assertEqual(response.scoped, {"where": "question_refused"})
            self.assertEqual(list(response.answers), ["screen"])
        response = self.decode(json.dumps(
            {**wire, "answers": {"screen": {"type": "refusal"},
                                 "where": {"type": "refusal"}}}).encode())
        self.assertEqual(response.error, "response_refused")
        self.assertEqual(response.answers, {})

    def test_choice_without_vector_is_vector_missing(self):
        # Answer-scoped since partial batches (ADR-3): the choice is lost,
        # the noul in the same request is kept (asserted through the gateway).
        wire = json.loads(openrouter_body(ANSWERS))
        for missing in ("probabilities", "confidence"):
            with self.subTest(missing=missing):
                where = {k: v for k, v in wire["answers"]["where"].items() if k != missing}
                body = json.dumps({**wire, "answers": {**wire["answers"], "where": where}})
                response = self.decode(body.encode())
                self.assertIsNone(response.error)
                self.assertEqual(response.scoped, {"where": "response_vector_missing"})
                self.assertEqual(list(response.answers), ["screen"])
                outcome, receipt = Harness(self, [reply(body.encode())]).evaluate()
                self.assertEqual(outcome, {"screen": ANSWERS["screen"]})
                self.assertEqual(receipt["status"], "validated_partial")
                self.assertEqual(receipt["scoped"], {"where": "response_vector_missing"})
                self.assertEqual(receipt["usage"], {"input_tokens": 100, "output_tokens": 0})

    def test_usage_cost_split_before_validate_usage(self):
        response = self.decode(openrouter_body(ANSWERS, input_tokens=8457))
        self.assertEqual(response.usage, {"input_tokens": 8457, "output_tokens": 0})
        self.assertEqual(response.cost_usd, Decimal("0.0008457"))
        self.assertIsInstance(response.cost_usd, Decimal)
        outcome, receipt = Harness(self, [reply(openrouter_body(ANSWERS, input_tokens=8457))]
                                   ).evaluate()
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual(receipt["usage"], {"input_tokens": 8457, "output_tokens": 0})
        for cost in (-1, 10, "0.1", True, None):
            with self.subTest(cost=cost):
                body = json.loads(openrouter_body(ANSWERS))
                body["usage"]["cost"] = cost
                response = self.decode(json.dumps(body).encode())
                self.assertIsNone(response.error)
                self.assertIsNone(response.cost_usd)
                self.assertEqual(response.provenance["cost_error"], "invalid")
        response = self.decode(openrouter_body(ANSWERS, omit=("usage",)))
        self.assertIsNone(response.usage)
        self.assertIsNone(response.cost_usd)

    def test_upstream_provider_recorded_and_unexpected_flagged(self):
        response = self.decode(openrouter_body(ANSWERS))
        self.assertEqual(response.provenance["upstream_provider"], "OpenAI")
        self.assertNotIn("upstream_provider_unexpected", response.provenance)
        for upstream, kept in (("Azure", "Azure"), ("bad\nname", None), (7, None)):
            with self.subTest(upstream=upstream):
                response = self.decode(openrouter_body(ANSWERS, provider=upstream))
                self.assertIsNone(response.error)
                self.assertIs(response.provenance["upstream_provider_unexpected"], True)
                self.assertEqual(response.provenance.get("upstream_provider"), kept)
        response = self.decode(openrouter_body(ANSWERS, omit=("provider", "id")))
        self.assertIsNone(response.error)
        self.assertNotIn("upstream_provider", response.provenance)

    def test_sensitive_and_malformed_bodies(self):
        for body, code in ((openrouter_body(ANSWERS, id=KEY), "response_sensitive"),
                           (b"[]", "response_schema"),
                           (b'{"answers":', "response_invalid_json"),
                           (b'{"a":1,"a":2}', "response_invalid_json")):
            with self.subTest(code=code):
                with self.assertRaises(ProviderError) as caught:
                    self.decode(body)
                self.assertEqual(caught.exception.code, code)
        # A parsed object without answers is still a schema defect, but the
        # usage and cost it reports are kept (the attempt was billed).
        response = self.decode(b'{"model":"x","usage":{"input_tokens":10,"output_tokens":0,'
                               b'"cost":0.000001}}')
        self.assertEqual(response.error, "response_schema")
        self.assertEqual(response.usage, {"input_tokens": 10, "output_tokens": 0})
        self.assertEqual(response.cost_usd, Decimal("0.000001"))
        self.assertEqual(self.decode(b'{"model":"x"}').error, "response_schema")


class FailureTests(unittest.TestCase):
    def test_provider_error_in_200_body(self):
        body = error_body(502, provider_name="OpenAI", raw="private-raw")
        outcome, receipt = Harness(self, [reply(body)]).evaluate()
        self.assertEqual(outcome.code, "provider_error_in_body")
        self.assertTrue(receipt["submission_possible"])
        self.assertEqual(receipt["provider_error"]["error_code"], 502)
        self.assertEqual(receipt["provider_error"]["provider_name"], "OpenAI")
        saved = json.dumps(receipt)
        self.assertNotIn("private-error-message", saved)
        self.assertNotIn("private-raw", saved)

    def test_status_table_openrouter(self):
        routing = {"failed_routing_step": "Filter by Data Policy",
                   "routing_funnel": ["private-funnel"]}
        moderation = {"reasons": ["private-reason"], "flagged_input": "private-flagged",
                      "provider_name": "OpenAI", "model_slug": "x"}
        cases = [(301, None, "http_redirect", True, True),
                 (400, None, "http_rejected", True, False),
                 (401, None, "http_unauthorized", True, True),
                 (402, None, "http_payment_required", True, True),
                 (403, moderation, "provider_moderated", True, False),
                 (403, None, "http_forbidden", True, True),
                 (404, routing, "routing_no_endpoint", True, True),
                 (404, None, "route_unavailable", True, True),
                 (408, None, "http_request_timeout", False, False),
                 (413, None, "request_too_large", True, False),
                 (422, None, "http_rejected", True, False),
                 (429, None, "http_rate_limited", False, False),
                 (500, None, "http_server_error", True, False),
                 (502, None, "http_server_error", True, False),
                 (503, routing, "routing_no_endpoint", True, True),
                 (503, None, "http_unavailable", False, False),
                 (504, None, "http_server_error", True, False),
                 (524, None, "http_provider_timeout", True, False),
                 (529, None, "http_overloaded", False, False)]
        for status, metadata, code, possible, blocks in cases:
            with self.subTest(status=status, metadata=bool(metadata)):
                body = error_body(status, **(metadata or {}))
                harness = Harness(self, [reply(body, status)])
                outcome, receipt = harness.evaluate()
                self.assertEqual(outcome.code, code)
                self.assertIsNone(outcome.__context__)
                self.assertIs(receipt["submission_possible"], possible)
                self.assertEqual(receipt["generation_id"], GENERATION)
                self.assertEqual(receipt["provider_error"]["error_body"], "ok")
                self.assertEqual(receipt["provider_error"]["error_code"], status)
                if blocks:
                    with self.assertRaises(ProviderError):
                        harness.gateway.require_available()
                else:
                    harness.gateway.require_available()
                saved = json.dumps(receipt)
                for private in ("private-", "Filter by Data Policy", CF_RAY, "cloudflare"):
                    self.assertNotIn(private, saved)

    def test_retry_after_recorded_only_for_retryable_rejections(self):
        outcome, receipt = Harness(self, [reply(error_body(429), 429,
                                                extra=[("Retry-After", "7")])]).evaluate()
        self.assertEqual(outcome.code, "http_rate_limited")
        self.assertEqual(receipt["retry_after_seconds"], 7.0)
        self.assertEqual(receipt["submission"], "rejected_unprocessed")
        outcome, receipt = Harness(self, [reply(error_body(402), 402,
                                                extra=[("Retry-After", "7")])]).evaluate()
        self.assertEqual(outcome.code, "http_payment_required")
        self.assertNotIn("retry_after_seconds", receipt)

    def test_error_extractor_never_keeps_message_metadata_user_id(self):
        body = error_body(403, message=f"private message {KEY[:6]}",
                          reasons=["private-reason"], flagged_input="private-flagged",
                          user_id="user-private-77", routing_funnel=["private-step"],
                          failed_routing_step="private-step", raw="private-raw",
                          provider_name="OpenAI", error_type="moderation_flag",
                          provider_code="content_filter", model_slug="private-slug")
        outcome, receipt = Harness(self, [reply(body, 403)]).evaluate()
        self.assertEqual(outcome.code, "provider_moderated")
        self.assertEqual(receipt["provider_error"], {
            "error_body": "ok", "error_code": 403, "moderation": True,
            "routing_metadata": True, "provider_error_type": "moderation_flag",
            "provider_code": "content_filter", "provider_name": "OpenAI"})
        saved = json.dumps(receipt)
        for private in ("private", "user-private-77", "message"):
            self.assertNotIn(private, saved)
        # A body carrying the key, even masked, is withheld before parsing.
        for leaked in (KEY, "sk-" + "or-v1-abc" + "***"):
            with self.subTest(leaked=leaked[:8]):
                outcome, receipt = Harness(self, [reply(error_body(403, leaked), 403)]
                                           ).evaluate()
                self.assertEqual(outcome.code, "http_forbidden")
                self.assertEqual(receipt["provider_error"], {"error_body": "withheld_sensitive"})
                self.assertNotIn(KEY, json.dumps(receipt))

    def test_generation_id_from_header_charset(self):
        for header, kept in ((GENERATION, GENERATION), ("gen dec spaced", None),
                             ("g" * 129, None), ("gen-dec-" + KEY, None)):
            with self.subTest(header=header[:16]):
                harness = Harness(self, [reply(openrouter_body(ANSWERS), generation=header)])
                _, receipt = harness.evaluate()
                self.assertEqual(receipt["status"], "validated")
                self.assertEqual(receipt["generation_id"], kept)
                self.assertNotIn(KEY, json.dumps(receipt))
        harness = Harness(self, [reply(openrouter_body(ANSWERS), generation=None)])
        _, receipt = harness.evaluate()
        self.assertIsNone(receipt["generation_id"])
        self.assertNotIn(CF_RAY, json.dumps(receipt))
        self.assertNotIn("ray", json.dumps(receipt).lower())

    def test_receipt_provenance_and_wire_hash(self):
        harness = Harness(self, [reply(openrouter_body(ANSWERS))])
        _, receipt = harness.evaluate()
        (request,) = harness.script.requests
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual((receipt["route"], receipt["model_requested"]),
                         ("openrouter-decisions", "openai/gpt-6-luna-decisions"))
        self.assertEqual((receipt["provider"], receipt["model"]),
                         ("openrouter-decisions", "openai/gpt-6-luna-decisions"))
        self.assertEqual(receipt["model_returned"], "openai/gpt-6-luna-decisions-20261006")
        self.assertEqual(receipt["upstream_provider"], "OpenAI")
        self.assertEqual(receipt["wire_sha256"], hashlib.sha256(request.body).hexdigest())
        self.assertEqual(receipt["request_sha256"],
                         hashlib.sha256(local_envelope(STATE, QUESTIONS)).hexdigest())
        self.assertIsNone(receipt["request_id"])
        self.assertIs(receipt["answer_order_mismatch"], False)

    def test_rejected_200_keeps_generation_id_wire_hash_usage_and_cost(self):
        # Billed 200s that fail decoding or framing are exactly the ones to
        # raise with the provider by generation id (review finding).
        usage_only = (b'{"model":"openai/gpt-6-luna-decisions","usage":{"input_tokens":10,'
                      b'"output_tokens":0,"cost":0.000001}}')
        cases = [(usage_only, "response_schema", None),
                 (b'{"answers": nope', "response_invalid_json", None),
                 (b'{"answers": NaN}', "response_invalid_json", None),
                 (b'{"answers": 0.' + b"1" * 200 + b"}", None, None),
                 (openrouter_body(ANSWERS), "response_type", "text/plain"),
                 (openrouter_body(ANSWERS), "response_type", "application/json; x=1")]
        for body, code, content_type in cases:
            with self.subTest(body=body[:24], content_type=content_type):
                step = reply(body)
                if content_type is not None:
                    step = Reply(status=200, body=body, close_after=True, headers=[
                        ("Content-Type", content_type), ("Content-Length", str(len(body))),
                        ("x-generation-id", GENERATION)])
                harness = Harness(self, [step])
                outcome, receipt = harness.evaluate()
                self.assertIsInstance(outcome, ProviderError)
                if code is not None:
                    self.assertEqual(outcome.code, code)
                self.assertIsNone(outcome.__context__)
                (request,) = harness.script.requests
                self.assertEqual(receipt["generation_id"], GENERATION)
                self.assertEqual(receipt["wire_sha256"], hashlib.sha256(request.body).hexdigest())
                self.assertTrue(receipt["submission_possible"])
                if body is usage_only:
                    self.assertEqual(receipt["usage"], {"input_tokens": 10, "output_tokens": 0})
                    self.assertEqual(receipt["cost_source"], "provider_reported")
                    self.assertEqual(receipt["cost_usd"], "0.000001")
                    self.assertEqual(receipt["model_returned"], "openai/gpt-6-luna-decisions")

    def test_unavailable_without_key_and_never_connects(self):
        script = ScriptedHTTPS([], clock=FakeClock(), host=openrouter.HOST)
        exchange = script.exchange(openrouter.HOST, openrouter.PATH)
        provider = OpenRouterProvider(environ={"OPENAI_API_KEY": "openai-only-key-123"},
                                      exchange=exchange)
        request = ProviderRequest(local_envelope(STATE, QUESTIONS), 1.0)
        for operation in (provider.require_available, lambda: provider.decide(request)):
            with self.assertRaises(ProviderError) as caught:
                operation()
            self.assertEqual(caught.exception.code, "provider_unavailable")
        self.assertEqual(script.connects, [])


if __name__ == "__main__":
    unittest.main()
