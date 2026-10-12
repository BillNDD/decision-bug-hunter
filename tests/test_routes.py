"""Route abstraction and explicit provider selection, fully offline.

Both routes serve the same Decisions judge. These tests pin selection (never
inferred from which key is set), model allow-lists, status tables, error
field extraction, provenance and that one engine fixture gives the same
findings through either adapter. No socket is opened and no real key is read.
"""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import decisions, hosted, openrouter, providers
from decision_bug_hunter.core import Config, Source
from decision_bug_hunter.decisions import (DecisionsProvider, error_fields, param_path,
                                           status_code, translate_response)
from decision_bug_hunter.engine import Search
from decision_bug_hunter.hosted import parse_retry_after
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import ProviderError, QUESTION
from decision_bug_hunter.providers import (ProviderIdentity, ValidatedGateway, classify,
                                           make_provider)
from tests.fakes import FakeClock, Reply, ScriptedHTTPS
from tests.support import (FixtureProvider, clean_provider_env, openai_body,
                           openrouter_body, scan, source)
from tests.test_decisions import FakeDecisionsService


KEY = "offline-route-sentinel-credential-5b1a"
OTHER = "offline-inactive-sentinel-credential-93f0"
ROOT = Path(__file__).resolve().parents[1]
CF_RAY = "8f1e2d3c4b5a6978-ZZZ"
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
ANSWERS = {"screen": {"type": "noul", "noul": 0.95},
           "where": {"type": "choice", "choice": "L1-1", "confidence": 0.9,
                     "probabilities": {"L1-1": 0.95, "none": 0.05}}}
METADATA = {"sequence": 1, "phase": "test"}
FAST = ["--no-whole-file", "--no-bug-lenses", "--max-action-steps", "0"]


class FakeOpenRouterService(ScriptedHTTPS):
    """Answers OpenRouter requests with the deterministic fixture judge."""

    def __init__(self, fixture):
        super().__init__([], host=openrouter.HOST)
        self.fixture = fixture
        self.bodies = []

    def _next_step(self, kind):
        request = self.requests[-1]
        assert (request.method, request.target) == ("POST", openrouter.PATH), request.target
        data = json.loads(request.body)
        self.bodies.append(data)
        answers = {name: self.fixture.answer(name, question, data["state"])
                   for name, question in data["questions"].items()}
        body = openrouter_body(answers, input_tokens=max(1, len(request.body) // 4))
        return Reply(body=body, headers=[
            ("Content-Type", "application/json"), ("Content-Length", str(len(body))),
            ("x-generation-id", f"gen-dec-fixture{len(self.bodies):06d}"), ("cf-ray", CF_RAY)])


class ReorderingDecisionsService(FakeDecisionsService):
    """The OpenAI fake, returning its answer list in reverse order."""

    def _next_step(self, kind):
        step = super()._next_step(kind)
        data = json.loads(step.body)
        data["answers"].reverse()
        return Reply(body=json.dumps(data).encode())


def run_cli(argv, **environment):
    out, err = io.StringIO(), io.StringIO()
    with clean_provider_env(**environment), redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def served_by(service):
    """Patch the exchange a CLI-built provider gets onto ``service``."""
    return patch.object(hosted, "HttpsExchange",
                        side_effect=lambda host, path, port=443: service.exchange(
                            host, path, port=port))


class SelectionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.target = self.root / "target.py"
        self.target.write_text("a = 1\nb = a / 0\n", encoding="utf-8")
        self.out = self.root / "out"
        self.reader = patch.object(Source, "read", side_effect=AssertionError("source read"))
        self.read = self.reader.start()
        self.addCleanup(self.reader.stop)

    def argv(self, *extra):
        return [str(self.target), "--scope", "standalone", "--judge", "openai",
                "--output-dir", str(self.out), *extra]

    def test_provider_required_need_user_input_lists_variable_names(self):
        code, out, err = run_cli(self.argv(), OPENROUTER_API_KEY=OTHER)
        self.assertEqual((code, out), (3, ""))
        self.assertIn("NEED_USER_INPUT provider: openai | openrouter (set: OPENROUTER_API_KEY)",
                      err)
        self.assertNotIn(OTHER, err)
        code, _, err = run_cli(self.argv(), OPENAI_API_KEY=KEY, OPENROUTER_API_KEY=OTHER)
        self.assertEqual(code, 3)
        self.assertIn("(set: OPENAI_API_KEY, OPENROUTER_API_KEY)", err)
        self.assertNotIn(KEY, err)
        code, _, err = run_cli(self.argv())
        self.assertEqual(code, 3)
        self.assertIn("NEED_USER_INPUT provider: openai | openrouter (set: none)", err)
        # The scope gate still comes first.
        code, _, err = run_cli([str(self.target), "--output-dir", str(self.out)])
        self.assertEqual(code, 3)
        self.assertIn("NEED_USER_INPUT project_scope", err)
        self.assertFalse(self.read.called)
        self.assertFalse(self.out.exists())

    def test_invalid_dbh_provider_exit2(self):
        for value in ("bogus-route-sentinel", "OpenAI", "openai "):
            with self.subTest(value=value):
                code, out, err = run_cli(self.argv(), DBH_PROVIDER=value, OPENAI_API_KEY=KEY)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("Scan failed (invalid_provider).", err)
                self.assertIn("DBH_PROVIDER must be one of: openai, openrouter.", err)
                self.assertNotIn("bogus-route-sentinel", err)
        # --provider wins over the environment.
        code, _, err = run_cli(self.argv("--provider", "openrouter"),
                               DBH_PROVIDER="bogus-route-sentinel")
        self.assertEqual(code, 2)
        self.assertIn("provider_unavailable", err)
        self.assertFalse(self.read.called)
        self.assertFalse(self.out.exists())

    def test_explicit_provider_missing_key_unavailable(self):
        for argv, environment, variable in (
                (self.argv("--provider", "openrouter"), {"OPENAI_API_KEY": KEY},
                 "OPENROUTER_API_KEY"),
                (self.argv(), {"DBH_PROVIDER": "openrouter", "OPENAI_API_KEY": KEY},
                 "OPENROUTER_API_KEY"),
                (self.argv("--provider", "openai"), {"OPENROUTER_API_KEY": OTHER},
                 "OPENAI_API_KEY")):
            with self.subTest(argv=argv[-2:], environment=sorted(environment)):
                code, out, err = run_cli(argv, **environment)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("Scan failed (provider_unavailable).", err)
                self.assertIn(f"Set {variable} in the environment", err)
                self.assertNotIn(KEY, err)
                self.assertNotIn(OTHER, err)
        self.assertFalse(self.read.called)
        self.assertFalse(self.out.exists())

    def test_unlisted_model_rejected_before_source_read(self):
        for provider, model in (("openrouter", "other-vendor/other-model-1"),
                                ("openrouter", "openai/gpt-6-luna-decisions-mini"),
                                ("openrouter", "gpt-6-luna"),
                                ("openai", "openai/gpt-6-luna-decisions"),
                                ("openai", "gpt-6-luna-mini")):
            with self.subTest(provider=provider, model=model):
                code, out, err = run_cli(self.argv("--provider", provider, "--model", model),
                                         OPENAI_API_KEY=KEY, OPENROUTER_API_KEY=OTHER)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("Scan failed (invalid_request).", err)
                self.assertNotIn(model, err)
        # OpenRouter privacy options are refused on the OpenAI route.
        for extra in (("--openrouter-zdr",), ("--openrouter-routing", "account-default")):
            with self.subTest(extra=extra):
                code, _, err = run_cli(self.argv("--provider", "openai", *extra),
                                       OPENAI_API_KEY=KEY)
                self.assertEqual(code, 2)
                self.assertIn("Scan failed (invalid_request).", err)
        self.assertFalse(self.read.called)
        self.assertFalse(self.out.exists())

    def test_inactive_provider_key_in_source_refused(self):
        provider = DecisionsProvider(KEY, environ={"OPENROUTER_API_KEY": OTHER})
        routed = OpenRouterProvider(OTHER, environ={"OPENAI_API_KEY": KEY})
        for candidate, inactive in ((provider, OTHER), (routed, KEY)):
            with self.assertRaises(ProviderError) as caught:
                candidate.check_sensitive("text with " + inactive)
            self.assertEqual(caught.exception.code, "sensitive_input")
        # Short placeholders are not treated as credentials.
        DecisionsProvider(KEY, environ={"OPENROUTER_API_KEY": "x"}).check_sensitive("x marks")
        self.reader.stop()
        self.target.write_text("token = " + repr(OTHER) + "\n", encoding="utf-8")
        code, out, err = run_cli(self.argv("--provider", "openai"),
                                 OPENAI_API_KEY=KEY, OPENROUTER_API_KEY=OTHER)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Scan failed (sensitive_input).", err)
        self.assertNotIn(OTHER, err)
        self.assertFalse(self.out.exists())

    def test_run_catalog_cli_args_parse(self):
        path = ROOT / "tools" / "eval" / "run_catalog.py"
        spec = importlib.util.spec_from_file_location("dbh_run_catalog_under_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cases = module.catalog.cases()
        picked = [cases[0]] + [case for case in cases if case["scope"] == "project"][:1]
        self.assertEqual(len(picked), 2)
        for case in picked:
            with self.subTest(case=case["id"]), tempfile.TemporaryDirectory() as temp:
                argv, _ = module.materialize(case, Path(temp))
                args = cli.parser().parse_args(argv + ["--provider", "openrouter"])
                self.assertEqual(args.provider, "openrouter")
                self.assertEqual(cli.selected_provider(args, {}), "openrouter")
                self.assertEqual(args.openrouter_routing, "deny")
                self.assertFalse(args.openrouter_zdr)


class LibraryTests(unittest.TestCase):
    def test_make_provider_routes_and_allow_lists(self):
        openai = make_provider("openai", api_key=KEY, environ={})
        self.assertIsInstance(openai, DecisionsProvider)
        self.assertEqual((openai.identity.name, openai.identity.model),
                         ("openai-decisions", "gpt-6-luna"))
        routed = make_provider("openrouter-decisions", api_key=KEY, environ={})
        self.assertIsInstance(routed, OpenRouterProvider)
        self.assertEqual((routed.identity.name, routed.identity.model, routed.routing),
                         ("openrouter-decisions", "openai/gpt-6-luna-decisions", "deny"))
        # Identity is per instance, not a class attribute.
        self.assertNotIn("identity", vars(DecisionsProvider))
        self.assertEqual(make_provider("openrouter", api_key=KEY, environ={},
                                       routing="account-default", zdr=True).zdr, True)
        for kwargs, code in (({"route": "other-route"}, "invalid_provider"),
                             ({"route": None}, "invalid_provider"),
                             ({"route": "openai", "routing": "deny"}, "invalid_request"),
                             ({"route": "openai", "zdr": True}, "invalid_request"),
                             ({"route": "openai", "model": "gpt-6-sol"}, "invalid_request"),
                             ({"route": "openrouter", "routing": "only"}, "invalid_request")):
            with self.subTest(kwargs=kwargs), self.assertRaises(ProviderError) as caught:
                make_provider(api_key=KEY, environ={}, **kwargs)
            self.assertEqual(caught.exception.code, code)

    def test_identity_accepts_vendor_slash_model(self):
        identity = ProviderIdentity("openrouter-decisions", model="openai/gpt-6-luna-decisions")
        self.assertEqual(identity.model, "openai/gpt-6-luna-decisions")
        for name, model in (("a/b", None), ("x", "has space"), ("x", "m" * 129),
                            ("x", "line\nbreak"), ("", None), ("x", "")):
            with self.subTest(name=name, model=model), self.assertRaises(ProviderError):
                ProviderIdentity(name, model=model)

    def test_classification_table(self):
        self.assertEqual(classify("connect_failed").submission, "not_sent")
        self.assertFalse(classify("connect_failed").submission_possible)
        self.assertFalse(classify("http_rate_limited").submission_possible)
        self.assertTrue(classify("http_server_error").submission_possible)
        self.assertTrue(classify("http_rejected").submission_possible)
        self.assertTrue(classify("http_rejected").permanent)
        self.assertTrue(classify("response_schema").permanent)
        self.assertFalse(classify("provider_error_in_body").permanent)
        blocking = {code for code in ("http_redirect", "http_unauthorized",
                                      "http_payment_required", "http_forbidden",
                                      "route_unavailable", "routing_no_endpoint",
                                      "http_quota_exhausted", "provider_moderated",
                                      "http_rate_limited", "http_unavailable")
                    if classify(code).blocking}
        self.assertEqual(blocking, {"http_redirect", "http_unauthorized",
                                    "http_payment_required", "http_forbidden",
                                    "route_unavailable", "routing_no_endpoint",
                                    "http_quota_exhausted"})
        self.assertEqual(classify("http_forbidden").scope, "run")
        self.assertEqual(classify("request_too_large", submission="not_sent").submission,
                         "not_sent")
        with self.assertRaises(ProviderError):
            classify("http_rejected", submission="maybe")

    def test_retry_after_parse(self):
        now = datetime(2026, 10, 7, 0, 0, 0, tzinfo=timezone.utc)
        future = format_datetime(now + timedelta(seconds=30), usegmt=True)
        past = format_datetime(now - timedelta(seconds=30), usegmt=True)
        for value, expected in (("7", 7.0), (" 0 ", 0.0), ("120", 60.0), ("99999", 60.0),
                                ("123456", None), ("-1", None), ("1.5", None), ("soon", None),
                                ("", None), (None, None), (future, 30.0), (past, 0.0)):
            with self.subTest(value=value):
                self.assertEqual(parse_retry_after(value, now), expected)


class OpenAIRouteTests(unittest.TestCase):
    def gateway(self, steps):
        script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=decisions.HOST)
        provider = DecisionsProvider(KEY, environ={},
                                     exchange=script.exchange(decisions.HOST, decisions.PATH))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gateway = ValidatedGateway(provider, Path(tmp.name) / "receipts")
        self.addCleanup(gateway.close)
        return gateway, script

    def evaluate(self, body, status=200, headers=None):
        reply = Reply(status=status, body=body, headers=headers, close_after=True)
        gateway, _ = self.gateway([reply])
        try:
            outcome = gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
        except ProviderError as exc:
            outcome = exc
        return outcome, json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))

    def test_status_table_openai(self):
        overloaded = {"type": "server_error", "code": "server_is_overloaded"}
        for status, error, code in (
                (301, None, "http_redirect"), (308, None, "http_redirect"),
                (400, None, "http_rejected"), (401, None, "http_unauthorized"),
                (402, None, "http_rejected"), (403, None, "http_forbidden"),
                (404, None, "route_unavailable"), (408, None, "http_request_timeout"),
                (409, None, "http_rejected"), (413, None, "request_too_large"),
                (422, None, "http_rejected"), (429, None, "http_rate_limited"),
                (429, {"code": "insufficient_quota"}, "http_quota_exhausted"),
                (429, {"type": "billing_hard_limit_reached"}, "http_quota_exhausted"),
                (429, {"code": "insufficient_quota_soon"}, "http_rate_limited"),
                (500, None, "http_server_error"), (502, None, "http_server_error"),
                (503, None, "http_server_error"), (503, overloaded, "http_overloaded"),
                (503, {"type": "server_is_overloaded"}, "http_overloaded"),
                (504, None, "http_server_error"), (524, None, "http_server_error"),
                (529, None, "http_server_error")):
            with self.subTest(status=status, error=error):
                self.assertEqual(status_code(status, error), code)

    def test_error_param_grammar(self):
        for value in ("questions[3].choices[0].value", "model", "input", "safety_identifier",
                      "questions[12].instructions", "questions[0].levels[2].label",
                      "questions.name"):
            with self.subTest(value=value):
                self.assertEqual(param_path(value), value)
                self.assertEqual(error_fields(400, {"param": value}), {"param": value})
        for value in ("questions[3].choices[0].value.text.more", "messages[0]",
                      "questions[1234]", "questions.Choices", "sk-abc123", "free text here",
                      "questions[3].secret", "", "questions[3]..value", "questions[-1]",
                      "input.text " + KEY, 3, ["model"]):
            with self.subTest(value=value):
                self.assertIsNone(param_path(value))
                self.assertEqual(error_fields(422, {"param": value}), {"param_withheld": True})
        # Kept only on 400 and 422; never alongside message text.
        self.assertEqual(error_fields(500, {"param": "model", "message": "private"}), {})
        self.assertEqual(error_fields(400, {"type": "invalid_request_error",
                                            "code": "Bad Code", "message": "private"}),
                         {"error_type": "invalid_request_error"})
        body = json.dumps({"error": {"type": "invalid_request_error", "code": None,
                                     "param": "questions[0].choices[1].value",
                                     "message": "private-message"}}).encode()
        outcome, receipt = self.evaluate(body, 400)
        self.assertEqual(outcome.code, "http_rejected")
        self.assertEqual(receipt["provider_error"], {
            "error_body": "ok", "error_type": "invalid_request_error",
            "param": "questions[0].choices[1].value"})
        self.assertNotIn("private-message", json.dumps(receipt))

    def test_openai_prefix_hole_closed(self):
        for model in ("gpt-6-luna-mini", "gpt-6-lunar", "gpt-6-luna-2026", "gpt-6-luna-",
                      "gpt-6-luna-20261006x", "openai/gpt-6-luna"):
            with self.subTest(model=model):
                response = translate_response(openai_body(ANSWERS, model=model), QUESTIONS)
                self.assertEqual(response.error, "response_model")
        for model in ("gpt-6-luna", "gpt-6-luna-20261006", "gpt-6-luna-2026-10-06"):
            with self.subTest(model=model):
                response = translate_response(openai_body(ANSWERS, model=model), QUESTIONS)
                self.assertIsNone(response.error)
                self.assertEqual(response.provenance["model_returned"], model)
        # The echo is checked against the requested model, not a constant.
        response = translate_response(openai_body(ANSWERS, model="gpt-6-luna"), QUESTIONS,
                                      model="gpt-6-other")
        self.assertEqual(response.error, "response_model")
        response = translate_response(openai_body(ANSWERS, model="gpt-6-other-20261006"),
                                      QUESTIONS, model="gpt-6-other")
        self.assertIsNone(response.error)

    def test_openai_boolean_choice_fails_closed(self):
        body = json.loads(openai_body(ANSWERS))
        where = body["answers"][1]
        for change in ({"choice": True},
                       {"probabilities": [{"value": True, "probability": 0.95},
                                          {"value": False, "probability": 0.05}]},
                       {"probabilities": [{"value": "L1-1", "probability": True},
                                          {"value": "none", "probability": False}]}):
            with self.subTest(change=change):
                answers = [body["answers"][0], {**where, **change}]
                raw = json.dumps({**body, "answers": answers}).encode()
                outcome, receipt = self.evaluate(raw)
                # A boolean choice is a wrong type (batch-level response_schema
                # since ADR-3); boolean values are response_probability.
                self.assertIn(outcome.code, {"response_distribution", "response_probability",
                                             "response_schema"})
                self.assertIsNone(receipt["answers"])

    def test_order_mismatch_counted_not_fatal(self):
        body = json.loads(openai_body(ANSWERS))
        body["answers"].reverse()
        answers, receipt = self.evaluate(json.dumps(body).encode())
        self.assertEqual(list(answers), ["screen", "where"])
        self.assertEqual(receipt["status"], "validated")
        self.assertIs(receipt["answer_order_mismatch"], True)
        service = ReorderingDecisionsService(FixtureProvider([(2, 2)]))
        provider = DecisionsProvider(KEY, environ={},
                                     exchange=service.exchange(decisions.HOST, decisions.PATH))
        with tempfile.TemporaryDirectory() as td, \
                ValidatedGateway(provider, Path(td) / "receipts") as gateway:
            report = scan(source(6), gateway, config=Config(whole_file=False, bug_lenses=False,
                                                            max_action_steps=0))
        multi = sum(1 for body in service.bodies if len(body["questions"]) > 1)
        self.assertGreater(multi, 0)
        self.assertEqual(report["provenance"]["answer_order_mismatch"], multi)
        self.assertEqual(report["provenance"]["models_returned"], ["gpt-6-luna"])

    def test_provider_error_in_200_body_both_routes(self):
        raw = json.dumps({"error": {"type": "server_error", "code": "upstream_failed",
                                    "message": "private-message"},
                          "usage": {"input_tokens": 5, "output_tokens": 0}}).encode()
        outcome, receipt = self.evaluate(raw)
        self.assertEqual(outcome.code, "provider_error_in_body")
        self.assertEqual(receipt["usage"], {"input_tokens": 5, "output_tokens": 0})
        self.assertEqual(receipt["provider_error"],
                         {"error_type": "server_error", "error_code": "upstream_failed"})
        self.assertNotIn("private-message", json.dumps(receipt))
        response = openrouter.decode_response(
            json.dumps({"error": {"code": 502, "message": "private-message"}}).encode(),
            QUESTIONS)
        self.assertEqual(response.error, "provider_error_in_body")
        self.assertEqual(response.provenance["error_code"], 502)
        # Without ``error`` a missing ``answers`` stays a schema defect, with
        # the reported usage kept for the receipt.
        response = translate_response(
            b'{"model":"gpt-6-luna","usage":{"input_tokens":4,"output_tokens":0}}', QUESTIONS)
        self.assertEqual(response.error, "response_schema")
        self.assertEqual(response.usage, {"input_tokens": 4, "output_tokens": 0})
        outcome, receipt = self.evaluate(
            b'{"model":"gpt-6-luna","usage":{"input_tokens":4,"output_tokens":0}}')
        self.assertEqual(outcome.code, "response_schema")
        self.assertEqual(receipt["usage"], {"input_tokens": 4, "output_tokens": 0})

    def test_rejected_200_keeps_request_id_and_wire_hash(self):
        for body in (b'{"answers": nope', b'{"model":"gpt-6-luna"}'):
            with self.subTest(body=body):
                outcome, receipt = self.evaluate(body, headers=[
                    ("Content-Type", "application/json"), ("Content-Length", str(len(body))),
                    ("x-request-id", "req_0123abc")])
                self.assertIsInstance(outcome, ProviderError)
                self.assertEqual(receipt["request_id"], "req_0123abc")
                self.assertRegex(receipt["wire_sha256"], "^[0-9a-f]{64}$")

    def test_request_id_header_charset(self):
        for value, kept in (("req_0123abc", "req_0123abc"), ("req with space", None)):
            with self.subTest(value=value):
                body = openai_body(ANSWERS)
                _, receipt = self.evaluate(body, headers=[
                    ("Content-Type", "application/json"), ("Content-Length", str(len(body))),
                    ("x-request-id", value)])
                self.assertEqual(receipt["request_id"], kept)
                self.assertIsNone(receipt["generation_id"])


class EngineRouteTests(unittest.TestCase):
    def test_cache_key_includes_route_and_model(self):
        keys = []
        for model in (None, "fixture-model/v1"):
            fixture = FixtureProvider([(2, 2)])
            fixture.model_id = model
            search = Search(source(6), fixture, Config(whole_file=False, bug_lenses=False,
                                                        max_action_steps=0),
                            None, context_scope="declared_standalone")
            search.run()
            self.assertTrue(search.cache)
            for key in list(search.cache) + list(search.request_origins):
                self.assertEqual(key[:2], ("offline-fixture", model))
                self.assertRegex(key[2], r"\A[0-9a-f]{64}\Z")
            keys.append({key[2] for key in search.cache})
        # The request hash itself does not depend on route or model.
        self.assertEqual(keys[0], keys[1])

    def test_same_fixture_identical_findings_both_routes(self):
        config = Config(whole_file=False, bug_lenses=False, max_action_steps=0)
        target = source(14)
        reports, receipts, services = {}, {}, {}
        for route, service in (("openai", FakeDecisionsService(FixtureProvider([(5, 5)]))),
                               ("openrouter", FakeOpenRouterService(FixtureProvider([(5, 5)])))):
            module = decisions if route == "openai" else openrouter
            provider = make_provider(route, api_key=KEY, environ={},
                                     exchange=service.exchange(module.HOST, module.PATH))
            with tempfile.TemporaryDirectory() as td, \
                    ValidatedGateway(provider, Path(td) / "receipts") as gateway:
                reports[route] = scan(target, gateway, config=config)
                receipts[route] = [json.loads(p.read_text(encoding="utf-8"))
                                   for p in (Path(td) / "receipts").glob("*.json")]
            services[route] = service
        openai, routed = reports["openai"], reports["openrouter"]
        self.assertTrue(openai["findings"])
        for key in ("findings", "status", "coverage", "issues", "calls_attempted"):
            self.assertEqual(openai[key], routed[key], key)
        self.assertEqual((routed["provider"], routed["model"]),
                         ("openrouter-decisions", "openai/gpt-6-luna-decisions"))
        self.assertEqual(routed["provenance"]["models_returned"],
                         ["openai/gpt-6-luna-decisions-20261006"])
        self.assertFalse(routed["provenance"]["model_returned_changed"])
        self.assertEqual(sorted(r["request_sha256"] for r in receipts["openai"]),
                         sorted(r["request_sha256"] for r in receipts["openrouter"]))
        for receipt in receipts["openrouter"]:
            self.assertEqual((receipt["route"], receipt["model_requested"], receipt["model"]),
                             ("openrouter-decisions", "openai/gpt-6-luna-decisions",
                              "openai/gpt-6-luna-decisions"))
            self.assertEqual(receipt["upstream_provider"], "OpenAI")
            self.assertTrue(receipt["generation_id"].startswith("gen-dec-fixture"))
            self.assertNotEqual(receipt["wire_sha256"], receipt["request_sha256"])
        everything = json.dumps([reports, receipts])
        self.assertNotIn(CF_RAY, everything)
        self.assertNotIn(KEY, everything)
        # Generation ids stay in receipts only.
        self.assertNotIn("gen-dec-fixture", json.dumps(reports))
        self.assertGreater(services["openrouter"].reuse_count, 0)


class CliRouteTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.target = self.root / "target.py"
        self.target.write_text("a = 1\nb = a / 0\nprint('private-line-three')\n",
                               encoding="utf-8")

    def files(self):
        return {path: path.read_text(encoding="utf-8")
                for path in (self.root / "runs").rglob("*") if path.is_file()}

    def test_account_default_omits_object_and_discloses(self):
        service = FakeOpenRouterService(FixtureProvider([(2, 2)]))
        argv = [str(self.target), "--scope", "standalone", "--provider", "openrouter",
                "--openrouter-routing", "account-default", "--output-dir",
                str(self.root / "runs"), *FAST]
        with served_by(service):
            code, out, err = run_cli(argv, OPENROUTER_API_KEY=KEY, DBH_JUDGE="openai")
        self.assertEqual(code, 1, err)
        self.assertEqual(err.count("OpenRouter routing: account default."), 1)
        self.assertTrue(service.bodies)
        for body in service.bodies:
            self.assertEqual(set(body), {"model", "state", "questions"})
        report = json.loads(next((self.root / "runs").glob("run-*/report.json")).read_text(
            encoding="utf-8"))
        self.assertEqual(report["provider"], "openrouter-decisions")
        # The default sends the deny object and prints no disclosure.
        service = FakeOpenRouterService(FixtureProvider([(2, 2)]))
        with served_by(service):
            code, _, err = run_cli(argv[:5] + argv[7:], OPENROUTER_API_KEY=KEY,
                                   DBH_JUDGE="openai")
        self.assertEqual(code, 1, err)
        self.assertNotIn("account default", err)
        for body in service.bodies:
            self.assertEqual(body["provider"],
                             {"allow_fallbacks": False, "data_collection": "deny"})

    def test_routing_ids_absent_from_receipts_reports_stdout(self):
        org, project = "org-routing-sentinel-1", "proj-routing-sentinel-2"
        service = FakeDecisionsService(FixtureProvider([(2, 2)]))
        argv = [str(self.target), "--scope", "standalone", "--provider", "openai",
                "--output-dir", str(self.root / "runs"), *FAST]
        with served_by(service):
            code, out, err = run_cli(argv, OPENAI_API_KEY=KEY, OPENAI_ORG_ID=org,
                                     OPENAI_PROJECT_ID=project, DBH_JUDGE="openai")
        self.assertEqual(code, 1, err)
        for request in service.headers:
            self.assertEqual(request.header("OpenAI-Organization"), org)
            self.assertEqual(request.header("OpenAI-Project"), project)
        files = self.files()
        self.assertTrue(any(path.parent.name == "receipts" for path in files))
        for text in (out, err, *files.values()):
            for private in (org, project, KEY):
                self.assertNotIn(private, text)


if __name__ == "__main__":
    unittest.main()
