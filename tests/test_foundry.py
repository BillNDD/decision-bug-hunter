"""Offline Foundry route contracts: scripted sockets, no network, no key.

The response bodies in ``tests/fixtures/foundry`` are built from the shapes in
Microsoft's public documentation of Microsoft-Decision-1 (2026-10-09); the
usage field names, the dated echo and the error bodies are assumptions, and no
deployment has been run. Passing these establishes local encoding, decoding,
endpoint validation and failure mapping; it says nothing about the live
service, which is why the route stays "not yet verified live".
"""
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from decision_bug_hunter import foundry, hosted, judges, openrouter, protocol
from decision_bug_hunter.core import Config
from decision_bug_hunter.foundry import FoundryProvider, decode_response
from decision_bug_hunter.protocol import QUESTION, ProviderError, _json
from decision_bug_hunter.protocol import encode_request as local_envelope
from decision_bug_hunter.providers import (ProviderRequest, RetryPolicy, ValidatedGateway,
                                           attempt_cost_bound, make_provider, usd)
from tests.fakes import FakeClock, Reply, ScriptedHTTPS
from tests.support import FixtureProvider, scan, source

FIXTURES = Path(__file__).parent / "fixtures" / "foundry"
API_KEY = "offline-azure-api-key-sentinel-7f3c"
TOKEN = "offline.entra.bearer-sentinel-token-2b9e"
OPENAI_KEY = "offline-openai-key-sentinel-51d0"
OPENROUTER_KEY = "offline-openrouter-key-sentinel-8a64"
HOST = "dbh-test.services.ai.azure.com"
ENDPOINT = "https://" + HOST
DEPLOYMENT = "dbh-decision-1"
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
METADATA = {"sequence": 1, "phase": "test"}
KEY_ENV = {"AZURE_API_KEY": API_KEY}
TOKEN_ENV = {"AZURE_ENTRA_TOKEN": TOKEN}
REQUEST_ID = "req-foundry-offline-0001"
ALL_ENV = {**KEY_ENV, **TOKEN_ENV, "OPENAI_API_KEY": OPENAI_KEY,
           "OPENROUTER_API_KEY": OPENROUTER_KEY}
ALL_KEYS = (API_KEY, TOKEN, OPENAI_KEY, OPENROUTER_KEY)


def fixture(name):
    return (FIXTURES / name).read_bytes().rstrip(b"\n")


def mutated(name, change):
    """A fixture body after ``change`` was applied to its parsed form."""
    data = json.loads(fixture(name))
    change(data)
    return json.dumps(data).encode()


def reply(body, status=200, *, request_id=REQUEST_ID, extra=()):
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
               *extra]
    if request_id is not None:
        headers.append(("x-request-id", request_id))
    return Reply(status=status, body=body, headers=headers, close_after=True)


def code_of(test, call, *args, **kwargs):
    with test.assertRaises(ProviderError) as caught:
        call(*args, **kwargs)
    return caught.exception.code


class Harness:
    """One scripted Foundry origin, a provider over it and a gateway."""

    def __init__(self, test, steps, *, retry_policy=None, api_key=None, environ=None,
                 **options):
        self.script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=HOST)
        exchange = self.script.exchange(HOST, foundry.PATH)
        options.setdefault("endpoint", ENDPOINT)
        options.setdefault("deployment", DEPLOYMENT)
        self.provider = FoundryProvider(api_key, environ=KEY_ENV if environ is None else environ,
                                        exchange=exchange, **options)
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.receipts = Path(tmp.name) / "receipts"
        self.gateway = ValidatedGateway(
            self.provider, self.receipts,
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

    def receipt_text(self):
        return "".join(path.read_text(encoding="utf-8") for path in self.receipts.rglob("*.json"))


class RouteTests(unittest.TestCase):
    def test_the_route_is_pinned_and_not_verified_live(self):
        self.assertEqual(foundry.PATH, "/providers/microsoft/v1/systemone")
        self.assertEqual(foundry.PROVIDER_NAME, "foundry-decisions")
        self.assertIs(foundry.VERIFIED_LIVE, False)
        self.assertIs(FoundryProvider.verified_live, False)
        self.assertIn("not yet verified live", foundry.__doc__.lower())
        provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT, deployment=DEPLOYMENT)
        route = provider.route
        self.assertEqual((route.name, route.selector, route.host, route.path, route.port),
                         ("foundry-decisions", "foundry", HOST, foundry.PATH, 443))
        self.assertEqual(route.credential_variable, "AZURE_API_KEY")
        self.assertEqual(provider.identity.name, "foundry-decisions")
        self.assertEqual(provider.identity.model, DEPLOYMENT)
        self.assertEqual(provider.endpoint_family, "services.ai.azure.com")
        # The class-level route is only the template: instances never share a host.
        self.assertNotEqual(FoundryProvider.route.host, HOST)
        other = FoundryProvider(environ=KEY_ENV, endpoint="https://other-res.openai.azure.com",
                                deployment="other")
        self.assertEqual(other.route.host, "other-res.openai.azure.com")
        self.assertEqual(provider.route.host, HOST)

    def test_the_registry_and_the_factory_agree(self):
        entry = judges.judge_route("microsoft", "foundry")
        self.assertEqual((entry.route_name, entry.model, entry.verified_live),
                         (foundry.PROVIDER_NAME, None, False))
        provider = make_provider("foundry", judge="microsoft", environ=KEY_ENV,
                                 foundry_endpoint=ENDPOINT, foundry_deployment=DEPLOYMENT)
        self.assertIsInstance(provider, FoundryProvider)
        self.assertEqual(provider.identity.model, DEPLOYMENT)
        with tempfile.TemporaryDirectory() as tmp:
            gateway = ValidatedGateway(provider, tmp)
            self.addCleanup(gateway.close)
            self.assertEqual(gateway.judge, "microsoft")
            self.assertIs(gateway.full_precision, True)
            self.assertIsNone(gateway.display_places)
            self.assertEqual(gateway.confidence_identity, "chance_normalized_p1")
            self.assertEqual(gateway.model_id, DEPLOYMENT)
            self.assertEqual(gateway.spend["price_table_date"], "2026-10-11")
        self.assertEqual(judges.judge_of_model("foundry-decisions", DEPLOYMENT), "microsoft")

    def test_the_model_spec_comes_from_the_template(self):
        spec = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT,
                               deployment=DEPLOYMENT).model_spec
        self.assertEqual(spec.id, DEPLOYMENT)
        self.assertEqual((spec.judge, spec.probability_precision), ("microsoft", "full"))
        self.assertEqual(spec.confidence_identity, "chance_normalized_p1")
        self.assertEqual((spec.price_in_per_mtok, spec.price_out_upper_per_mtok),
                         (Decimal("0.042"), Decimal(0)))
        self.assertIsNone(spec.expected_upstream)
        self.assertIsNone(spec.state_placement_max_questions)
        self.assertIsNone(spec.state_placement_max_envelope_bytes)
        self.assertEqual(foundry.TEMPLATE.judge, "microsoft")

    def test_caps_are_the_owner_decision_under_both_placements(self):
        for placement in ("instructions", "state"):
            with self.subTest(placement=placement):
                provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT,
                                           deployment=DEPLOYMENT, policy_placement=placement)
                self.assertEqual(provider.request_limits, (64, 24576))
                self.assertEqual(provider.payload_limits(b"{}"), (64, 24576))
        code = code_of(self, FoundryProvider, environ=KEY_ENV, endpoint=ENDPOINT,
                       deployment=DEPLOYMENT, policy_placement="elsewhere")
        self.assertEqual(code, "invalid_request")


class EndpointTests(unittest.TestCase):
    def test_the_three_suffixes_are_accepted(self):
        cases = [("https://res-1.services.ai.azure.com", "services.ai.azure.com"),
                 ("https://res-1.cognitiveservices.azure.com", "cognitiveservices.azure.com"),
                 ("https://res-1.openai.azure.com", "openai.azure.com"),
                 ("https://res-1.services.ai.azure.com/", "services.ai.azure.com"),
                 ("https://res-1.services.ai.azure.com:443", "services.ai.azure.com"),
                 ("https://res-1.services.ai.azure.com:443/", "services.ai.azure.com"),
                 ("https://RES-1.Services.AI.Azure.COM", "services.ai.azure.com"),
                 ("https://ab.openai.azure.com", "openai.azure.com"),
                 ("https://a" + "b" * 62 + ".openai.azure.com", "openai.azure.com")]
        for endpoint, family in cases:
            with self.subTest(endpoint=endpoint):
                host, found = foundry.validate_endpoint(endpoint)
                self.assertEqual(host, host.lower())
                self.assertTrue(host.endswith("." + family))
                self.assertEqual(found, family)
                provider = FoundryProvider(environ=KEY_ENV, endpoint=endpoint,
                                           deployment=DEPLOYMENT)
                self.assertEqual((provider.route.host, provider.endpoint_family),
                                 (host, family))

    def test_everything_else_is_endpoint_invalid(self):
        good = "res-1.services.ai.azure.com"
        cases = ["http://" + good, "https://" + good + ":8443", "https://" + good + ":80",
                 "https://" + good + ":", "https://" + good + ":abc",
                 "https://" + good + "/api/projects/x", "https://" + good + "/api/projects/x/",
                 "https://" + good + "/providers/microsoft/v1/systemone",
                 "https://" + good + "?x=1", "https://" + good + "/?x=1",
                 "https://" + good + "#frag", "https://" + good + "/#frag",
                 "https://user@" + good, "https://user:pw@" + good,
                 "https://" + good + "@evil.example.com", "https://" + good + ".evil.com",
                 "https://evil.com/" + good, "https://evil.com#@" + good,
                 "https://evil.com\\@" + good, "https://" + good + "\\",
                 "https://res-1.azure.com", "https://res-1.ai.azure.com",
                 "https://res-1.core.windows.net", "https://res-1.services.ai.azure.cn",
                 "https://res-1.services.ai.azure.us", "https://services.ai.azure.com",
                 "https://openai.azure.com", "https://.openai.azure.com",
                 "https://-a.openai.azure.com", "https://a.openai.azure.com",
                 "https://a" + "b" * 63 + ".openai.azure.com",
                 "https://res_1.openai.azure.com", "https://a.b.openai.azure.com",
                 "https://127.0.0.1", "https://127.0.0.1:443", "https://[::1]",
                 "https://[::1]:443", "https://169.254.169.254", "https://localhost",
                 "https://2130706433", "ftp://" + good, "wss://" + good, "//" + good, good,
                 "https:/" + good, "https:///" + good, "", " ", "https://", "https",
                 " https://" + good, "https://" + good + " ", "https://" + good + "\n",
                 "https://" + good + "\r\n", "https://" + good + "\t",
                 "https://res-1.services.ai.azure.com%2Eevil.com", "https://" + good + "%00",
                 "https://res" + chr(0xe9) + ".services.ai.azure.com", "https://" + chr(0xff52) + "es-1.openai.azure.com",
                 "https://" + good + "." , "https://" + good + "/x", "https://" + good + "//",
                 "https://" + good + "/;a", "https://" + "a" * 600 + ".openai.azure.com",
                 # '%' and backslash are refused outright, besides the host and path checks
                 "https://x.services.ai.azure.com/%2e",
                 "https://x.services.ai.azure.com\\@evil.example",
                 "https://x%2e.services.ai.azure.com"]
        for endpoint in cases:
            with self.subTest(endpoint=endpoint[:60]):
                self.assertEqual(code_of(self, foundry.validate_endpoint, endpoint),
                                 "endpoint_invalid")
                self.assertEqual(code_of(self, FoundryProvider, environ=KEY_ENV,
                                         endpoint=endpoint, deployment=DEPLOYMENT),
                                 "endpoint_invalid")
        for endpoint in (None, 7, b"https://" + good.encode(), ["https://" + good]):
            with self.subTest(endpoint=repr(endpoint)[:40]):
                self.assertEqual(code_of(self, foundry.validate_endpoint, endpoint),
                                 "endpoint_invalid")

    def test_a_refused_endpoint_is_never_echoed(self):
        secret = "https://user:pw-sentinel-9981@evil.example.com/api/projects/x"
        with self.assertRaises(ProviderError) as caught:
            FoundryProvider(environ=KEY_ENV, endpoint=secret, deployment=DEPLOYMENT)
        error = caught.exception
        self.assertNotIn("pw-sentinel", str(error) + repr(error) + repr(error.args))
        self.assertIsNone(error.__cause__)

    def test_the_endpoint_comes_from_the_variable_when_not_given(self):
        env = {**KEY_ENV, foundry.ENDPOINT_VARIABLE: ENDPOINT,
               foundry.DEPLOYMENT_VARIABLE: DEPLOYMENT}
        provider = FoundryProvider(environ=env)
        self.assertEqual((provider.route.host, provider.identity.model), (HOST, DEPLOYMENT))
        # An argument wins over the variable.
        provider = FoundryProvider(environ=env, endpoint="https://x2.openai.azure.com",
                                   deployment="other")
        self.assertEqual((provider.route.host, provider.identity.model),
                         ("x2.openai.azure.com", "other"))
        self.assertEqual(code_of(self, FoundryProvider, environ=KEY_ENV,
                                 deployment=DEPLOYMENT), "endpoint_invalid")
        bad = {**env, foundry.ENDPOINT_VARIABLE: "http://" + HOST}
        self.assertEqual(code_of(self, FoundryProvider, environ=bad), "endpoint_invalid")

    def test_the_host_is_never_in_a_receipt_or_the_report_fields(self):
        harness = Harness(self, [reply(fixture("response_ok.json"))])
        _, receipt = harness.evaluate()
        self.assertEqual(receipt["status"], "validated")
        saved = harness.receipt_text()
        for private in (HOST, "dbh-test", ENDPOINT):
            self.assertNotIn(private, saved)
        self.assertEqual(harness.provider.endpoint_family, "services.ai.azure.com")
        self.assertNotIn(HOST, repr(harness.provider.endpoint_family))


class DeploymentTests(unittest.TestCase):
    def test_valid_names(self):
        for name in ("a", "A1", "dbh-decision-1", "pi-decision-1", "d.e_p-1", "0abc",
                     "a" * 64, "Microsoft-Decision-1"):
            with self.subTest(name=name):
                self.assertEqual(foundry.validate_deployment(name), name)
                provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT, deployment=name)
                self.assertEqual(provider.identity.model, name)
                self.assertEqual(provider.model_spec.id, name)

    def test_invalid_names_are_invalid_request(self):
        for name in ("", "-a", ".a", "_a", "a b", "a/b", "a\\b", "a:b", "a" * 65, "dep\n",
                     "dep\n\n", " dep", "d" + chr(0xe9) + "p", "a?b", "a#b", "a%20b", None, 5, b"dep",
                     ["dep"]):
            with self.subTest(name=repr(name)[:30]):
                self.assertEqual(code_of(self, foundry.validate_deployment, name),
                                 "invalid_request")
                self.assertEqual(code_of(self, FoundryProvider, environ=KEY_ENV,
                                         endpoint=ENDPOINT, deployment=name),
                                 "invalid_request")

    def test_a_missing_deployment_is_invalid_request(self):
        self.assertEqual(code_of(self, FoundryProvider, environ=KEY_ENV, endpoint=ENDPOINT),
                         "invalid_request")
        env = {**KEY_ENV, foundry.DEPLOYMENT_VARIABLE: DEPLOYMENT}
        provider = FoundryProvider(environ=env, endpoint=ENDPOINT)
        self.assertEqual(provider.identity.model, DEPLOYMENT)


class AuthTests(unittest.TestCase):
    def evaluate_headers(self, **harness_options):
        harness = Harness(self, [reply(fixture("response_ok.json"))], **harness_options)
        outcome, receipt = harness.evaluate()
        self.assertEqual(receipt["status"], "validated", outcome)
        (request,) = harness.script.requests
        return harness, request

    def test_api_key_is_the_api_key_header_alone(self):
        harness, request = self.evaluate_headers()
        self.assertEqual(request.header("api-key"), API_KEY)
        self.assertIsNone(request.header("Authorization"))
        self.assertEqual({name.lower() for name, _ in request.headers},
                         {"host", "api-key", "content-type", "accept", "accept-encoding",
                          "content-length"})
        self.assertEqual(harness.provider.auth, "api-key")

    def test_entra_token_is_the_bearer_header_alone(self):
        harness, request = self.evaluate_headers(environ=TOKEN_ENV)
        self.assertEqual(request.header("Authorization"), "Bearer " + TOKEN)
        self.assertIsNone(request.header("api-key"))
        self.assertEqual({name.lower() for name, _ in request.headers},
                         {"host", "authorization", "content-type", "accept", "accept-encoding",
                          "content-length"})
        self.assertEqual(harness.provider.auth, "entra-token")
        self.assertEqual(harness.provider.route.credential_variable, "AZURE_ENTRA_TOKEN")

    def test_the_mode_can_be_chosen_explicitly(self):
        both = {**KEY_ENV, **TOKEN_ENV}
        _, request = self.evaluate_headers(environ=both, auth="api-key")
        self.assertEqual(request.header("api-key"), API_KEY)
        self.assertIsNone(request.header("Authorization"))
        _, request = self.evaluate_headers(environ=both, auth="entra-token")
        self.assertEqual(request.header("Authorization"), "Bearer " + TOKEN)
        self.assertIsNone(request.header("api-key"))

    def test_both_variables_without_a_mode_is_ambiguous(self):
        code = code_of(self, FoundryProvider, environ={**KEY_ENV, **TOKEN_ENV},
                       endpoint=ENDPOINT, deployment=DEPLOYMENT)
        self.assertEqual(code, "invalid_request")

    def test_an_explicit_key_is_an_api_key_unless_a_mode_is_given(self):
        harness, request = self.evaluate_headers(api_key=API_KEY, environ={})
        self.assertEqual(request.header("api-key"), API_KEY)
        _, request = self.evaluate_headers(api_key=TOKEN, environ={}, auth="entra-token")
        self.assertEqual(request.header("Authorization"), "Bearer " + TOKEN)
        # The explicit key decides, whatever the environment holds.
        for name, environ in (("token only", TOKEN_ENV), ("both", {**KEY_ENV, **TOKEN_ENV})):
            with self.subTest(environment=name):
                _, request = self.evaluate_headers(api_key=API_KEY, environ=environ)
                self.assertEqual(request.header("api-key"), API_KEY)
                self.assertIsNone(request.header("Authorization"))

    def test_an_unknown_mode_is_invalid_request(self):
        for auth in ("key", "bearer", "", "API-KEY", 1, True, ["api-key"]):
            with self.subTest(auth=auth):
                self.assertEqual(code_of(self, FoundryProvider, environ=KEY_ENV,
                                         endpoint=ENDPOINT, deployment=DEPLOYMENT, auth=auth),
                                 "invalid_request")

    def test_a_mode_without_its_variable_is_unavailable_and_never_connects(self):
        cases = [({}, None), ({"AZURE_API_KEY": ""}, None), (TOKEN_ENV, "api-key"),
                 (KEY_ENV, "entra-token"), ({"OPENAI_API_KEY": OPENAI_KEY,
                                             "OPENROUTER_API_KEY": OPENROUTER_KEY}, None),
                 ({"AZURE_API_KEY": "has space"}, None)]
        for environ, auth in cases:
            with self.subTest(environ=sorted(environ), auth=auth):
                script = ScriptedHTTPS([], clock=FakeClock(), host=HOST)
                provider = FoundryProvider(environ=environ, endpoint=ENDPOINT,
                                           deployment=DEPLOYMENT, auth=auth,
                                           exchange=script.exchange(HOST, foundry.PATH))
                request = ProviderRequest(local_envelope(STATE, QUESTIONS), 1.0)
                for operation in (provider.require_available,
                                  lambda: provider.decide(request)):
                    self.assertEqual(code_of(self, operation), "provider_unavailable")
                with tempfile.TemporaryDirectory() as tmp:
                    gateway = ValidatedGateway(provider, tmp)
                    self.addCleanup(gateway.close)
                    self.assertEqual(code_of(self, gateway.require_available),
                                     "provider_unavailable")
                self.assertEqual((script.connects, script.requests), ([], []))

    def test_no_key_appears_on_the_wire_in_receipts_or_the_report(self):
        env = {**KEY_ENV, "AZURE_ENTRA_TOKEN": TOKEN, "OPENAI_API_KEY": OPENAI_KEY,
               "OPENROUTER_API_KEY": OPENROUTER_KEY}
        for auth, secret in (("api-key", API_KEY), ("entra-token", TOKEN)):
            with self.subTest(auth=auth):
                harness = Harness(self, [reply(fixture("response_ok.json"))], environ=env,
                                  auth=auth)
                _, receipt = harness.evaluate()
                (request,) = harness.script.requests
                for key in (API_KEY, TOKEN, OPENAI_KEY, OPENROUTER_KEY):
                    self.assertNotIn(key.encode(), request.body)
                    self.assertNotIn(key, harness.receipt_text())
                    self.assertNotIn(key, json.dumps(receipt))
                self.assertIn(secret, [value for _, value in request.headers] +
                              [value.removeprefix("Bearer ") for _, value in request.headers])

    def test_no_key_appears_in_a_report(self):
        oracle = FixtureProvider([(5, 5)])

        class Responder(ScriptedHTTPS):
            """Answers each request with the fixture judge's answers, Foundry style."""

            def _next_step(self, kind):
                request = json.loads(self.requests[-1].body)
                raw = json.loads(oracle.raw(request["state"], request["questions"]))
                body = json.dumps({"answers": raw["answers"], "model": "microsoft-decision-1",
                                   "usage": {"input_tokens": 100, "output_tokens": 0}})
                return reply(body.encode())

        script = Responder([], clock=FakeClock(), host=HOST)
        env = {**KEY_ENV, "AZURE_ENTRA_TOKEN": TOKEN, "OPENAI_API_KEY": OPENAI_KEY,
               "OPENROUTER_API_KEY": OPENROUTER_KEY}
        provider = FoundryProvider(environ=env, endpoint=ENDPOINT, deployment=DEPLOYMENT,
                                   auth="api-key", exchange=script.exchange(HOST, foundry.PATH))
        with tempfile.TemporaryDirectory() as tmp:
            gateway = ValidatedGateway(provider, Path(tmp) / "receipts",
                                       retry_policy=RetryPolicy.none())
            self.addCleanup(gateway.close)
            report = scan(source(24), gateway, Config(whole_file=False))
            receipts = "".join(path.read_text(encoding="utf-8")
                               for path in Path(tmp).rglob("*.json"))
        self.assertGreater(len(script.requests), 3)
        self.assertEqual(report["judge"], "microsoft")
        self.assertEqual(report["model"], DEPLOYMENT)
        self.assertEqual(report["provider"], "foundry-decisions")
        text = json.dumps(report) + receipts
        for key in (API_KEY, TOKEN, OPENAI_KEY, OPENROUTER_KEY, HOST):
            self.assertNotIn(key, text)
        for request in script.requests:
            for key in (API_KEY, TOKEN, OPENAI_KEY, OPENROUTER_KEY):
                self.assertNotIn(key.encode(), request.body)

    def test_every_configured_key_is_refused_in_outgoing_data(self):
        for auth in ("api-key", "entra-token"):
            for key in ALL_KEYS:
                with self.subTest(auth=auth, key=key[:12]):
                    harness = Harness(self, [], environ=ALL_ENV, auth=auth)
                    state = {**STATE, "note": "see " + key + " here"}
                    outcome, _ = harness.evaluate(state=state)
                    self.assertIsInstance(outcome, ProviderError)
                    self.assertEqual(outcome.code, "sensitive_input")
                    self.assertEqual((harness.script.connects, harness.script.requests),
                                     ([], []))
                    self.assertEqual(code_of(self, harness.provider.check_sensitive,
                                             {"x": key}), "sensitive_input")
            provider = FoundryProvider(environ=ALL_ENV, endpoint=ENDPOINT,
                                       deployment=DEPLOYMENT, auth=auth)
            provider.check_sensitive({"x": "short"})

    def test_a_key_in_the_questions_is_refused_after_encoding(self):
        harness = Harness(self, [])
        questions = {**QUESTIONS, "where": {**CHOICE, "instructions": "uses " + API_KEY}}
        outcome, _ = harness.evaluate(questions=questions)
        self.assertEqual(outcome.code, "sensitive_input")
        self.assertEqual(harness.script.requests, [])

    def test_the_azure_credentials_are_refused_on_the_other_routes(self):
        # The reverse direction: a Foundry key never leaves through OpenAI or OpenRouter.
        env = {**KEY_ENV, **TOKEN_ENV}
        for route in ("openai", "openrouter"):
            provider = make_provider(route, api_key=OPENAI_KEY, environ=env)
            for key in (API_KEY, TOKEN):
                with self.subTest(route=route, key=key[:12]):
                    self.assertEqual(code_of(self, provider.check_sensitive, {"x": key}),
                                     "sensitive_input")


class RequestTests(unittest.TestCase):
    def test_the_wire_is_exactly_the_splice(self):
        harness = Harness(self, [reply(fixture("response_ok.json"))])
        harness.evaluate()
        (request,) = harness.script.requests
        self.assertEqual(request.body,
                         b'{"model":"' + DEPLOYMENT.encode() + b'","state":' + _json(STATE)
                         + b',"questions":' + _json(QUESTIONS) + b"}")
        self.assertEqual((request.method, request.target), ("POST", foundry.PATH))
        self.assertEqual(request.header("Host"), HOST)
        self.assertEqual(harness.script.connects[0][0], (HOST, 443))
        self.assertEqual(harness.script.server_hostnames, [HOST])
        body = json.loads(request.body)
        self.assertEqual(list(body), ["model", "state", "questions"])
        for absent in (b"provider", b"routing", b"zdr", b"session_id", b'"user"', b"score",
                       b"api-version", b"dbh-judge-v1", b"contract"):
            self.assertNotIn(absent, request.body)
        self.assertEqual(request.header("Content-Type"), "application/json")
        self.assertEqual(request.header("Accept"), "application/json")
        self.assertEqual(request.header("Accept-Encoding"), "identity")

    def test_encode_matches_the_openrouter_splice_without_routing(self):
        local = local_envelope(STATE, QUESTIONS)
        provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT, deployment=DEPLOYMENT)
        wire, questions = provider.encode(local)
        expected, expected_questions = openrouter.encode_request(
            local, model=DEPLOYMENT, routing="account-default")
        self.assertEqual((wire, questions), (expected, expected_questions))
        deny, _ = openrouter.encode_request(local, model=DEPLOYMENT)
        self.assertEqual(deny, wire[:-1] + openrouter.routing_fragment() + b"}")
        # The state and question bytes are the local envelope's own bytes.
        self.assertIn(local[len(b'{"contract":"dbh-judge-v1","state":'):-1], wire)
        for payload in (b"{}", local[:-1] + b',"extra":1}', "text", local + b" "):
            with self.subTest(payload=payload[:20]):
                self.assertEqual(code_of(self, provider.encode, payload), "invalid_request")

    def test_the_local_request_hash_equals_the_openrouter_one(self):
        harness = Harness(self, [reply(fixture("response_ok.json"))])
        _, receipt = harness.evaluate()
        script = ScriptedHTTPS(
            [Reply(status=200, close_after=True, headers=[("Content-Type", "application/json")],
                   body=json.dumps({
                       "answers": json.loads(fixture("response_ok.json"))["answers"],
                       "id": "gen-offline-0001", "model": "microsoft/microsoft-decision-1-20261009",
                       "provider": "Azure",
                       "usage": {"input_tokens": 96, "output_tokens": 0, "cost": 4e-06}}).encode())],
            clock=FakeClock(), host=openrouter.HOST)
        router = make_provider("openrouter", model="microsoft/microsoft-decision-1",
                               judge="microsoft", api_key=OPENROUTER_KEY, environ={},
                               exchange=script.exchange(openrouter.HOST, openrouter.PATH))
        with tempfile.TemporaryDirectory() as tmp:
            gateway = ValidatedGateway(router, tmp, retry_policy=RetryPolicy.none())
            self.addCleanup(gateway.close)
            gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
            other = json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))
        local_hash = hashlib.sha256(local_envelope(STATE, QUESTIONS)).hexdigest()
        self.assertEqual(receipt["request_sha256"], local_hash)
        self.assertEqual(other["request_sha256"], local_hash)
        (request,) = harness.script.requests
        self.assertEqual(receipt["wire_sha256"], hashlib.sha256(request.body).hexdigest())
        self.assertNotEqual(receipt["wire_sha256"], other["wire_sha256"])

    def test_the_wire_size_matches_what_is_sent(self):
        harness = Harness(self, [reply(fixture("response_ok.json"))])
        local = local_envelope(STATE, QUESTIONS)
        size = harness.provider.wire_size(local)
        harness.evaluate()
        self.assertEqual(size, len(harness.script.requests[0].body))
        self.assertIsNone(harness.provider.wire_size("text"))

    def test_the_limits_are_64_questions_and_24_kib(self):
        tiny = {"type": "noul", "instructions": "q",
                "criteria": {"true": "t", "false": "f"}}
        for placement in ("instructions", "state"):
            with self.subTest(placement=placement):
                provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT,
                                           deployment=DEPLOYMENT, policy_placement=placement)
                max_questions, max_bytes = provider.request_limits
                self.assertEqual((max_questions, max_bytes), (64, 24576))
                exactly = {f"q{i}": tiny for i in range(64)}
                wire, questions = provider.encode(local_envelope(STATE, exactly), max_questions)
                self.assertEqual(len(questions), 64)
                # Past the question cap the request is refused locally, unsent.
                over = _envelope_of(STATE, {f"q{i}": tiny for i in range(65)})
                self.assertLessEqual(len(over), max_bytes)
                # The shared question validator refuses a count over the cap as
                # invalid_request, like the OpenAI and OpenRouter routes;
                # request_too_large is the byte cap's code (the tests below).
                with self.assertRaises(ProviderError) as caught:
                    provider.decide(ProviderRequest(over, 5.0))
                self.assertEqual(caught.exception.code, "invalid_request")
                self.assertEqual(caught.exception.classification.submission, "not_sent")
        harness = Harness(self, [])
        outcome, _ = harness.evaluate(questions={f"q{i}": tiny for i in range(65)})
        self.assertIsInstance(outcome, ProviderError)
        self.assertEqual(outcome.code, "invalid_request")
        self.assertEqual((harness.script.connects, harness.script.requests), ([], []))

    def test_an_envelope_over_24_kib_is_request_too_large(self):
        big = b'{"contract":"dbh-judge-v1","state":{"pad":"' + b"a" * 24576 + b'"},"questions":{}}'
        self.assertGreater(len(big), 24576)
        for placement in ("instructions", "state"):
            with self.subTest(placement=placement):
                provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT,
                                           deployment=DEPLOYMENT, policy_placement=placement)
                with self.assertRaises(ProviderError) as caught:
                    provider.decide(ProviderRequest(big, 5.0))
                self.assertEqual(caught.exception.code, "request_too_large")
                self.assertEqual(caught.exception.classification.submission, "not_sent")

    def test_the_envelope_cap_is_exactly_24576_bytes(self):
        for placement in ("instructions", "state"):
            with self.subTest(placement=placement, size=24576):
                payload = _envelope_of_size(24576)
                self.assertEqual(len(payload), 24576)
                harness = Harness(self, [reply(fixture("response_ok.json"))],
                                  policy_placement=placement)
                response = harness.provider.decide(ProviderRequest(payload, 5.0))
                self.assertIsNone(response.error)
                self.assertEqual(len(harness.script.requests), 1)
            with self.subTest(placement=placement, size=24577):
                payload = _envelope_of_size(24577)
                self.assertEqual(len(payload), 24577)
                harness = Harness(self, [], policy_placement=placement)
                with self.assertRaises(ProviderError) as caught:
                    harness.provider.decide(ProviderRequest(payload, 5.0))
                self.assertEqual(caught.exception.code, "request_too_large")
                self.assertEqual(caught.exception.classification.submission, "not_sent")
                self.assertEqual((harness.script.connects, harness.script.requests), ([], []))


def _envelope_of_size(size):
    """A valid local envelope of exactly ``size`` bytes, padded in the state and
    in two question texts (each text is capped at 12,000 characters)."""
    slots = [0, 0, 0]
    caps = (12000, 8000, 8000)

    def build():
        state = {**STATE, "pad": "a" * slots[0]}
        screen = {**QUESTION, "instructions": QUESTION["instructions"] + "a" * slots[1]}
        where = {**CHOICE, "instructions": CHOICE["instructions"] + "a" * slots[2]}
        return _envelope_of(state, {"screen": screen, "where": where})

    remaining = size - len(build())
    assert remaining >= 0
    for index, cap in enumerate(caps):
        slots[index] = min(cap, remaining)
        remaining -= slots[index]
    assert remaining == 0
    return build()


def _envelope_of(state, questions):
    """A local envelope that skips the local question cap, to reach the adapter's own."""
    return (b'{"contract":"dbh-judge-v1","state":' + _json(state) + b',"questions":'
            + _json(questions) + b"}")


class DecodeTests(unittest.TestCase):
    def decode(self, body, questions=QUESTIONS, credentials=(API_KEY,)):
        return decode_response(body, questions, credentials)

    def test_a_full_precision_answer_validates_through_the_gateway(self):
        harness = Harness(self, [reply(fixture("response_ok.json"))])
        answers, receipt = harness.evaluate()
        self.assertEqual(answers["screen"]["noul"], Decimal("0.8123456789012345"))
        where = answers["where"]
        self.assertEqual(where["choice"], "L1-1")
        self.assertEqual(where["probabilities"], {"L1-1": Decimal("0.7234519123456789"),
                                                  "none": Decimal("0.2765480876543211")})
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual(receipt["route"], "foundry-decisions")
        self.assertEqual((receipt["model_requested"], receipt["model_returned"]),
                         (DEPLOYMENT, "microsoft-decision-1"))
        self.assertEqual(receipt["judge"], "microsoft")
        self.assertEqual(receipt["request_id"], REQUEST_ID)
        self.assertEqual(receipt["usage"], {"input_tokens": 96, "output_tokens": 0})
        self.assertIsNone(receipt["upstream_provider"])

    def test_noul_and_choice_answers_decode_to_the_documented_shapes(self):
        response = self.decode(fixture("response_ok.json"))
        self.assertIsNone(response.error)
        self.assertEqual(list(response.answers), ["screen", "where"])
        self.assertEqual(response.answers["screen"],
                         {"type": "noul", "noul": Decimal("0.8123456789012345")})
        self.assertEqual(response.answers["where"]["type"], "choice")
        self.assertEqual(response.order_mismatch, 0)
        self.assertIsNone(response.cost_usd)
        self.assertEqual(response.usage, {"input_tokens": 96, "output_tokens": 0})
        self.assertEqual(response.provenance, {"model_returned": "microsoft-decision-1"})

    def test_the_echo_is_the_underlying_model(self):
        for model in ("microsoft-decision-1", "Microsoft-Decision-1",
                      "microsoft-decision-1-20261009", "Microsoft-Decision-1-20261009"):
            with self.subTest(model=model):
                body = mutated("response_ok.json", lambda d, m=model: d.update(model=m))
                response = self.decode(body)
                self.assertIsNone(response.error)
                self.assertEqual(response.provenance["model_returned"], model)
        for model in (DEPLOYMENT, "microsoft/microsoft-decision-1", "microsoft-decision-2",
                      "microsoft-decision-1-mini", "microsoft-decision-1-2026-10-09",
                      "microsoft-decision-1-2026100", "MICROSOFT-DECISION-1", "", 7, None):
            with self.subTest(model=model):
                body = mutated("response_ok.json", lambda d, m=model: d.update(model=m))
                response = self.decode(body)
                self.assertEqual(response.error, "response_model")
                self.assertEqual(response.answers, {})
                self.assertEqual(response.usage, {"input_tokens": 96, "output_tokens": 0})
        body = mutated("response_ok.json", lambda d: d.pop("model"))
        self.assertEqual(self.decode(body).error, "response_model")

    def test_a_wrong_echo_twice_stops_the_run_as_a_contract_mismatch(self):
        body = mutated("response_ok.json", lambda d: d.update(model="other-model"))
        harness = Harness(self, [reply(body), reply(body)])
        for _ in range(2):
            outcome, receipt = harness.evaluate()
            self.assertEqual(outcome.code, "response_model")
            self.assertEqual(receipt["status"], "failed")
        self.assertEqual(harness.gateway.breaker.stop_reason, "contract_mismatch")
        self.assertEqual(code_of(self, harness.gateway.require_available), "provider_stopped")

    def test_refusals_are_answer_scoped_once_and_withhold_the_batch_twice(self):
        one = mutated("response_ok.json",
                      lambda d: d["answers"].update(where={"type": "refusal"}))
        response = self.decode(one)
        self.assertIsNone(response.error)
        self.assertEqual(response.scoped, {"where": "question_refused"})
        self.assertEqual(list(response.answers), ["screen"])
        harness = Harness(self, [reply(one)])
        outcome, receipt = harness.evaluate()
        self.assertEqual(set(outcome), {"screen"})
        self.assertEqual(receipt["status"], "validated_partial")
        self.assertEqual(receipt["scoped"], {"where": "question_refused"})
        two = mutated("response_ok.json", lambda d: d.update(
            answers={"screen": {"type": "refusal"}, "where": {"type": "refusal"}}))
        response = self.decode(two)
        self.assertEqual(response.error, "response_refused")
        self.assertEqual(response.answers, {})
        outcome, receipt = Harness(self, [reply(two)]).evaluate()
        self.assertEqual(outcome.code, "response_refused")
        self.assertTrue(receipt["submission_possible"])

    def test_a_missing_vector_is_response_vector_missing(self):
        for missing in ("probabilities", "confidence"):
            with self.subTest(missing=missing):
                body = mutated("response_ok.json",
                               lambda d, m=missing: d["answers"]["where"].pop(m))
                response = self.decode(body)
                self.assertIsNone(response.error)
                self.assertEqual(response.scoped, {"where": "response_vector_missing"})
                outcome, receipt = Harness(self, [reply(body)]).evaluate()
                self.assertEqual(set(outcome), {"screen"})
                self.assertEqual(receipt["scoped"], {"where": "response_vector_missing"})

    def test_answer_schema_defects_are_batch_level(self):
        wire = json.loads(fixture("response_ok.json"))
        cases = [{"screen": wire["answers"]["screen"]},
                 {**wire["answers"], "extra": wire["answers"]["screen"]},
                 [wire["answers"]["screen"], wire["answers"]["where"]], None,
                 {**wire["answers"], "screen": {"type": "score", "score": 1}},
                 {**wire["answers"], "where": {**wire["answers"]["where"], "note": "x"}},
                 {**wire["answers"], "screen": {"type": "noul", "noul": 0.5, "extra": 1}}]
        for answers in cases:
            with self.subTest(answers=str(answers)[:40]):
                body = json.dumps({**wire, "answers": answers}).encode()
                self.assertEqual(self.decode(body).error, "response_schema")
        reordered = json.dumps({**wire, "answers": {"where": wire["answers"]["where"],
                                                    "screen": wire["answers"]["screen"]}})
        response = self.decode(reordered.encode())
        self.assertIsNone(response.error)
        self.assertEqual(response.order_mismatch, 1)

    def test_the_response_size_cap_is_exactly_max_response_bytes(self):
        base = fixture("response_ok.json")
        exact = base + b" " * (protocol.MAX_RESPONSE_BYTES - len(base))
        self.assertEqual(len(exact), protocol.MAX_RESPONSE_BYTES)
        self.assertIsNone(decode_response(exact, QUESTIONS).error)
        self.assertEqual(code_of(self, decode_response, exact + b" ", QUESTIONS),
                         "response_too_large")

    def test_usage_is_read_tolerantly(self):
        cases = [({"input_tokens": 96, "output_tokens": 0}, (96, 0)),
                 ({"input_tokens": 96, "output_tokens": 3, "total_tokens": 99}, (96, 3)),
                 ({"prompt_tokens": 120, "completion_tokens": 0}, (120, 0)),
                 ({"prompt_tokens": 120, "completion_tokens": 2, "total_tokens": 122,
                   "prompt_tokens_details": {"cached_tokens": 0}}, (120, 2))]
        for usage, counters in cases:
            with self.subTest(usage=usage):
                body = mutated("response_ok.json", lambda d, u=usage: d.update(usage=u))
                response = self.decode(body)
                self.assertEqual(response.usage, {"input_tokens": counters[0],
                                                  "output_tokens": counters[1]})
                self.assertNotIn("usage_shape", response.provenance)
        # With both counter pairs present the input/output pair wins and
        # total_tokens is never read; the cost estimate follows the winner.
        both = {"input_tokens": 5, "output_tokens": 6, "prompt_tokens": 9,
                "completion_tokens": 10, "total_tokens": 99}
        body = mutated("response_ok.json", lambda d: d.update(usage=both))
        self.assertEqual(self.decode(body).usage, {"input_tokens": 5, "output_tokens": 6})
        _, receipt = Harness(self, [reply(body)]).evaluate()
        self.assertEqual(receipt["usage"], {"input_tokens": 5, "output_tokens": 6})
        self.assertEqual(Decimal(receipt["cost_usd"]), Decimal("0.00000021"))
        # A malformed first pair falls through to a well-formed second one.
        first_bad = {"input_tokens": -1, "output_tokens": 6, "prompt_tokens": 9,
                     "completion_tokens": 10}
        body = mutated("response_ok.json", lambda d: d.update(usage=first_bad))
        self.assertEqual(self.decode(body).usage, {"input_tokens": 9, "output_tokens": 10})
        body = fixture("response_dated_prompt_completion.json")
        self.assertEqual(self.decode(body).usage, {"input_tokens": 120, "output_tokens": 0})
        outcome, receipt = Harness(self, [reply(body)]).evaluate()
        self.assertEqual(receipt["usage"], {"input_tokens": 120, "output_tokens": 0})
        self.assertEqual(receipt["model_returned"], "Microsoft-Decision-1-20261009")

    def test_an_unrecognized_usage_is_unknown_and_flagged(self):
        for usage in ({"tokens": 96}, {}, {"input_tokens": 96}, {"prompt_tokens": 3},
                      {"input_tokens": 1, "completion_tokens": 2},
                      {"input_tokens": -1, "output_tokens": 0},
                      {"input_tokens": 1.5, "output_tokens": 0},
                      {"input_tokens": "96", "output_tokens": 0},
                      {"input_tokens": True, "output_tokens": 0},
                      {"input_tokens": 2 ** 63, "output_tokens": 0},
                      {"input_tokens": None, "output_tokens": None}, [], "96", 96, False):
            with self.subTest(usage=usage):
                body = mutated("response_ok.json", lambda d, u=usage: d.update(usage=u))
                response = self.decode(body)
                self.assertIsNone(response.error)
                self.assertIsNone(response.usage)
                self.assertEqual(response.provenance["usage_shape"], "unrecognized")
                self.assertEqual(list(response.answers), ["screen", "where"])
        absent = self.decode(mutated("response_ok.json", lambda d: d.pop("usage")))
        self.assertIsNone(absent.usage)
        self.assertNotIn("usage_shape", absent.provenance)

    def test_unknown_usage_costs_the_bound_and_records_the_shape(self):
        harness = Harness(self, [reply(fixture("response_unknown_usage.json"))])
        outcome, receipt = harness.evaluate()
        self.assertEqual(receipt["status"], "validated")
        self.assertIsNone(receipt["usage"])
        self.assertEqual(receipt["cost_source"], "none")
        (request,) = harness.script.requests
        # The bound prices the larger of the wire body and the local envelope.
        size = max(len(request.body), len(local_envelope(STATE, QUESTIONS)))
        bound = attempt_cost_bound(size, len(QUESTIONS), Decimal("0.042"), Decimal(0))
        self.assertEqual(receipt["cost_bound_usd"], usd(bound))
        self.assertGreater(Decimal(receipt["cost_bound_usd"]), 0)
        self.assertEqual(receipt["provider_error"], {"usage_shape": "unrecognized"})
        spend = harness.gateway.spend
        self.assertEqual(spend["attempts"]["unknown_bounded"], 1)
        self.assertEqual(spend["unknown_usage_upper_bound_usd"], usd(bound))

    def test_a_cost_in_the_body_is_not_read(self):
        body = mutated("response_ok.json", lambda d: d["usage"].update(cost=0.5))
        response = self.decode(body)
        self.assertIsNone(response.cost_usd)
        self.assertNotIn("cost_error", response.provenance)
        _, receipt = Harness(self, [reply(body)]).evaluate()
        self.assertEqual(receipt["cost_source"], "list_price_estimate")

    def test_the_cost_is_the_list_price_estimate(self):
        for tokens, expected in ((1_000_000, "0.042"), (96, "0.000004032"), (0, "0")):
            with self.subTest(tokens=tokens):
                body = mutated("response_ok.json", lambda d, t=tokens: d["usage"].update(
                    input_tokens=t))
                harness = Harness(self, [reply(body)])
                _, receipt = harness.evaluate()
                self.assertEqual(receipt["cost_source"], "list_price_estimate")
                self.assertEqual(Decimal(receipt["cost_usd"]), Decimal(expected))
                self.assertEqual(Decimal(harness.gateway.spend["estimated_usd"]),
                                 Decimal(expected))
        body = mutated("response_ok.json", lambda d: d["usage"].update(
            input_tokens=1_000_000, output_tokens=500))
        _, receipt = Harness(self, [reply(body)]).evaluate()
        self.assertEqual(Decimal(receipt["cost_usd"]), Decimal("0.042"))

    def test_an_error_in_a_200_body(self):
        body = fixture("response_error_in_body.json")
        response = self.decode(body)
        self.assertEqual(response.error, "provider_error_in_body")
        self.assertEqual(response.usage, {"input_tokens": 40, "output_tokens": 0})
        self.assertEqual(response.provenance["error_code"], "InternalServerError")
        self.assertEqual(response.provenance["error_type"], "server_error")
        outcome, receipt = Harness(self, [reply(body)]).evaluate()
        self.assertEqual(outcome.code, "provider_error_in_body")
        self.assertTrue(receipt["submission_possible"])
        self.assertEqual(receipt["usage"], {"input_tokens": 40, "output_tokens": 0})
        self.assertEqual(receipt["provider_error"]["error_code"], "InternalServerError")
        self.assertNotIn("private-error-message", json.dumps(receipt))
        # Neither answers nor an error is a schema defect with the usage kept.
        neither = self.decode(b'{"model":"microsoft-decision-1","usage":'
                              b'{"input_tokens":10,"output_tokens":0}}')
        self.assertEqual(neither.error, "response_schema")
        self.assertEqual(neither.usage, {"input_tokens": 10, "output_tokens": 0})
        self.assertEqual(self.decode(b'{"model":"x"}').error, "response_schema")
        self.assertEqual(self.decode(b'{"error":"text","model":"x"}').error,
                         "provider_error_in_body")

    def test_sensitive_and_malformed_bodies(self):
        leaked = mutated("response_ok.json", lambda d: d.update(id=API_KEY))
        escaped = mutated("response_ok.json", lambda d: d.update(
            id="".join("\\u%04x" % ord(c) for c in API_KEY)))
        for body, code in ((leaked, "response_sensitive"),
                           (b"[]", "response_schema"),
                           (b'{"answers":', "response_invalid_json"),
                           (b'{"a":1,"a":2}', "response_invalid_json"),
                           (b'{"answers":NaN}', "response_invalid_json"),
                           (b" " * (protocol.MAX_RESPONSE_BYTES + 1), "response_too_large")):
            with self.subTest(code=code, body=body[:20]):
                self.assertEqual(code_of(self, self.decode, body), code)
        # An escaped key is found by the decoded walk.
        escaped = escaped.replace(b"\\\\", b"\\")
        self.assertEqual(code_of(self, self.decode, escaped), "response_sensitive")
        for auth in ("api-key", "entra-token"):
            for key in ALL_KEYS:
                with self.subTest(auth=auth, key=key[:12]):
                    harness = Harness(self, [reply(mutated("response_ok.json",
                                                           lambda d, k=key: d.update(id=k)))],
                                      environ=ALL_ENV, auth=auth)
                    outcome, receipt = harness.evaluate()
                    self.assertEqual(outcome.code, "response_sensitive")
                    self.assertNotIn(key, json.dumps(receipt))
                    self.assertNotIn(key, harness.receipt_text())

    def test_an_unrelated_body_never_reaches_the_receipt(self):
        body = mutated("response_ok.json", lambda d: d.update(
            reasoning="private-rationale", provider="private-upstream", id="private-id"))
        harness = Harness(self, [reply(body)])
        _, receipt = harness.evaluate()
        self.assertEqual(receipt["status"], "validated")
        self.assertNotIn("private", json.dumps(receipt))
        self.assertNotIn("private", harness.receipt_text())

    def test_identical_requests_may_differ_slightly(self):
        wobble = mutated("response_ok.json", lambda d: d["answers"].update(where={
            "type": "choice", "choice": "L1-1", "confidence": 0.4469038247913578,
            "probabilities": {"L1-1": 0.7234519123956789, "none": 0.2765480876043211}}))
        harness = Harness(self, [reply(fixture("response_ok.json")), reply(wobble)])
        first, _ = harness.evaluate()
        second, _ = harness.evaluate()
        self.assertNotEqual(first["where"]["probabilities"], second["where"]["probabilities"])

    def test_a_float32_like_vector_is_a_distribution_defect(self):
        body = mutated("response_ok.json", lambda d: d["answers"].update(where={
            "type": "choice", "choice": "L1-1", "confidence": 0.4999999,
            "probabilities": {"L1-1": 0.7499999, "none": 0.25}}))
        harness = Harness(self, [reply(body)])
        got, _ = harness.evaluate()
        self.assertEqual(set(got), {"screen"})
        self.assertEqual(harness.gateway.last_defects, {"where": "response_distribution"})


class StatusTests(unittest.TestCase):
    def test_the_status_table(self):
        # status, code, submission class, blocks the run, retried
        table = [(300, "http_redirect", "terminal", True, False),
                 (301, "http_redirect", "terminal", True, False),
                 (307, "http_redirect", "terminal", True, False),
                 (399, "http_redirect", "terminal", True, False),
                 (400, "http_rejected", "terminal", False, False),
                 (401, "http_unauthorized", "terminal", True, False),
                 (402, "http_rejected", "terminal", False, False),
                 (403, "http_forbidden", "terminal", True, False),
                 (404, "route_unavailable", "terminal", True, False),
                 (408, "http_request_timeout", "not_sent", False, True),
                 (409, "http_rejected", "terminal", False, False),
                 (413, "request_too_large", "terminal", False, False),
                 (422, "http_rejected", "terminal", False, False),
                 (429, "http_rate_limited", "rejected_unprocessed", False, True),
                 (500, "http_server_error", "possible", False, False),
                 (503, "http_server_error", "possible", False, False),
                 (529, "http_server_error", "possible", False, False)]
        for status, code, submission, blocks, retried in table:
            with self.subTest(status=status):
                body = json.dumps({"error": {"code": "SomeCode", "type": "some_type",
                                             "message": "private-error-message"}}).encode()
                steps = [reply(body, status)] * 4
                harness = Harness(self, steps, retry_policy=RetryPolicy(
                    not_sent=3, rejected=3, possible=0, not_sent_cap=0.0, rejected_cap=0.0,
                    retry_after_cap=0.0) if retried else RetryPolicy.none())
                outcome, receipt = harness.evaluate()
                self.assertEqual(outcome.code, code)
                self.assertIsNone(outcome.__context__)
                self.assertEqual(receipt["provider_error"]["error_body"], "ok")
                self.assertEqual(receipt["provider_error"]["error_code"], "SomeCode")
                self.assertEqual(receipt["provider_error"]["error_type"], "some_type")
                self.assertEqual(receipt["request_id"], REQUEST_ID)
                self.assertEqual(receipt["submission"], submission)
                self.assertIs(receipt["submission_possible"],
                              submission not in ("not_sent", "rejected_unprocessed"))
                self.assertNotIn("private-error-message", harness.receipt_text())
                if blocks:
                    self.assertEqual(code_of(self, harness.gateway.require_available), code)
                else:
                    harness.gateway.require_available()
                attempts = len(harness.script.requests)
                self.assertEqual(attempts > 1, retried, (status, attempts))

    def test_422_keeps_the_error_code(self):
        harness = Harness(self, [reply(fixture("error_422.json"), 422)])
        outcome, receipt = harness.evaluate()
        self.assertEqual(outcome.code, "http_rejected")
        self.assertEqual(receipt["provider_error"], {
            "error_body": "ok", "error_code": "unsupported_deployment",
            "error_type": "invalid_request_error"})
        self.assertNotIn("private-error-message", json.dumps(receipt))
        # Two rejections of the request shape stop the run as a contract mismatch.
        harness = Harness(self, [reply(fixture("error_422.json"), 422)] * 2)
        harness.evaluate()
        harness.evaluate()
        self.assertEqual(harness.gateway.breaker.stop_reason, "contract_mismatch")

    def test_429_honors_retry_after_capped_at_sixty_seconds(self):
        harness = Harness(self, [reply(fixture("error_429.json"), 429,
                                       extra=[("Retry-After", "7")])])
        outcome, receipt = harness.evaluate()
        self.assertEqual(outcome.code, "http_rate_limited")
        self.assertEqual(receipt["retry_after_seconds"], 7.0)
        self.assertEqual(receipt["provider_error"]["error_code"], "429")
        self.assertEqual(receipt["provider_error"]["error_type"], "rate_limit_exceeded")
        _, receipt = Harness(self, [reply(fixture("error_429.json"), 429,
                                          extra=[("Retry-After", "3600")])]).evaluate()
        self.assertEqual(receipt["retry_after_seconds"], 60.0)
        _, receipt = Harness(self, [reply(fixture("error_429.json"), 429,
                                          extra=[("Retry-After", "soon")])]).evaluate()
        self.assertNotIn("retry_after_seconds", receipt)
        _, receipt = Harness(self, [reply(b'{"error":{"code":"x"}}', 401,
                                          extra=[("Retry-After", "7")])]).evaluate()
        self.assertNotIn("retry_after_seconds", receipt)

    def test_429_is_retried_after_the_wait_then_succeeds(self):
        steps = [reply(fixture("error_429.json"), 429, extra=[("Retry-After", "2")]),
                 reply(fixture("response_ok.json"))]
        harness = Harness(self, steps, retry_policy=RetryPolicy(
            not_sent=0, rejected=3, possible=0, not_sent_cap=0.0, rejected_cap=0.0,
            retry_after_cap=60.0))
        outcome, receipt = harness.evaluate()
        self.assertEqual(set(outcome), {"screen", "where"})
        self.assertEqual(receipt["attempt"], 2)
        self.assertEqual(len(harness.script.requests), 2)

    def test_error_fields_keep_only_short_tokens(self):
        self.assertEqual(foundry.error_fields(None), {})
        self.assertEqual(foundry.error_fields({}), {})
        self.assertEqual(foundry.error_fields({"code": "DeploymentNotFound", "type": "t_1",
                                               "message": "private"}),
                         {"error_code": "DeploymentNotFound", "error_type": "t_1"})
        self.assertEqual(foundry.error_fields({"code": 422}), {"error_code": 422})
        for bad in ({"code": "has space"}, {"code": "x" * 65}, {"code": 99}, {"code": 600},
                    {"code": True}, {"code": 1.5}, {"code": ["a"]}, {"code": {"a": 1}},
                    {"code": "a\nb"}, {"code": "sk-" + "a" * 40 + "!"}, {"type": "a b"},
                    {"type": 3}, {"type": None}, {"message": "private"}):
            with self.subTest(bad=bad):
                self.assertEqual(foundry.error_fields(bad), {})

    def test_the_body_of_an_error_is_withheld_when_it_carries_a_key(self):
        for auth in ("api-key", "entra-token"):
            for key in ALL_KEYS:
                with self.subTest(auth=auth, key=key[:12]):
                    body = json.dumps({"error": {"code": "x",
                                                 "message": "bad key " + key}}).encode()
                    harness = Harness(self, [reply(body, 401)], environ=ALL_ENV, auth=auth)
                    outcome, receipt = harness.evaluate()
                    self.assertEqual(outcome.code, "http_unauthorized")
                    self.assertEqual(receipt["provider_error"],
                                     {"error_body": "withheld_sensitive"})
                    self.assertNotIn(key, harness.receipt_text())
                    self.assertNotIn(key, json.dumps(receipt))

    def test_status_code_is_a_pure_table(self):
        self.assertEqual(foundry.status_code(404, {"metadata": {"failed_routing_step": "x"}}),
                         "route_unavailable")
        self.assertEqual(foundry.status_code(403, {"metadata": {"reasons": ["x"]}}),
                         "http_forbidden")
        self.assertEqual(foundry.status_code(199), "http_rejected")
        self.assertEqual(foundry.status_code(204), "http_rejected")

    def test_request_id_comes_from_the_header_in_its_charset(self):
        for header, kept in ((REQUEST_ID, REQUEST_ID), ("bad id", None), ("r" * 129, None),
                             ("req-" + API_KEY, None)):
            with self.subTest(header=header[:16]):
                harness = Harness(self, [reply(fixture("response_ok.json"),
                                               request_id=header)])
                _, receipt = harness.evaluate()
                self.assertEqual(receipt["request_id"], kept)
                self.assertNotIn(API_KEY, json.dumps(receipt))
        harness = Harness(self, [reply(fixture("response_ok.json"), request_id=None,
                                       extra=[("apim-request-id", "apim-private-1")])])
        _, receipt = harness.evaluate()
        self.assertIsNone(receipt["request_id"])
        self.assertNotIn("apim", json.dumps(receipt))

    def test_a_rejected_200_keeps_the_request_id_and_the_wire_hash(self):
        cases = [(b'{"answers": nope', "response_invalid_json"),
                 (fixture("response_ok.json"), "response_type")]
        for body, code in cases:
            with self.subTest(code=code):
                step = reply(body)
                if code == "response_type":
                    step = Reply(status=200, body=body, close_after=True, headers=[
                        ("Content-Type", "text/plain"), ("Content-Length", str(len(body))),
                        ("x-request-id", REQUEST_ID)])
                harness = Harness(self, [step])
                outcome, receipt = harness.evaluate()
                self.assertEqual(outcome.code, code)
                (request,) = harness.script.requests
                self.assertEqual(receipt["request_id"], REQUEST_ID)
                self.assertEqual(receipt["wire_sha256"], hashlib.sha256(request.body).hexdigest())
                self.assertTrue(receipt["submission_possible"])


class PoolTests(unittest.TestCase):
    def test_max_connections_above_one_pools_over_the_instance_host(self):
        script = ScriptedHTTPS([reply(fixture("response_ok.json")),
                                reply(fixture("response_ok.json"))], clock=FakeClock(),
                               host=HOST)

        def factory(host, path, *, port=443, context=None):
            kwargs = {} if context is None else {"context": context}
            return script.exchange(host, path, port=port, **kwargs)

        with mock.patch.object(hosted, "HttpsExchange", factory):
            provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT,
                                       deployment=DEPLOYMENT, max_connections=2)
            self.addCleanup(provider.close)
            self.assertIsNotNone(provider._pool)
            payload = local_envelope(STATE, QUESTIONS)
            for _ in range(2):
                response = provider.decide(ProviderRequest(payload, 5.0))
                self.assertEqual(list(response.answers), ["screen", "where"])
        self.assertEqual({address for address, _ in script.connects}, {(HOST, 443)})
        self.assertEqual(len(script.requests), 2)
        for request in script.requests:
            self.assertEqual(request.target, foundry.PATH)
            self.assertEqual(request.header("api-key"), API_KEY)

    def test_the_pool_bounds_and_the_injected_exchange_rule(self):
        for value in (0, 9, -1, True, 2.0, "4", None):
            with self.subTest(value=value):
                self.assertEqual(code_of(self, FoundryProvider, environ=KEY_ENV,
                                         endpoint=ENDPOINT, deployment=DEPLOYMENT,
                                         max_connections=value), "invalid_request")
        self.assertEqual(code_of(self, FoundryProvider, environ=KEY_ENV, endpoint=ENDPOINT,
                                 deployment=DEPLOYMENT, exchange=object(), max_connections=2),
                         "invalid_request")
        for value in (1, 2, 8):
            provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT,
                                       deployment=DEPLOYMENT, max_connections=value)
            self.assertEqual(provider._pool is None, value == 1)

    def test_a_single_connection_provider_copies_and_a_pooled_one_does_not(self):
        import copy
        provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT, deployment=DEPLOYMENT)
        clone = copy.copy(provider)
        self.assertEqual(clone.route.host, HOST)
        self.assertEqual((clone.auth, clone.endpoint_family),
                         ("api-key", "services.ai.azure.com"))
        pooled = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT, deployment=DEPLOYMENT,
                                 max_connections=2)
        with self.assertRaises(TypeError):
            copy.copy(pooled)


class EnvironmentTests(unittest.TestCase):
    def test_construction_reads_only_the_given_environment(self):
        with mock.patch.dict(os.environ, {"AZURE_API_KEY": "process-key-not-used-0001",
                                          foundry.ENDPOINT_VARIABLE: "http://bad"}):
            provider = FoundryProvider(environ=KEY_ENV, endpoint=ENDPOINT,
                                       deployment=DEPLOYMENT)
            self.assertEqual(provider._api_key, API_KEY)
            # Without environ the process environment is read.
            self.assertEqual(code_of(self, FoundryProvider, deployment=DEPLOYMENT),
                             "endpoint_invalid")

    def test_the_module_imports_no_network_or_identity_library(self):
        text = (Path(foundry.__file__)).read_text(encoding="utf-8")
        for needle in ("import requests", "azure.identity", "import urllib.request",
                       "http.client", "import socket", "os.environ["):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
