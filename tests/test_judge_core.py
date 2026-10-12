"""The judge registry, the Microsoft judge on the OpenRouter route and full precision.

Offline only: scripted sockets behind the real adapter and the real
ValidatedGateway, or small fakes of what the engine reads from a gateway.
Passing these establishes local routing, accounting and validation for a
judge that writes full-precision probabilities; it says nothing about how
the live Microsoft judge behaves.
"""
from decimal import Decimal
from fractions import Fraction
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from decision_bug_hunter import decisions, hosted, judges, openrouter, providers
from decision_bug_hunter.core import Config, Span
from decision_bug_hunter.engine import (IDENTITY_FULL_PRECISION_PLACES, Search,
                                        confidence_identity_violation)
from decision_bug_hunter.hosted import ModelSpec
from decision_bug_hunter.judges import (JUDGE_CHOICES, JUDGES, judge_of_model,
                                        judge_route)
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import QUESTION, ProviderError
from decision_bug_hunter.protocol import STATE_PLACEMENT_MAX_QUESTIONS as RAISED_QUESTIONS
from decision_bug_hunter.protocol import STATE_PLACEMENT_MAX_REQUEST_BYTES as RAISED_BYTES
from decision_bug_hunter.protocol import encode_request as local_envelope
from decision_bug_hunter.providers import (ProviderIdentity, ProviderRequest, RetryPolicy,
                                           ValidatedGateway, make_provider)
from tests.fakes import FakeClock, Reply, ScriptedHTTPS
from tests.support import FixtureProvider, openrouter_body, scan, source

KEY = "offline-judge-core-sentinel-credential-3b7a"
AZURE_KEY = "offline-azure-sentinel-credential-9d41"
AZURE_TOKEN = "offline.azure.entra-sentinel-token-5c2e"
MICROSOFT = "microsoft/microsoft-decision-1"
DATED = "microsoft/microsoft-decision-1-20261009"
LUNA = "openai/gpt-6-luna-decisions"
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
METADATA = {"sequence": 1, "phase": "test"}
#: As the live service writes them: the shortest repr of a double, here of
#: 0.7234519123456789 and 0.2765480876543211 (which sum to 1 within float error).
P1 = Decimal(repr(0.7234519123456789))
P2 = Decimal(repr(0.2765480876543211))
#: (p1 - 1/2) / (1 - 1/2), to the precision of a double.
CONFIDENCE = Decimal(repr(0.4469038246913578))
FULL = {"screen": {"type": "noul", "noul": Decimal("0.8123456789012345")},
        "where": {"type": "choice", "choice": "L1-1", "confidence": CONFIDENCE,
                  "probabilities": {"L1-1": P1, "none": P2}}}
OPENAI_ANSWERS = {"screen": {"type": "noul", "noul": Decimal("0.95")},
                  "where": {"type": "choice", "choice": "L1-1", "confidence": Decimal("0.9"),
                            "probabilities": {"L1-1": Decimal("0.95"),
                                              "none": Decimal("0.05")}}}


def reply(body, status=200):
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    return Reply(status=status, body=body, headers=headers, close_after=True)


def microsoft_body(answers=None, *, model=DATED, provider="Azure", **extra):
    """A 200 body in the shape OpenRouter returned for the Microsoft judge."""
    return openrouter_body(FULL if answers is None else answers, model=model,
                           provider=provider, input_tokens=96, cost=0.000004, **extra)


class Harness:
    """A scripted OpenRouter origin, a provider built by make_provider and a gateway."""

    def __init__(self, test, steps, *, model=None, judge=None, environ=None, **kwargs):
        self.script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=openrouter.HOST)
        exchange = self.script.exchange(openrouter.HOST, openrouter.PATH)
        self.provider = make_provider(
            "openrouter", model=model, judge=judge, api_key=KEY,
            environ={} if environ is None else environ, exchange=exchange, **kwargs)
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.gateway = ValidatedGateway(self.provider, Path(tmp.name) / "receipts",
                                        retry_policy=RetryPolicy.none())
        test.addCleanup(self.gateway.close)

    def evaluate(self, state=STATE, questions=QUESTIONS):
        answers = self.gateway.evaluate(state, questions, metadata=METADATA)
        receipt = json.loads(Path(self.gateway.last_receipt).read_text(encoding="utf-8"))
        return answers, receipt


def code_of(test, call, *args, **kwargs):
    with test.assertRaises(ProviderError) as caught:
        call(*args, **kwargs)
    return caught.exception.code


class RegistryTests(unittest.TestCase):
    def test_the_two_judges_and_their_routes(self):
        self.assertEqual(JUDGE_CHOICES, ("openai", "microsoft"))
        self.assertEqual(set(JUDGES), set(JUDGE_CHOICES))
        pairs = {judge: [(r.selector, r.route_name, r.model, r.verified_live)
                         for r in JUDGES[judge].routes] for judge in JUDGES}
        self.assertEqual(pairs["openai"], [
            ("openai", "openai-decisions", "gpt-6-luna", True),
            ("openrouter", "openrouter-decisions", LUNA, True)])
        self.assertEqual(pairs["microsoft"], [
            ("openrouter", "openrouter-decisions", MICROSOFT, True),
            ("foundry", "foundry-decisions", None, False)])
        self.assertEqual(JUDGES["microsoft"].title, "Microsoft-Decision-1")
        for judge, spec in JUDGES.items():
            self.assertEqual(spec.id, judge)

    def test_only_the_microsoft_judge_carries_a_notice(self):
        self.assertIsNone(JUDGES["openai"].notice)
        self.assertEqual(
            JUDGES["microsoft"].notice,
            "Note: Microsoft-Decision-1 support is experimental: in DBH's validation it "
            "finds fewer bugs than OpenAI Decisions (README: Choosing a judge).")

    def test_judge_route_pairs_only_registered_routes(self):
        self.assertEqual(judge_route("openai", "openai").model, "gpt-6-luna")
        self.assertEqual(judge_route("openai", "openrouter").model, LUNA)
        self.assertEqual(judge_route("microsoft", "openrouter").model, MICROSOFT)
        self.assertIsNone(judge_route("microsoft", "foundry").model)
        for judge, selector in (("microsoft", "openai"), ("openai", "foundry"),
                                ("google", "openrouter"), ("openai", "azure"),
                                ("", "openai"), (None, "openai"), ("openai", None),
                                ("openai", "openai-decisions"), (["microsoft"], "openrouter"),
                                ("microsoft", ["openrouter"]), ({}, "openai"),
                                ("openai", {})):
            with self.subTest(judge=judge, selector=selector):
                self.assertEqual(code_of(self, judge_route, judge, selector),
                                 "invalid_request")

    def test_judge_of_model_follows_the_allow_lists(self):
        self.assertEqual(judge_of_model("openai-decisions", "gpt-6-luna"), "openai")
        self.assertEqual(judge_of_model("openrouter-decisions", LUNA), "openai")
        self.assertEqual(judge_of_model("openrouter-decisions", MICROSOFT), "microsoft")
        # The deployment name is the model on Foundry: any name belongs to the judge.
        self.assertEqual(judge_of_model("foundry-decisions", "my-deployment"), "microsoft")
        self.assertEqual(judge_of_model("foundry-decisions", None), "microsoft")
        for route, model in (("openai-decisions", MICROSOFT), ("openrouter-decisions", "gpt-6-luna"),
                             ("openrouter-decisions", None), ("custom", MICROSOFT)):
            with self.subTest(route=route, model=model):
                self.assertIsNone(judge_of_model(route, model))

    def test_the_registry_agrees_with_the_adapters(self):
        # Every registered model is on its route's allow-list with the same judge.
        by_name = {"openai-decisions": decisions.ROUTE,
                   "openrouter-decisions": openrouter.ROUTE}
        for judge, spec in JUDGES.items():
            for route in spec.routes:
                if route.model is None:
                    continue
                model = by_name[route.route_name].model(route.model)
                self.assertEqual(model.judge, judge)
        self.assertEqual(openrouter.ROUTE.default_model, LUNA)

    def test_the_command_line_routes_are_unchanged_and_foundry_is_buildable(self):
        self.assertEqual(providers.ROUTES, {"openai": "openai-decisions",
                                            "openrouter": "openrouter-decisions"})
        self.assertEqual(providers.ALL_ROUTES, {**providers.ROUTES,
                                                "foundry": "foundry-decisions"})
        for judge in JUDGES.values():
            for route in judge.routes:
                self.assertEqual(providers.ALL_ROUTES[route.selector], route.route_name)

    def test_the_registry_imports_no_adapter(self):
        source_text = Path(judges.__file__).read_text(encoding="utf-8")
        for name in ("hosted", "openrouter", "decisions", "providers", "foundry", "engine"):
            self.assertNotIn(f"import {name}", source_text)
            self.assertNotIn(f"from .{name}", source_text)


class ModelSpecTests(unittest.TestCase):
    def test_defaults_keep_every_existing_spec_unchanged(self):
        spec = ModelSpec("m", price_in_per_mtok=Decimal(1), price_out_upper_per_mtok=Decimal(0))
        self.assertEqual((spec.judge, spec.probability_precision), ("openai", "display"))
        for model in openrouter.ROUTE.models:
            if model.id == LUNA:
                self.assertEqual((model.judge, model.probability_precision, model.display_places),
                                 ("openai", "display", 2))
        self.assertEqual(decisions.ROUTE.models[0].probability_precision, "display")

    def test_values_are_validated(self):
        price = dict(price_in_per_mtok=Decimal(1), price_out_upper_per_mtok=Decimal(0))
        for kwargs in ({"probability_precision": "exact"}, {"probability_precision": None},
                       {"judge": "google"}, {"judge": None}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(code_of(self, ModelSpec, "m", **price, **kwargs),
                                 "invalid_metadata")
        self.assertEqual(ModelSpec("m", **price, judge="microsoft",
                                   probability_precision="full").judge, "microsoft")

    def test_the_microsoft_spec(self):
        spec = openrouter.ROUTE.model(MICROSOFT)
        self.assertEqual((spec.judge, spec.probability_precision), ("microsoft", "full"))
        self.assertEqual((spec.price_in_per_mtok, spec.price_out_upper_per_mtok),
                         (Decimal("0.042"), Decimal(0)))
        self.assertEqual(spec.confidence_identity, "chance_normalized_p1")
        self.assertEqual(spec.expected_upstream, "Azure")
        self.assertEqual(spec.expected_upstream, openrouter.MICROSOFT_EXPECTED_UPSTREAM)
        self.assertIsNone(spec.state_placement_max_questions)
        self.assertIsNone(spec.state_placement_max_envelope_bytes)
        self.assertEqual(spec.limits("instructions"), (64, 24576))
        self.assertEqual(spec.limits("state"), (64, 24576))
        # The OpenAI model on the same route keeps its upstream pin and its raised caps.
        self.assertEqual(openrouter.ROUTE.model(LUNA).expected_upstream, "OpenAI")
        self.assertEqual(openrouter.EXPECTED_UPSTREAM, "OpenAI")
        self.assertEqual(openrouter.ROUTE.model(LUNA).limits("state"),
                         (RAISED_QUESTIONS, RAISED_BYTES))
        # The price was read live after the shared table's date.
        self.assertEqual(spec.price_table_date, "2026-10-11")
        self.assertEqual(openrouter.ROUTE.model(LUNA).price_table_date, "2026-10-06")

    def test_credential_variables_cover_the_azure_credentials(self):
        self.assertEqual(hosted.CREDENTIAL_VARIABLES,
                         ("OPENAI_API_KEY", "OPENROUTER_API_KEY", "AZURE_API_KEY",
                          "AZURE_ENTRA_TOKEN"))

    def test_the_default_auth_header_is_a_bearer_token_in_the_old_position(self):
        provider = OpenRouterProvider(KEY, environ={})
        self.assertEqual(provider.auth_headers(), {"Authorization": "Bearer " + KEY})
        body = local_envelope(STATE, QUESTIONS)
        headers = provider._prepare(ProviderRequest(body, 5.0))[2]
        self.assertEqual(list(headers), ["Authorization", "Content-Type", "Accept",
                                         "Accept-Encoding"])

    def test_an_instance_may_carry_its_own_route(self):
        class Mine(OpenRouterProvider):
            def __init__(self):
                self.route = hosted.RouteSpec(
                    name="openrouter-decisions", selector="openrouter", host="example.test",
                    path="/x", credential_variable="OPENROUTER_API_KEY",
                    models=openrouter.ROUTE.models, default_model=LUNA)
                super().__init__(KEY, environ={})

        self.assertEqual(Mine().route.host, "example.test")
        self.assertEqual(OpenRouterProvider.route.host, "openrouter.ai")


class MakeProviderTests(unittest.TestCase):
    def test_microsoft_on_openrouter(self):
        for placement in ("instructions", "state"):
            with self.subTest(placement=placement):
                provider = make_provider("openrouter", model=MICROSOFT, judge="microsoft",
                                         api_key=KEY, environ={}, policy_placement=placement)
                self.assertIsInstance(provider, OpenRouterProvider)
                self.assertEqual(provider.identity,
                                 ProviderIdentity("openrouter-decisions", model=MICROSOFT))
                self.assertEqual(provider.request_limits, (64, 24576))
                self.assertEqual(provider.payload_limits(b"{}"), (64, 24576))
                with tempfile.TemporaryDirectory() as tmp:
                    gateway = ValidatedGateway(provider, tmp)
                    self.addCleanup(gateway.close)
                    self.assertEqual(gateway.judge, "microsoft")
                    self.assertIs(gateway.full_precision, True)
                    # Full-precision probabilities have no display precision.
                    self.assertIsNone(gateway.display_places)
                    self.assertEqual(gateway.spend["price_table_date"], "2026-10-11")
                    self.assertEqual(gateway.model_id, MICROSOFT)
                    self.assertEqual(gateway.confidence_identity, "chance_normalized_p1")
                    self.assertEqual(gateway.request_limits, (64, 24576))

    def test_the_openai_gateway_keeps_its_display_places_and_price_date(self):
        provider = make_provider("openrouter", model=LUNA, judge="openai", api_key=KEY,
                                 environ={})
        with tempfile.TemporaryDirectory() as tmp:
            gateway = ValidatedGateway(provider, tmp)
            self.addCleanup(gateway.close)
            self.assertIs(gateway.full_precision, False)
            self.assertEqual(gateway.display_places, 2)
            self.assertEqual(gateway.spend["price_table_date"], "2026-10-06")

    def test_an_unhashable_judge_is_refused_as_an_invalid_request(self):
        for judge in (["x"], ["microsoft"], {}):
            with self.subTest(judge=judge):
                self.assertEqual(code_of(self, make_provider, "openrouter", judge=judge,
                                         api_key=KEY, environ={}), "invalid_request")

    def test_a_gateway_reports_only_a_registered_judge(self):
        provider = make_provider("openrouter", judge="microsoft", api_key=KEY, environ={})
        with tempfile.TemporaryDirectory() as tmp:
            gateway = ValidatedGateway(provider, tmp)
            self.addCleanup(gateway.close)
            self.assertEqual(gateway.judge, "microsoft")
            for judge in ("bogus", "Microsoft", "x" * 5000, "", 3, ["microsoft"], None):
                with self.subTest(judge=judge):
                    provider.model_spec = types.SimpleNamespace(judge=judge)
                    self.assertIsNone(gateway.judge)

    def test_the_judge_default_model_is_used_when_no_model_is_given(self):
        provider = make_provider("openrouter", judge="microsoft", api_key=KEY, environ={})
        self.assertEqual(provider.model_spec.id, MICROSOFT)
        provider = make_provider("openrouter", judge="openai", api_key=KEY, environ={})
        self.assertEqual(provider.model_spec.id, LUNA)
        provider = make_provider("openai", judge="openai", api_key=KEY, environ={})
        self.assertEqual(provider.model_spec.id, "gpt-6-luna")

    def test_openai_judge_on_both_routes_is_the_same_provider_as_before(self):
        for route, model in (("openai", "gpt-6-luna"), ("openrouter", LUNA)):
            with self.subTest(route=route):
                provider = make_provider(route, judge="openai", model=model, api_key=KEY,
                                         environ={})
                plain = make_provider(route, api_key=KEY, environ={})
                self.assertEqual(provider.identity, plain.identity)
                self.assertEqual(provider.model_spec, plain.model_spec)
                with tempfile.TemporaryDirectory() as tmp:
                    gateway = ValidatedGateway(provider, tmp)
                    self.addCleanup(gateway.close)
                    self.assertEqual(gateway.judge, "openai")
                    self.assertIs(gateway.full_precision, False)

    def test_a_judge_and_a_model_of_another_judge_are_refused(self):
        for kwargs in ({"route": "openrouter", "model": MICROSOFT, "judge": "openai"},
                       {"route": "openrouter", "model": LUNA, "judge": "microsoft"},
                       {"route": "openai", "model": MICROSOFT, "judge": "openai"},
                       {"route": "openrouter", "model": "microsoft/other", "judge": "microsoft"}):
            with self.subTest(**kwargs):
                route = kwargs.pop("route")
                self.assertEqual(code_of(self, make_provider, route, api_key=KEY, environ={},
                                         **kwargs), "invalid_request")

    def test_a_judge_and_a_route_that_do_not_pair_are_refused(self):
        for route, judge in (("openai", "microsoft"), ("foundry", "openai"),
                             ("openai-decisions", "microsoft")):
            with self.subTest(route=route, judge=judge):
                self.assertEqual(code_of(self, make_provider, route, judge=judge, api_key=KEY,
                                         environ={}), "invalid_request")
        self.assertEqual(code_of(self, make_provider, "openrouter", judge="google",
                                 api_key=KEY, environ={}), "invalid_request")
        self.assertEqual(code_of(self, make_provider, "nowhere", judge="openai",
                                 api_key=KEY, environ={}), "invalid_provider")

    def test_without_a_judge_the_model_alone_decides_as_before(self):
        self.assertEqual(make_provider("openrouter", model=MICROSOFT, api_key=KEY,
                                       environ={}).model_spec.judge, "microsoft")
        self.assertEqual(code_of(self, make_provider, "openai", model=MICROSOFT, api_key=KEY,
                                 environ={}), "invalid_request")
        self.assertEqual(code_of(self, make_provider, "nowhere", api_key=KEY, environ={}),
                         "invalid_provider")
        self.assertEqual(code_of(self, make_provider, None, api_key=KEY, environ={}),
                         "invalid_provider")

    def test_foundry_options_belong_to_the_foundry_route(self):
        for option in ("foundry_endpoint", "foundry_deployment", "foundry_auth"):
            with self.subTest(option=option):
                self.assertEqual(code_of(self, make_provider, "openrouter", api_key=KEY,
                                         environ={}, **{option: "x"}), "invalid_request")

    def test_foundry_is_built_by_its_own_module_and_is_unavailable_without_it(self):
        missing = ModuleNotFoundError("No module named 'decision_bug_hunter.foundry'",
                                      name="decision_bug_hunter.foundry")
        with mock.patch.object(providers.importlib, "import_module", side_effect=missing):
            self.assertEqual(code_of(self, make_provider, "foundry", judge="microsoft",
                                     api_key=KEY, environ={}), "invalid_provider")
            self.assertEqual(code_of(self, make_provider, "foundry-decisions", api_key=KEY,
                                     environ={}), "invalid_provider")
        # Another missing module is a real defect, not an absent adapter.
        other = ModuleNotFoundError("No module named 'elsewhere'", name="elsewhere")
        with mock.patch.object(providers.importlib, "import_module", side_effect=other):
            with self.assertRaises(ModuleNotFoundError):
                make_provider("foundry", judge="microsoft", api_key=KEY, environ={})

    def test_foundry_receives_its_options(self):
        built = []

        class Fake:
            def __init__(self, *args, **kwargs):
                built.append((args, kwargs))

        module = types.SimpleNamespace(FoundryProvider=Fake)
        with mock.patch.object(providers.importlib, "import_module", return_value=module):
            provider = make_provider(
                "foundry", judge="microsoft", api_key=KEY, environ={}, exchange="x",
                foundry_endpoint="https://r.services.ai.azure.com", foundry_deployment="dep",
                foundry_auth="api-key", policy_placement="state", max_connections=3)
            self.assertIsInstance(provider, Fake)
            ((args, kwargs),) = built
            self.assertEqual(args, (KEY,))
            self.assertEqual(kwargs, {
                "environ": {}, "exchange": "x", "endpoint": "https://r.services.ai.azure.com",
                "deployment": "dep", "auth": "api-key", "policy_placement": "state",
                "max_connections": 3})
            # The deployment is the model there: a model, routing or zdr is refused.
            for extra in ({"model": "dep"}, {"routing": "deny"}, {"zdr": True}):
                with self.subTest(extra=extra):
                    self.assertEqual(code_of(self, make_provider, "foundry", api_key=KEY,
                                             environ={}, **extra), "invalid_request")
            # The OpenAI judge is not served by Foundry.
            self.assertEqual(code_of(self, make_provider, "foundry", judge="openai",
                                     api_key=KEY, environ={}), "invalid_request")


class MicrosoftUpstreamTests(unittest.TestCase):
    """The Microsoft spec pins Azure; a mismatch is journaled and never fails the call."""

    def decode(self, model, **kwargs):
        spec = openrouter.ROUTE.model(model)
        body = microsoft_body(**kwargs) if model == MICROSOFT else openrouter_body(
            OPENAI_ANSWERS, **kwargs)
        return openrouter.decode_response(body, QUESTIONS, model=model,
                                          expected_upstream=spec.expected_upstream)

    def test_azure_is_not_flagged(self):
        response = self.decode(MICROSOFT)
        self.assertIsNone(response.error)
        self.assertEqual(response.provenance["upstream_provider"], "Azure")
        self.assertNotIn("upstream_provider_unexpected", response.provenance)

    def test_another_upstream_is_journaled_and_not_fatal(self):
        for upstream in ("Microsoft", "OpenAI", "azure", "bad\nname", 7):
            with self.subTest(upstream=upstream):
                response = self.decode(MICROSOFT, provider=upstream)
                self.assertIsNone(response.error)
                self.assertEqual(response.answers["screen"]["noul"], FULL["screen"]["noul"])
                self.assertIs(response.provenance["upstream_provider_unexpected"], True)

    def test_an_absent_upstream_is_not_flagged(self):
        # Without a provider block the check never runs: nothing is recorded.
        response = self.decode(MICROSOFT, omit=("provider",))
        self.assertIsNone(response.error)
        self.assertNotIn("upstream_provider", response.provenance)
        self.assertNotIn("upstream_provider_unexpected", response.provenance)

    def test_the_openai_spec_is_unchanged(self):
        response = self.decode(LUNA)
        self.assertEqual(response.provenance["upstream_provider"], "OpenAI")
        self.assertNotIn("upstream_provider_unexpected", response.provenance)
        flagged = self.decode(LUNA, provider="Azure")
        self.assertIs(flagged.provenance["upstream_provider_unexpected"], True)

    def test_a_mismatch_reaches_the_receipt_through_the_gateway(self):
        harness = Harness(self, [reply(microsoft_body(provider="Microsoft"))],
                          model=MICROSOFT, judge="microsoft")
        _, receipt = harness.evaluate()
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual(receipt["upstream_provider"], "Microsoft")
        self.assertIs(receipt["upstream_provider_unexpected"], True)


class MicrosoftExchangeTests(unittest.TestCase):
    def test_a_full_precision_exchange_validates_and_names_the_judge(self):
        harness = Harness(self, [reply(microsoft_body())], model=MICROSOFT, judge="microsoft")
        answers, receipt = harness.evaluate()
        self.assertEqual(answers["screen"]["noul"], Decimal("0.8123456789012345"))
        self.assertEqual(answers["where"]["probabilities"], {"L1-1": P1, "none": P2})
        self.assertEqual(answers["where"]["confidence"], CONFIDENCE)
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual(receipt["judge"], "microsoft")
        self.assertEqual(receipt["model_requested"], MICROSOFT)
        self.assertEqual(receipt["model_returned"], DATED)
        self.assertEqual(receipt["route"], "openrouter-decisions")
        self.assertEqual(receipt["cost_source"], "provider_reported")
        self.assertEqual(receipt["cost_usd"], "0.000004")
        self.assertEqual(receipt["upstream_provider"], "Azure")
        self.assertNotIn("upstream_provider_unexpected", json.dumps(receipt))
        # The judge key sits beside the route and model identity.
        keys = list(receipt)
        self.assertEqual(keys[keys.index("model_requested") + 1], "judge")
        self.assertEqual(harness.gateway.judge, "microsoft")

    def test_the_request_is_the_same_splice_with_the_microsoft_model(self):
        harness = Harness(self, [reply(microsoft_body())], model=MICROSOFT, judge="microsoft")
        harness.evaluate()
        (request,) = harness.script.requests
        local = local_envelope(STATE, QUESTIONS)
        self.assertEqual(request.body, b'{"model":"' + MICROSOFT.encode() + b'","state":'
                         + local[len(b'{"contract":"dbh-judge-v1","state":'):-1]
                         + b',"provider":{"allow_fallbacks":false,"data_collection":"deny"}}')
        self.assertEqual((request.method, request.target), ("POST", "/api/alpha/decisions"))
        self.assertEqual(request.header("Authorization"), "Bearer " + KEY)

    def test_the_openai_exchange_has_no_judge_key(self):
        body = openrouter_body(OPENAI_ANSWERS)
        harness = Harness(self, [reply(body)], judge="openai")
        _answers, receipt = harness.evaluate()
        self.assertNotIn("judge", receipt)
        self.assertEqual(receipt["model_requested"], LUNA)
        harness = Harness(self, [reply(body)])
        self.assertNotIn("judge", harness.evaluate()[1])

    def test_a_wrong_echo_is_a_model_defect(self):
        body = microsoft_body(model="microsoft/other-model-20261009")
        harness = Harness(self, [reply(body)], model=MICROSOFT, judge="microsoft")
        with self.assertRaises(ProviderError) as caught:
            harness.evaluate()
        self.assertEqual(caught.exception.code, "response_model")

    def test_the_mass_defect_of_a_float32_vector_is_a_distribution_defect(self):
        # Documents the OM-slack contingency: 0.9999999 is not within 1e-12.
        answers = {**FULL, "where": {
            "type": "choice", "choice": "L1-1", "confidence": Decimal("0.4999999"),
            "probabilities": {"L1-1": Decimal("0.7499999"), "none": Decimal("0.25")}}}
        harness = Harness(self, [reply(microsoft_body(answers))], model=MICROSOFT,
                          judge="microsoft")
        got, _receipt = harness.evaluate()
        self.assertEqual(set(got), {"screen"})
        self.assertEqual(harness.gateway.last_defects, {"where": "response_distribution"})
        # The same vector summing to 1 within float64 error validates.
        near = {**FULL, "where": {
            "type": "choice", "choice": "L1-1", "confidence": CONFIDENCE,
            "probabilities": {"L1-1": P1, "none": Decimal("0.2765480876543212")}}}
        harness = Harness(self, [reply(microsoft_body(near))], model=MICROSOFT,
                          judge="microsoft")
        got, _receipt = harness.evaluate()
        self.assertEqual(set(got), {"screen", "where"})
        self.assertEqual(harness.gateway.last_defects, {})

    def test_the_probabilities_may_differ_between_identical_requests(self):
        # Live, identical requests differ by about 1e-10; each still validates alone.
        wobble = {**FULL, "where": {
            "type": "choice", "choice": "L1-1", "confidence": Decimal("0.4469038247913578"),
            "probabilities": {"L1-1": Decimal("0.7234519123956789"),
                              "none": Decimal("0.2765480876043211")}}}
        harness = Harness(self, [reply(microsoft_body()), reply(microsoft_body(wobble))],
                          model=MICROSOFT, judge="microsoft")
        first, _ = harness.evaluate()
        second, _ = harness.evaluate()
        self.assertNotEqual(first["where"]["probabilities"], second["where"]["probabilities"])


class SensitiveInputTests(unittest.TestCase):
    def test_an_azure_credential_in_source_is_refused_on_every_route(self):
        for variable, value in (("AZURE_API_KEY", AZURE_KEY),
                                ("AZURE_ENTRA_TOKEN", AZURE_TOKEN)):
            for route in ("openai", "openrouter"):
                with self.subTest(variable=variable, route=route):
                    script = ScriptedHTTPS([], clock=FakeClock())
                    host, path = ((openrouter.HOST, openrouter.PATH) if route == "openrouter"
                                  else (decisions.HOST, decisions.PATH))
                    provider = make_provider(
                        route, api_key=KEY, environ={variable: value},
                        exchange=script.exchange(host, path))
                    with tempfile.TemporaryDirectory() as tmp:
                        gateway = ValidatedGateway(provider, tmp)
                        self.addCleanup(gateway.close)
                        state = {**STATE, "note": "secret " + value + " inside"}
                        with self.assertRaises(ProviderError) as caught:
                            gateway.evaluate(state, QUESTIONS, metadata=METADATA)
                        self.assertEqual(caught.exception.code, "sensitive_input")
                    self.assertEqual(script.requests, [])
                    self.assertEqual(script.connects, [])

    def test_a_short_azure_value_is_not_a_credential(self):
        provider = OpenRouterProvider(KEY, environ={"AZURE_API_KEY": "short"})
        provider.check_sensitive({"text": "a short value inside"})
        provider = OpenRouterProvider(KEY, environ={"AZURE_API_KEY": AZURE_KEY})
        with self.assertRaises(ProviderError) as caught:
            provider.check_sensitive({"text": AZURE_KEY})
        self.assertEqual(caught.exception.code, "sensitive_input")

    def test_a_response_carrying_an_azure_credential_is_withheld(self):
        body = microsoft_body(note=AZURE_TOKEN)
        harness = Harness(self, [reply(body)], model=MICROSOFT, judge="microsoft",
                          environ={"AZURE_ENTRA_TOKEN": AZURE_TOKEN})
        with self.assertRaises(ProviderError) as caught:
            harness.evaluate()
        self.assertEqual(caught.exception.code, "response_sensitive")


class Gateway:
    """The attributes the engine reads from a gateway."""

    def __init__(self, *, rounding_places=None, display_places=None, full_precision=False,
                 confidence_identity=None):
        self.rounding_places = rounding_places
        self.display_places = display_places
        self.full_precision = full_precision
        self.confidence_identity = confidence_identity


def search_for(gateway, **options):
    return Search(source(20), gateway, Config(**options), None)


def singles_answer(masses, confidence):
    best = max(masses, key=masses.get)
    return {"type": "choice", "choice": best, "probabilities": dict(masses),
            "confidence": confidence}


class FullPrecisionTests(unittest.TestCase):
    OPTIONS = [Span(5, 5), Span(6, 6)]

    def answer(self):
        # (0.5 - 1/3) / (1 - 1/3) = 0.25, as displayed.
        return singles_answer({"L5-5": Decimal("0.5"), "L6-6": Decimal("0.3"),
                               "none": Decimal("0.2")}, Decimal("0.25"))

    def test_the_mass_gate_uses_an_exact_zero_quantum(self):
        answer = self.answer()
        search = search_for(Gateway(full_precision=True))
        self.assertEqual(search.gate_half_quantum(answer), Fraction(0))
        # p = 0.5 exactly reaches the threshold only when nothing is subtracted.
        spans, fields = search.mass_selection(answer, self.OPTIONS, 3)
        self.assertEqual(spans, [Span(5, 5)])
        self.assertEqual(fields["mass_selected"], ["L5-5"])
        self.assertEqual(fields["qualifying_runs"], 1)
        # A model that displays two places keeps h = 0.005 and misses the same answer.
        display = search_for(Gateway(display_places=2))
        self.assertEqual(display.gate_half_quantum(answer), Fraction(1, 200))
        self.assertEqual(display.mass_selection(answer, self.OPTIONS, 3)[0], [])

    def test_a_rounding_profile_still_wins(self):
        answer = self.answer()
        search = search_for(Gateway(rounding_places=3, full_precision=True))
        self.assertEqual(search.gate_half_quantum(answer), Fraction(1, 2000))
        search = search_for(Gateway(rounding_places=0, full_precision=True))
        self.assertEqual(search.gate_half_quantum(answer), Fraction(1, 2))

    def test_only_a_true_full_precision_flag_counts(self):
        answer = self.answer()
        for flag in (False, None, 1, "full", object()):
            with self.subTest(flag=flag):
                search = search_for(Gateway(display_places=2, full_precision=flag))
                self.assertEqual(search.gate_half_quantum(answer), Fraction(1, 200))
        # A gateway that has no such attribute (a custom one) is unchanged: h
        # comes from the two places the answer shows.
        plain = types.SimpleNamespace(display_places=None, rounding_places=None)
        self.assertEqual(search_for(plain).gate_half_quantum(answer), Fraction(1, 200))

    def test_the_identity_tolerance_at_six_places(self):
        self.assertEqual(IDENTITY_FULL_PRECISION_PLACES, 6)

        def answer(delta):
            return {"type": "choice", "choice": "a", "confidence": CONFIDENCE + delta,
                    "probabilities": {"a": P1, "b": P2}}

        places = IDENTITY_FULL_PRECISION_PLACES
        self.assertFalse(confidence_identity_violation(answer(Decimal(0)), places))
        self.assertFalse(confidence_identity_violation(answer(Decimal("1e-12")), places))
        self.assertFalse(confidence_identity_violation(answer(Decimal("-1e-12")), places))
        self.assertTrue(confidence_identity_violation(answer(Decimal("1e-5")), places))
        self.assertTrue(confidence_identity_violation(answer(Decimal("-1e-5")), places))
        # The bound is h * (1 + 1 / (1 - 1 / k)) with h = 5e-7: about 1.5e-6 for two
        # options, so 1e-6 and 1.4e-6 are inside it and 1.6e-6 is outside.
        for delta, flagged in (("1e-6", False), ("1.4e-6", False), ("1.6e-6", True),
                               ("-1.4e-6", False), ("-1.6e-6", True)):
            with self.subTest(delta=delta):
                self.assertIs(confidence_identity_violation(answer(Decimal(delta)), places),
                              flagged)
        # At the display precision of the OpenAI judge the same 1e-5 is invisible.
        self.assertFalse(confidence_identity_violation(answer(Decimal("1e-5")), 2))

    def record(self, gateway, answers):
        search = search_for(gateway)
        batch = {name: {"type": answer["type"]} for name, answer in answers.items()}
        search.record_answers(batch, answers, {}, Span(1, 20), "test")
        return search

    def test_record_answers_counts_a_deviation_only_above_float_error(self):
        identity = "chance_normalized_p1"

        def where(delta):
            return {"where": {"type": "choice", "choice": "a",
                              "confidence": CONFIDENCE + delta,
                              "probabilities": {"a": P1, "b": P2}}}

        full = Gateway(full_precision=True, display_places=2, confidence_identity=identity)
        for delta, violations in ((Decimal(0), 0), (Decimal("1e-12"), 0),
                                  (Decimal("1e-5"), 1)):
            with self.subTest(delta=delta):
                search = self.record(full, where(delta))
                self.assertEqual(search.identity_checked, 1)
                self.assertEqual(search.identity_violations, violations)
        # Without full precision the declared two places decide, as before.
        display = Gateway(display_places=2, confidence_identity=identity)
        search = self.record(display, where(Decimal("1e-5")))
        self.assertEqual((search.identity_checked, search.identity_violations), (1, 0))
        # Only a true flag switches the tolerance: a truthy value keeps the two places.
        for flag in (1, "full", object()):
            with self.subTest(flag=flag):
                truthy = Gateway(full_precision=flag, display_places=2,
                                 confidence_identity=identity)
                search = self.record(truthy, where(Decimal("1e-5")))
                self.assertEqual((search.identity_checked, search.identity_violations),
                                 (1, 0))
        # A route with no declared identity is never checked.
        search = self.record(Gateway(full_precision=True), where(Decimal("1e-5")))
        self.assertEqual(search.identity_checked, 0)


class ReportJudgeTests(unittest.TestCase):
    class Judged(FixtureProvider):
        def __init__(self, judge, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.judge = judge

    def report(self, provider):
        return scan(source(24), provider, Config(whole_file=False))

    def test_the_microsoft_report_names_the_judge_after_the_model(self):
        result = self.report(self.Judged("microsoft", [(5, 5)]))
        keys = list(result)
        self.assertEqual(result["judge"], "microsoft")
        self.assertEqual(keys[keys.index("model") + 1], "judge")
        self.assertEqual(keys[keys.index("judge") + 1], "synthetic")

    def test_an_openai_or_custom_report_has_no_judge_key(self):
        for provider in (self.Judged("openai", [(5, 5)]), self.Judged(None, [(5, 5)]),
                         FixtureProvider([(5, 5)])):
            with self.subTest(judge=getattr(provider, "judge", "absent")):
                self.assertNotIn("judge", self.report(provider))

    def test_only_a_known_judge_name_is_reported(self):
        for judge in (3, ["microsoft"], object(), "bogus", "Microsoft", "x" * 5000,
                      "sk-" + "a" * 40, ""):
            with self.subTest(judge=judge):
                # Not a registered name: it must never reach the JSON report.
                self.assertNotIn("judge", self.report(self.Judged(judge, [(5, 5)])))


if __name__ == "__main__":
    unittest.main()
