"""Revision-3 WP-13: policy placement and per-model request geometry.

``--policy-placement`` defaults to "instructions", whose request bytes and
reports are pinned here against the build before this change. "state" sends
the policy preamble once, as the first state key, and strips it from every
question that carried it; only such requests may use a route's raised caps
(OpenRouter: 200 questions and 48 KiB, after S12b moved no answer across
batch geometries). OpenAI direct keeps 64 questions and 24 KiB.
"""
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import decisions, openrouter
from decision_bug_hunter.core import Config, Span
from decision_bug_hunter.engine import Search
from decision_bug_hunter.protocol import (MAX_QUESTIONS, MAX_REQUEST_BYTES, MAX_STATE_BYTES,
                                          POLICY_STATE_KEY, STATE_PLACEMENT_MAX_QUESTIONS,
                                          STATE_PLACEMENT_MAX_REQUEST_BYTES, ProviderError,
                                          RequestEnvelope, _REQUEST_PREFIX, _json,
                                          encode_request, place_policy, request_envelope,
                                          using_request_envelope, validate_answer_objects)
from decision_bug_hunter.providers import (ProviderRequest, RetryPolicy, ValidatedGateway,
                                           make_provider)
from decision_bug_hunter.questions import (load_pack, noul, policy, prepared_question_batches,
                                           state_for)
from tests.fakes import FakeClock, Reply, ScriptedHTTPS
from tests.support import (FixtureProvider, clean_provider_env, openrouter_body, scan,
                           source)
from tests.test_choice_gate import PRE_WP15, digests, scenarios

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "tools" / "smoke" / "openrouter"
KEY = "offline-placement-sentinel-credential-7c3e"
PACK, _PACK_HASH = load_pack()
POLICY_V1 = policy(PACK, "v1")
POLICY_V2 = policy(PACK, "v2")
WIDE = RequestEnvelope(POLICY_V1, STATE_PLACEMENT_MAX_QUESTIONS,
                       STATE_PLACEMENT_MAX_REQUEST_BYTES)
NARROW = RequestEnvelope(POLICY_V1)

# (wire sha256, report sha256) of the pinned scenarios with every default,
# canaries on included, produced by the build before WP-13 (HEAD 599a1c6).
PRE_WP13 = {
    "legacy": ("6f4823a49d87418d66a4144036d5e714a5058b9f24e4c1187e7c2ddf2cbe319d",
               "7865a120b2428ebbee0805b752a27197fb2052afb7d965e4767ad0a40a4470d2"),
    "scoped": ("ed8fdcb46a3cdf7e8cf3a4c50749a7095eb2f5cc55fbd5aa017e234d7223b9b1",
               "5d73f14635b6a46595a1ded5f78a96a1a6f2bcf8c45badc9b5bb84315e057ff0"),
    "legacy_spec": ("4e6a91baa3d537d7378d9d9130ca532c9965b654a8c7073af443379f3a33b576",
                    "d52f58b3f3b50432464f04961584a835f9d1a35fea30752c73b51bf149db4a6a"),
    "strict": ("6f4823a49d87418d66a4144036d5e714a5058b9f24e4c1187e7c2ddf2cbe319d",
               "299a2e5a52ca778db923f070e1e3ea0413839f1a1ad65e87a0a02f90aa9b1064"),
    "diffuse": ("4be94793ac4fa422ec7df6c7eb6ca45feebc901b8ea1fad3667416975edeed48",
                "c2936055458eca57218350e056125e30f6600dd4687a216633b438668d270541"),
    "diffuse_scoped": ("f0ec532b9d151f526c3030821e2caebe81d7788d1282f53de426bba80df58824",
                       "352da8d2c71ec58732cb54e0b4256d7328e6c749d288db79487c837dd7bb37cc"),
    "context": ("ba687d017d67e34297246887e059f9e87dc28daf2b8c3ee33fc693897b09776c",
                "07e34c6cdfdc5baf0c8619c9f69b147f0e959f7d946db51c465fe0dea797aed5"),
}


def sample_state(lines=12):
    src = source(lines)
    state = state_for(src, Span(1, lines), 0, None, context_scope="declared_standalone")
    return src, state


def screens(count, lines=12):
    """*count* policy-carrying screen questions over the lines of a sample."""
    return {f"screen_{i}": noul(PACK, "screen", Span(1 + i % lines, 1 + i % lines))
            for i in range(count)}


def small(count, *, placed=True):
    """*count* short policy-carrying questions (200 fit in 48 KiB once placed)."""
    prefix = POLICY_V1 + " " if placed else ""
    return {f"q{i}": {"type": "noul", "instructions": prefix + f"Is line {1 + i % 12} wrong?",
                      "criteria": {"true": "yes", "false": "no"}}
            for i in range(count)}


def s02s():
    """The committed S02s production split: (state, merged questions, wires)."""
    wires = [(SMOKE / f"S02s-{i}-production-split.local.json").read_bytes() for i in (1, 2)]
    bodies = [json.loads(wire) for wire in wires]
    state = bodies[0]["state"]
    questions = {}
    for body in bodies:
        assert body["state"] == state
        questions.update(body["questions"])
    return state, questions, wires


def answers_for(questions, value=Decimal("0.05")):
    return {name: {"type": "noul", "noul": value} for name in questions}


class Wide(FixtureProvider):
    """A fixture gateway that declares OpenRouter's policy-in-state caps."""

    request_limits = (STATE_PLACEMENT_MAX_QUESTIONS, STATE_PLACEMENT_MAX_REQUEST_BYTES)


class DefaultWireTests(unittest.TestCase):
    def test_default_wire_byte_identical_to_b1(self):
        # Every default, canaries on: the bytes and reports of 599a1c6.
        for name, (provider, src, cfg, kwargs) in scenarios(canaries="on").items():
            with self.subTest(name):
                self.assertEqual(cfg.policy_placement, "instructions")
                self.assertEqual(digests(provider, src, cfg, **kwargs), PRE_WP13[name])
        # Canaries off and placement named explicitly: the b1 (pre-WP-15) pins.
        for name, (provider, src, cfg, kwargs) in scenarios(
                policy_placement="instructions").items():
            with self.subTest(f"b1 {name}"):
                self.assertEqual(digests(provider, src, cfg, **kwargs), PRE_WP15[name])
        # A gateway that declares raised caps changes nothing by default.
        provider, src, cfg, kwargs = scenarios(canaries="on")["legacy"]
        wide = Wide(provider.bugs)
        self.assertEqual(digests(wide, src, cfg, **kwargs), PRE_WP13["legacy"])

    def test_default_packer_reproduces_committed_s02s_bytes(self):
        state, questions, wires = s02s()
        for envelope in (None, RequestEnvelope()):
            with self.subTest(envelope=envelope):
                if envelope is None:
                    packed = list(prepared_question_batches(state, questions))
                else:
                    with using_request_envelope(envelope):
                        packed = list(prepared_question_batches(state, questions))
                self.assertEqual([wire for _batch, _failed, wire in packed], wires)

    def test_default_envelope_moves_nothing(self):
        _src, state = sample_state()
        questions = screens(3)
        self.assertIs(request_envelope(), request_envelope())
        self.assertEqual(request_envelope(), RequestEnvelope())
        self.assertEqual(request_envelope().limits(True),
                         (MAX_QUESTIONS, MAX_REQUEST_BYTES, MAX_STATE_BYTES))
        placed = place_policy(state, questions)
        self.assertIs(placed[0], state)
        self.assertIs(placed[1], questions)
        self.assertFalse(placed[2])
        # A caller's own "policy" key is plain data under the b1 envelope.
        foreign = {POLICY_STATE_KEY: "caller text", **state}
        self.assertEqual(json.loads(encode_request(foreign, questions))["state"], foreign)

    def test_configuration_and_report_record_only_state_placement(self):
        self.assertEqual(Config().policy_placement, "instructions")
        self.assertNotIn("policy_placement", Config().as_dict())
        self.assertNotIn("policy_placement", Config(policy_placement="instructions").as_dict())
        self.assertEqual(Config(policy_placement="state").as_dict()["policy_placement"], "state")
        for bad in ("State", "", None, "both"):
            with self.subTest(bad=bad), self.assertRaises(ValueError) as caught:
                Config(policy_placement=bad)
            self.assertEqual(str(caught.exception), "invalid_policy_placement")
        report = scan(source(12), FixtureProvider([(5, 5)]), Config(whole_file=False))
        self.assertNotIn("request_geometry", report)
        self.assertNotIn("policy_placement", report["configuration"])


class StatePlacementTests(unittest.TestCase):
    def test_state_placement_policy_first_key_and_stripped(self):
        _src, state = sample_state()
        questions = {**screens(3), "plain": {"type": "noul", "instructions": "Is it plain?",
                                             "criteria": {"true": "yes", "false": "no"}}}
        default = json.loads(encode_request(state, questions))
        with using_request_envelope(NARROW):
            wire = encode_request(state, questions)
        sent = json.loads(wire)
        self.assertEqual(list(sent["state"])[0], POLICY_STATE_KEY)
        self.assertEqual(sent["state"][POLICY_STATE_KEY], POLICY_V1)
        self.assertEqual({k: v for k, v in sent["state"].items() if k != POLICY_STATE_KEY},
                         state)
        self.assertEqual(list(sent["state"])[1:], list(state))
        self.assertEqual(list(sent["questions"]), list(questions))
        for name, question in sent["questions"].items():
            original = default["questions"][name]
            with self.subTest(name):
                self.assertFalse(question["instructions"].startswith(POLICY_V1))
                self.assertEqual(list(question), list(original))
                self.assertEqual(question["criteria"], original["criteria"])
                if name == "plain":
                    self.assertEqual(question, original)
                else:
                    self.assertEqual(POLICY_V1 + " " + question["instructions"],
                                     original["instructions"])
        self.assertLess(len(wire), len(encode_request(state, questions)))
        # Neither argument was mutated.
        self.assertNotIn(POLICY_STATE_KEY, state)
        self.assertTrue(questions["screen_0"]["instructions"].startswith(POLICY_V1))

    def test_placement_follows_the_scan_layout(self):
        provider = FixtureProvider([(5, 5)])
        scan(source(12), provider, Config(whole_file=False, policy_placement="state",
                                          state_layout="v2"))
        placed = [r for r in provider.requests if POLICY_STATE_KEY in r["state"]]
        self.assertTrue(placed)
        self.assertTrue(all(r["state"][POLICY_STATE_KEY] == POLICY_V2 for r in placed))

    def test_placement_is_idempotent_and_refuses_a_foreign_policy(self):
        _src, state = sample_state()
        questions = screens(2)
        with using_request_envelope(NARROW):
            wire = encode_request(state, questions)
            sent = json.loads(wire)
            self.assertEqual(encode_request(sent["state"], sent["questions"]), wire)
            self.assertEqual(place_policy(sent["state"], sent["questions"])[1:],
                             (sent["questions"], True))
            for foreign in ({POLICY_STATE_KEY: "other", **state},
                            {**state, POLICY_STATE_KEY: POLICY_V1}):
                with self.subTest(first=list(foreign)[0]), \
                        self.assertRaises(ProviderError) as caught:
                    encode_request(foreign, questions)
                self.assertEqual(caught.exception.code, "invalid_request")

    def test_request_without_the_policy_is_unchanged(self):
        _src, state = sample_state()
        plain = {"claim": {"type": "noul", "instructions": "Does line 1 exist?",
                           "criteria": {"true": "yes", "false": "no"}}}
        b1 = encode_request(state, plain)
        self.assertEqual(b1, _REQUEST_PREFIX + _json(state) + b',"questions":'
                         + _json(plain) + b"}")
        with using_request_envelope(WIDE):
            self.assertEqual(encode_request(state, plain), b1)
            self.assertEqual(place_policy(state, plain), (state, plain, False))
            (_batch, _failed, wire), = prepared_question_batches(state, plain)
            self.assertEqual(wire, b1)

    def test_evidence_state_cap_excludes_the_policy_entry(self):
        src = source(1)
        envelope = NARROW
        questions = screens(1, lines=1)
        allowance = envelope.state_allowance
        self.assertEqual(allowance, len(b'"policy":' + _json(POLICY_V1)) + 1)
        self.assertEqual(envelope.limits(True)[2], MAX_STATE_BYTES + allowance)
        # An evidence state of exactly the b1 cap still fits once placed.
        state = {"source_sha256": src.sha256, "file": "x", "pad": ""}
        state["pad"] = "a" * (MAX_STATE_BYTES - len(_json(state)))
        self.assertEqual(len(_json(state)), MAX_STATE_BYTES)
        encode_request(state, questions)
        with using_request_envelope(envelope):
            sent = json.loads(encode_request(state, questions))
            self.assertEqual(len(_json(sent["state"])), MAX_STATE_BYTES + allowance)
            state["pad"] += "a"
            with self.assertRaises(ProviderError) as caught:
                encode_request(state, questions)
            self.assertEqual(caught.exception.code, "request_too_large")

    def test_scan_under_state_placement(self):
        base = FixtureProvider([(5, 5), (130, 131)])
        expected = scan(source(200), base, Config(whole_file=False))
        for provider, caps in ((FixtureProvider([(5, 5), (130, 131)]),
                                (MAX_QUESTIONS, MAX_REQUEST_BYTES)),
                               (Wide([(5, 5), (130, 131)]),
                                (STATE_PLACEMENT_MAX_QUESTIONS,
                                 STATE_PLACEMENT_MAX_REQUEST_BYTES))):
            with self.subTest(caps=caps):
                report = scan(source(200), provider,
                              Config(whole_file=False, policy_placement="state"))
                self.assertEqual(report["status"], "complete")
                self.assertEqual([(f["start_line"], f["end_line"]) for f in report["findings"]],
                                 [(f["start_line"], f["end_line"])
                                  for f in expected["findings"]])
                self.assertEqual(report["configuration"]["policy_placement"], "state")
                self.assertEqual(report["request_geometry"], {
                    "policy_placement": "state", "max_questions": caps[0],
                    "max_request_bytes": caps[1],
                    "max_state_bytes": MAX_STATE_BYTES + NARROW.state_allowance,
                    "max_evidence_state_bytes": MAX_STATE_BYTES})
                self.assertEqual(report["controls"]["requests_failed"], 0)
                self.assertLess(report["calls_attempted"], expected["calls_attempted"])
                for request in provider.requests:
                    self.assertEqual(list(request["state"])[0], POLICY_STATE_KEY)
                    for question in request["questions"].values():
                        self.assertFalse(question["instructions"].startswith(POLICY_V1))
                sizes = [len(r["questions"]) for r in provider.requests]
                self.assertLessEqual(max(sizes), caps[0])
                if caps[0] > MAX_QUESTIONS:
                    self.assertGreater(max(sizes), MAX_QUESTIONS)
                else:
                    self.assertLessEqual(max(sizes), MAX_QUESTIONS)

    def test_engine_takes_caps_from_the_gateway_only_under_state(self):
        def envelope(gateway, placement):
            return Search(source(4), gateway, Config(policy_placement=placement),
                          None).request_envelope()

        self.assertEqual(envelope(Wide(), "instructions"), RequestEnvelope())
        self.assertEqual(envelope(Wide(), "state"), WIDE)
        self.assertEqual(envelope(FixtureProvider(), "state"), NARROW)

        class Odd(FixtureProvider):
            request_limits = [200, 49152]

        self.assertEqual(envelope(Odd(), "state"), NARROW)

    def test_s02s_fixture_packs_into_one_request_under_state_placement(self):
        state, questions, wires = s02s()
        self.assertEqual(len(wires), 2)
        for controls in (False, True):
            with self.subTest(controls=controls), using_request_envelope(WIDE):
                packed = list(prepared_question_batches(state, questions, controls=controls))
                self.assertEqual(len(packed), 1)
                batch, failed, wire = packed[0]
                self.assertIsNone(failed)
                self.assertEqual(len(batch), len(questions) + 2 * controls)
                sent = json.loads(wire)
                self.assertEqual(list(sent["state"])[0], POLICY_STATE_KEY)
                self.assertLess(len(wire), sum(map(len, wires)))
                self.assertEqual(encode_request(sent["state"], sent["questions"]), wire)

    def test_response_validation_accepts_the_placed_question_count(self):
        questions = screens(100)
        with self.assertRaises(ProviderError):
            validate_answer_objects(answers_for(questions), questions, 2)
        with using_request_envelope(WIDE):
            self.assertEqual(len(validate_answer_objects(answers_for(questions), questions, 2)),
                             100)


class GeometryTests(unittest.TestCase):
    def test_caps_per_model(self):
        router = openrouter.ROUTE.model()
        direct = decisions.ROUTE.model()
        self.assertEqual(router.limits(), (64, 24576))
        self.assertEqual(router.limits("instructions"), (64, 24576))
        self.assertEqual(router.limits("state"), (200, 49152))
        self.assertEqual((router.max_questions, router.max_envelope_bytes), (64, 24576))
        self.assertEqual(direct.limits("state"), (64, 24576))
        self.assertEqual(direct.limits(), (64, 24576))
        self.assertEqual((STATE_PLACEMENT_MAX_QUESTIONS, STATE_PLACEMENT_MAX_REQUEST_BYTES),
                         (200, 48 * 1024))
        # The OpenRouter wire (model + envelope + routing) stays under its body cap.
        self.assertLess(STATE_PLACEMENT_MAX_REQUEST_BYTES + 256, openrouter.MAX_BODY_BYTES)
        for route, placement, limits in (("openrouter", "state", (200, 49152)),
                                         ("openrouter", "instructions", (64, 24576)),
                                         ("openai", "state", (64, 24576)),
                                         ("openai", "instructions", (64, 24576))):
            with self.subTest(route=route, placement=placement):
                provider = make_provider(route, api_key=KEY, environ={},
                                         policy_placement=placement)
                self.assertEqual(provider.policy_placement, placement)
                self.assertEqual(provider.request_limits, limits)
        default = make_provider("openrouter", api_key=KEY, environ={})
        self.assertEqual(default.request_limits, (64, 24576))
        for bad in ("State", None):
            with self.subTest(bad=bad), self.assertRaises(ProviderError) as caught:
                make_provider("openrouter", api_key=KEY, environ={}, policy_placement=bad)
            self.assertEqual(caught.exception.code, "invalid_request")

    def test_envelope_bounds(self):
        for args in ((None, 200, MAX_REQUEST_BYTES), (None, MAX_QUESTIONS, 49152),
                     (POLICY_V1, 201, 49152), (POLICY_V1, 200, 49153),
                     (POLICY_V1, 63, 49152), (POLICY_V1, 200, MAX_REQUEST_BYTES - 1),
                     ("", 64, MAX_REQUEST_BYTES), (" ", 64, MAX_REQUEST_BYTES),
                     (POLICY_V1, True, MAX_REQUEST_BYTES)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                RequestEnvelope(*args)
        with self.assertRaises(ValueError):
            with using_request_envelope(None):
                pass
        self.assertEqual(WIDE.limits(False), (MAX_QUESTIONS, MAX_REQUEST_BYTES, MAX_STATE_BYTES))
        self.assertEqual(WIDE.placement, "state")
        self.assertEqual(RequestEnvelope().placement, "instructions")

    def placed_payload(self, count):
        _src, state = sample_state()
        with using_request_envelope(WIDE):
            return encode_request(state, screens(count))

    def prepare(self, provider, payload):
        try:
            _body, questions, _headers, _timeout = provider._prepare(
                ProviderRequest(payload, 10.0))
        except ProviderError as exc:
            return exc.code
        return len(questions)

    def test_adapters_accept_raised_caps_only_for_placed_requests(self):
        placed_many = self.placed_payload(100)
        self.assertGreater(len(placed_many), MAX_REQUEST_BYTES)
        placed_few = self.placed_payload(10)
        _src, state = sample_state()
        unplaced = encode_request(state, screens(10))
        # A large unplaced envelope (b1 bytes, no policy in state).
        big_state = {**state, "pad": "a" * 9000}
        unplaced_big = encode_request(big_state, {"q": screens(1)["screen_0"]})
        self.assertLessEqual(len(unplaced_big), MAX_REQUEST_BYTES)
        # Policy-in-state with a big state too: over 24 KiB, 50 questions.
        with using_request_envelope(WIDE):
            placed_big = encode_request(big_state, screens(50))
        self.assertGreater(len(placed_big), MAX_REQUEST_BYTES)
        router_state = make_provider("openrouter", api_key=KEY, environ={},
                                     policy_placement="state")
        router_default = make_provider("openrouter", api_key=KEY, environ={})
        direct_state = make_provider("openai", api_key=KEY, environ={},
                                     policy_placement="state")
        self.assertEqual(self.prepare(router_state, placed_many), 100)
        self.assertEqual(self.prepare(router_state, placed_big), 50)
        self.assertEqual(self.prepare(router_state, placed_few), 10)
        self.assertEqual(self.prepare(router_state, unplaced), 10)
        for provider in (router_default, direct_state):
            with self.subTest(provider=type(provider).__name__,
                              placement=provider.policy_placement):
                self.assertEqual(self.prepare(provider, placed_many), "request_too_large")
                self.assertEqual(self.prepare(provider, placed_big), "request_too_large")
                self.assertEqual(self.prepare(provider, placed_few), 10)
        # An unplaced envelope never gets the raised caps, even on OpenRouter
        # with state placement: 65 questions are refused as before.
        many = _REQUEST_PREFIX + _json(state) + b',"questions":' + _json(small(65, placed=False)) + b"}"
        self.assertLessEqual(len(many), MAX_REQUEST_BYTES)
        self.assertEqual(self.prepare(router_state, many), "invalid_request")
        self.assertEqual(self.prepare(router_default, many), "invalid_request")
        # Over 200 questions or 48 KiB is refused under any placement.
        over = _REQUEST_PREFIX + b"{" + _json(POLICY_STATE_KEY) + b":" + _json(POLICY_V1) \
            + b"," + _json(state)[1:] + b',"questions":' + _json(small(201, placed=False)) + b"}"
        self.assertLessEqual(len(over), STATE_PLACEMENT_MAX_REQUEST_BYTES)
        self.assertEqual(self.prepare(router_state, over), "invalid_request")
        long = {f"q{i}": {"type": "noul", "instructions": "x" * 11000,
                          "criteria": {"true": "yes", "false": "no"}} for i in range(5)}
        heavy = over[:over.index(b',"questions":')] + b',"questions":' + _json(long) + b"}"
        self.assertGreater(len(heavy), STATE_PLACEMENT_MAX_REQUEST_BYTES)
        self.assertEqual(self.prepare(router_state, heavy), "request_too_large")
        self.assertEqual(router_state.wire_size(placed_many),
                         len(router_state.encode(placed_many, 200)[0]))

    def test_openrouter_round_trip_with_200_question_request(self):
        _src, state = sample_state()
        questions = small(200)
        script = ScriptedHTTPS([Reply(status=200, body=openrouter_body(answers_for(questions)),
                                      headers=[("Content-Type", "application/json")],
                                      close_after=True)],
                               clock=FakeClock(), host=openrouter.HOST)
        provider = openrouter.OpenRouterProvider(
            KEY, environ={}, exchange=script.exchange(openrouter.HOST, openrouter.PATH),
            policy_placement="state")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gateway = ValidatedGateway(provider, Path(tmp.name) / "receipts",
                                   retry_policy=RetryPolicy.none())
        self.addCleanup(gateway.close)
        self.assertEqual(gateway.request_limits, (200, 49152))
        with using_request_envelope(WIDE):
            answers = gateway.evaluate(state, questions,
                                       metadata={"sequence": 1, "phase": "test"})
        self.assertEqual(len(answers), 200)
        (request,) = script.requests
        sent = json.loads(request.body)
        self.assertEqual(list(sent)[:3], ["model", "state", "questions"])
        self.assertEqual(list(sent["state"])[0], POLICY_STATE_KEY)
        self.assertEqual(len(sent["questions"]), 200)
        self.assertTrue(all(not q["instructions"].startswith(POLICY_V1)
                            for q in sent["questions"].values()))
        self.assertLessEqual(len(request.body), openrouter.MAX_BODY_BYTES)

    def test_cli_passes_placement_to_the_openrouter_route(self):
        with clean_provider_env(OPENROUTER_API_KEY=KEY, OPENAI_API_KEY=KEY + "-direct"):
            for argv, placement, limits in (
                    ([], "instructions", (64, 24576)),
                    (["--policy-placement", "state"], "state", (200, 49152))):
                with self.subTest(argv=argv):
                    args = cli.parser().parse_args(["target.py", "--provider", "openrouter",
                                                    *argv])
                    self.assertEqual(args.policy_placement, placement)
                    provider = cli.make_provider(args)
                    self.assertEqual(provider.request_limits, limits)
            args = cli.parser().parse_args(["target.py", "--provider", "openai",
                                            "--policy-placement", "state"])
            self.assertEqual(cli.make_provider(args).request_limits, (64, 24576))


if __name__ == "__main__":
    unittest.main()
