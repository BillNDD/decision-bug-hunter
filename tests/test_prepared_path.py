"""The prepared path (A2) and the skipped answer re-validation (A3).

``Search.ask`` takes a fast path when ``type(gw) is ValidatedGateway`` and its
``evaluate`` was not replaced on the instance: the packer's wire goes to
``_evaluate_prepared`` as packed, the state digest is sliced from that wire,
and the engine checks only that the answers carry the names it kept. A batch
whose policy preamble the gateway would strip again (a doubled preamble under
state placement) takes the evaluate path instead, as does every other gateway.
These tests hold the two paths to the same bytes, keys, reports and receipts,
count the work the fast path must not do, and show that the skipped
re-validation refuses answers under other names.

Every scan and every gateway reads a pinned monotonic clock, a no-op sleep and
a seeded jitter source, so two runs of one oracle pair cannot differ by timing
or by retry waits. The scoped-v2-beta scans of the oracle end ``incomplete`` on
both paths, so their equality checks cover incomplete reports; the partial
batch test under scoped-v2-beta checks the scoped rows that fixture produces.
"""
from collections import Counter
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from decision_bug_hunter import engine, protocol, providers, questions
from decision_bug_hunter.core import Config
from decision_bug_hunter.protocol import (DEFAULT_REQUEST_ENVELOPE, QUESTION, ProviderError,
                                          RequestEnvelope, encode_request,
                                          using_request_envelope, validate_answer_objects)
from decision_bug_hunter.providers import ProviderResponse, ValidatedGateway
from decision_bug_hunter.questions import (CONTROL_ABSENT_WORDS, CONTROL_MUST_FALSE,
                                           CONTROL_MUST_TRUE, CONTROL_NAME,
                                           CONTROL_TOTAL_LINES, control_role, load_pack,
                                           policy)
from tests.support import FixtureProvider, is_control, scan, source
from tests.test_call_summary import FlakySynthetic, canonical, scrub
from tests.test_cost_accounting import PricedProvider
from tests.test_provider_boundary import SyntheticProvider

#: Planted bugs as (start, end) inclusive line ranges of ``source(8)``.
BUGS = ((2, 3), (6, 6))
PACK, _PACK_HASH = load_pack()
POLICY = policy(PACK, "v1")
ANSWERS = {"q": {"type": "noul", "noul": Decimal(".9")}}
QUESTIONS = {"q": deepcopy(QUESTION)}
#: One preamble (the packer strips it, the re-encode finds nothing to strip).
PREFIXED = {"q": {**deepcopy(QUESTION), "instructions": f"{POLICY} Is line 3 a bug?"}}
#: Two preambles: the packer strips one, a re-encode strips the second too.
DOUBLED = {"q": {**deepcopy(QUESTION), "instructions": f"{POLICY} {POLICY} Is line 3 a bug?"}}
#: Two questions, one doubled and one prefixed: one batch that restrips.
MIXED = {"q": DOUBLED["q"], "r": PREFIXED["q"]}
USAGE = {"input_tokens": 10, "output_tokens": 1}
SECRET = "SECRET-IN-QUESTION-SENTINEL"
STATE = {"text": "private-source-sentinel", "context_scope": "declared_standalone",
         "total_lines": 8, "source_sha256": "a" * 64}
ENVELOPES = (DEFAULT_REQUEST_ENVELOPE, RequestEnvelope(POLICY))
#: The separator between the state and the questions of every request wire.
SEPARATOR = b',"questions":'


def _prepared_request_batches(state, questions_, *, controls=False):
    """The packer's (batch, failure, wire, placed state) items, as the engine reads them."""
    return questions._prepared_request_batches(state, questions_, controls=controls)


def frozen():
    """Every reader of the clock sees 0.0: no deadline can pass under load."""
    return 0.0


def no_sleep(seconds):
    """A retry wait is only a wait on the frozen clock, so it takes no real time."""
    return None


def pinned(**options):
    """Gateway options that pin every source of timing and randomness."""
    return {"clock": frozen, "sleep": no_sleep, "rng": random.Random(0), **options}


@contextmanager
def pinned_clock():
    with patch.object(time, "monotonic", frozen):
        yield


class _Legacy(ValidatedGateway):
    """The same gateway, but not ``type(gw) is ValidatedGateway``: the old engine path."""


class Denormalized(SyntheticProvider):
    """The fixture judge with every probability and confidence written as 0.950 or 1.000.

    Each value keeps its exact number, so the gateway's validated objects are
    Decimals with extra digits. Re-validating them must return the same objects.
    """

    def decide(self, request):
        response = super().decide(request)

        def extra_digits(value):
            return value if isinstance(value, str) else Decimal(f"{float(value):.2f}0")

        answers = {}
        for qid, answer in response.answers.items():
            if answer["type"] == "noul":
                answers[qid] = {"type": "noul", "noul": extra_digits(answer["noul"])}
            else:
                answers[qid] = {**answer,
                                "confidence": extra_digits(answer["confidence"]),
                                "probabilities": {k: extra_digits(v) for k, v
                                                  in answer["probabilities"].items()}}
        return replace(response, answers=answers)


class PartialJudge(SyntheticProvider):
    """The fixture judge with one refusal and one defective choice in every request.

    The first non-control question of a request is refused (``question_refused``)
    and the first non-control choice answer names an option other than its
    argmax (``choice_argmax_mismatch``), so the engine keeps the rest of the
    batch as a ``validated_partial`` batch.
    """

    def __init__(self):
        super().__init__(fixture=FixtureProvider(BUGS))

    def decide(self, request):
        response = super().decide(request)
        requested = json.loads(request.payload)["questions"]
        plain_ids = [qid for qid in requested if not is_control(qid)]
        answers, scoped = dict(response.answers), {}
        if plain_ids:
            refused = plain_ids[0]
            answers.pop(refused)
            scoped[refused] = "question_refused"
        for qid in plain_ids[1:]:
            if requested[qid]["type"] == "choice":
                names = list(requested[qid]["criteria"])
                answers[qid] = {"type": "choice", "choice": names[1], "confidence": Decimal("1"),
                                "probabilities": {name: Decimal("1") if index == 0
                                                  else Decimal("0")
                                                  for index, name in enumerate(names)}}
                break
        return replace(response, answers=answers, scoped=scoped)


def typed(value):
    """Equality that tells Decimal('0.50') from 0.5 and keeps the key order."""
    if isinstance(value, dict):
        return ("dict", [(key, typed(item)) for key, item in value.items()])
    if isinstance(value, (list, tuple)):
        return (type(value).__name__, [typed(item) for item in value])
    return (type(value).__name__, repr(value))


def compact(batch):
    """The compact JSON of a question batch: the questions part of its wire."""
    return json.dumps(batch, ensure_ascii=False, separators=(",", ":")).encode()


#: The receipt fields the paths may differ in by time or identity alone.
RECEIPT_VOLATILE = frozenset({"elapsed_seconds", "timeout_seconds", "deadline_seconds",
                              "late", "logical_id"})


def receipt_scrub(value):
    """Drop only the timing and identity fields the oracle allows to differ.

    Unlike ``scrub``, the wait fields (``waited_seconds``, ``retry_after_seconds``)
    stay, so a retry that waits differently on the two paths is a difference.
    """
    if isinstance(value, dict):
        return {key: receipt_scrub(item) for key, item in value.items()
                if key not in RECEIPT_VOLATILE}
    if isinstance(value, list):
        return [receipt_scrub(item) for item in value]
    return value


def answers_for(wire):
    """A judge that answers every question of *wire* as a correct judge would.

    Controls get the value their role requires, every other noul gets .9 and
    every choice puts all its mass on its first option.
    """
    answers = {}
    for qid, question in json.loads(wire)["questions"].items():
        if question["type"] == "choice":
            names = list(question["criteria"])
            answers[qid] = {"type": "choice", "choice": names[0], "confidence": Decimal("1"),
                            "probabilities": {name: Decimal("1") if index == 0 else Decimal("0")
                                              for index, name in enumerate(names)}}
        elif is_control(qid):
            high = control_role(question) == "must_true"
            answers[qid] = {"type": "noul", "noul": Decimal("0.95" if high else "0.05")}
        else:
            answers[qid] = {"type": "noul", "noul": Decimal(".9")}
    return ProviderResponse(answers, USAGE)


@contextmanager
def instrumented():
    """Count the work the fast path must not do, around one scan.

    ``prepared``: calls to ``_evaluate_prepared``; ``key_mismatch``: keys that
    are not ``sha256(wire)``; ``encode``: every ``providers.encode_request``
    call, ``encode_in_prepared``: those made inside ``_evaluate_prepared``;
    ``snapshot_in_prepared``: ``protocol._snapshot`` calls made inside it;
    ``evaluate_from_ask``: ``_evaluate`` calls, the base route's re-encoding
    body, which only ``evaluate`` reaches; every request the base route sends
    is one of them. The class-level ``evaluate`` is left unpatched, so a
    replaced one still reaches the engine's base route (see
    ``test_class_evaluate_hook_still_receives_every_call``).
    ``loads_from_ask``, ``validate_from_ask`` and
    ``questions_validate_from_ask``: ``json.loads``, ``validate_answer_objects``
    and ``validate_questions`` called directly by ``Search.ask``;
    ``overflow_encode``: ``encode_request`` called directly by ``Search.ask``;
    ``fallback``: the state digest decoded its wire instead of slicing it.
    """
    counts = Counter()
    active = [0]
    real = {"prepared": ValidatedGateway._evaluate_prepared,
            "_evaluate": ValidatedGateway._evaluate,
            "encode": providers.encode_request, "snapshot": protocol._snapshot,
            "loads": json.loads, "validate": engine.validate_answer_objects,
            "fallback": engine._decoded_state_digest, "engine_encode": engine.encode_request,
            "protocol_questions": protocol.validate_questions,
            "questions": questions.validate_questions}

    def prepared(self, wire, key, *, metadata):
        counts["prepared"] += 1
        if key != hashlib.sha256(wire).hexdigest():
            counts["key_mismatch"] += 1
        active[0] += 1
        try:
            return real["prepared"](self, wire, key, metadata=metadata)
        finally:
            active[0] -= 1

    def base_route(self, state, questions_, *, metadata):
        counts["evaluate_from_ask"] += 1
        return real["_evaluate"](self, state, questions_, metadata=metadata)

    def encode(*args, **kwargs):
        counts["encode"] += 1
        if active[0]:
            counts["encode_in_prepared"] += 1
        return real["encode"](*args, **kwargs)

    def snapshot(value, depth=0):
        if active[0]:
            counts["snapshot_in_prepared"] += 1
        return real["snapshot"](value, depth)

    def loads(text, *args, **kwargs):
        if sys._getframe(1).f_code.co_name == "ask":
            counts["loads_from_ask"] += 1
        return real["loads"](text, *args, **kwargs)

    def validate(*args, **kwargs):
        if sys._getframe(1).f_code.co_name == "ask":
            counts["validate_from_ask"] += 1
        return real["validate"](*args, **kwargs)

    def fallback(wire):
        counts["fallback"] += 1
        return real["fallback"](wire)

    def engine_encode(*args, **kwargs):
        if sys._getframe(1).f_code.co_name == "ask":
            counts["overflow_encode"] += 1
        return real["engine_encode"](*args, **kwargs)

    def validator(name):
        def check(*args, **kwargs):
            if sys._getframe(1).f_code.co_name == "ask":
                counts["questions_validate_from_ask"] += 1
            return real[name](*args, **kwargs)
        return check

    with ExitStack() as stack:
        stack.enter_context(patch.object(ValidatedGateway, "_evaluate_prepared", prepared))
        stack.enter_context(patch.object(ValidatedGateway, "_evaluate", base_route))
        stack.enter_context(patch.object(providers, "encode_request", encode))
        stack.enter_context(patch.object(protocol, "_snapshot", snapshot))
        stack.enter_context(patch.object(json, "loads", loads))
        stack.enter_context(patch.object(engine, "validate_answer_objects", validate))
        stack.enter_context(patch.object(engine, "_decoded_state_digest", fallback))
        stack.enter_context(patch.object(engine, "encode_request", engine_encode))
        stack.enter_context(patch.object(protocol, "validate_questions",
                                         validator("protocol_questions")))
        stack.enter_context(patch.object(questions, "validate_questions",
                                         validator("questions")))
        yield counts


@contextmanager
def verify_rewritten(rewrite):
    """Rewrite the instructions of every ``verify`` question: ``rewrite(pack, text)``."""
    noul = engine.noul

    def rewritten(pack, kind, span, **values):
        question = noul(pack, kind, span, **values)
        if kind != "verify":
            return question
        return {**question, "instructions": rewrite(pack, question["instructions"])}

    with patch.object(engine, "noul", rewritten):
        yield


@contextmanager
def doubled_verify(counts):
    """Give every ``verify`` question a second copy of the policy preamble.

    Under state placement the packer strips one copy and the gateway's
    re-encode would strip the other, so these batches must take the evaluate
    route. ``counts["doubled"]`` counts the questions made this way.
    """
    def doubled(pack, text):
        counts["doubled"] += 1
        return policy(pack) + " " + text

    with verify_rewritten(doubled):
        yield


@contextmanager
def bare_verify():
    """Make every ``verify`` question start with the policy text and no space after it.

    That text starts with the preamble but is not one: the packer does not strip
    it, a re-encode does not either, so these batches stay on the fast path.
    """
    def bare(pack, text):
        return text.replace(policy(pack) + " ", policy(pack), 1)

    with verify_rewritten(bare):
        yield


@contextmanager
def oversized_verify():
    """Make the first ``verify`` question too large for any request.

    Validation accepts 12000 control characters, and the JSON escapes each one
    to six bytes, so the question fits neither envelope: the packer yields it
    as a singleton failure and the scan goes on with the other questions.
    """
    noul = engine.noul
    made = []

    def oversized(pack, kind, span, **values):
        question = noul(pack, kind, span, **values)
        if kind != "verify" or made:
            return question
        made.append(question)
        return {**question, "instructions": "\x01" * 12000}

    with patch.object(engine, "noul", oversized):
        yield


@contextmanager
def leaked_verify():
    """Append the planted credential to the instructions of every ``verify`` question."""
    with verify_rewritten(lambda pack, text: f"{text} {SECRET}"):
        yield


def watch(gateway):
    """Replace ``evaluate`` on one gateway instance with a recording wrapper.

    Returns the list the wrapper appends each call's metadata to.
    """
    calls = []
    original = gateway.evaluate

    def evaluate(state, questions_, *, metadata):
        calls.append(metadata)
        return original(state, questions_, metadata=metadata)

    gateway.evaluate = evaluate
    return calls


@contextmanager
def misnamed_answers(*, drop=False, extra=False):
    """The gateway hands the engine answers under names it did not ask (A3).

    ``drop`` removes the first answer and ``extra`` adds one under a name no
    question has. Both paths receive the same answers, so both must refuse them.
    """
    dispatch = ValidatedGateway._dispatch

    def wrapped(self, wire, expected, key, meta):
        answers = dispatch(self, wire, expected, key, meta)
        if drop:
            answers = dict(list(answers.items())[1:])
        if extra:
            answers = {**answers, "ghost": {"type": "noul", "noul": Decimal("0.5")}}
        return answers

    with patch.object(ValidatedGateway, "_dispatch", wrapped):
        yield


class PreparedPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def scan_once(self, gateway_class, label, make_provider=None, *, doubled=False,
                  text=None, extra=None, gateway_options=None, hook=None, **options):
        """(scrubbed report, sorted scrubbed receipts, counts, provider payloads) of one scan.

        ``text`` is the text of every source line, ``extra`` a context manager
        factory entered around the scan, ``hook`` a function given the gateway
        before the scan, and ``gateway_options`` extra options of the gateway
        (the clock and sleep are pinned either way).
        """
        provider = (make_provider() if make_provider is not None
                    else SyntheticProvider(fixture=FixtureProvider(BUGS)))
        receipts = self.root / label
        with pinned_clock(), instrumented() as counts, ExitStack() as stack:
            if doubled:
                stack.enter_context(doubled_verify(counts))
            if extra is not None:
                stack.enter_context(extra())
            with gateway_class(provider, receipts, **pinned(**(gateway_options or {}))) as gateway:
                if hook is not None:
                    hook(gateway)
                report = scan(source(8, text), gateway, Config(whole_file=False, **options))
        saved = [receipt_scrub(json.loads(path.read_text(encoding="utf-8")))
                 for path in receipts.glob("*.json")]
        payloads = [request.payload for request in provider.requests]
        return scrub(report), sorted(canonical(item) for item in saved), counts, payloads

    def assert_prepared_work(self, counts):
        """The fast path encodes nothing, decodes nothing and re-validates nothing."""
        self.assertGreater(counts["prepared"], 0)
        self.assertEqual(counts["encode_in_prepared"], 0)
        self.assertEqual(counts["snapshot_in_prepared"], 0)
        self.assertEqual(counts["encode"], 0)
        self.assertEqual(counts["evaluate_from_ask"], 0)
        self.assertEqual(counts["loads_from_ask"], 0)
        self.assertEqual(counts["validate_from_ask"], 0)
        self.assertEqual(counts["questions_validate_from_ask"], 0)
        self.assertEqual(counts["fallback"], 0)
        self.assertEqual(counts["key_mismatch"], 0)

    # (a) legacy-path oracle, (b) call counts, (c) digest slice ----------------
    def test_prepared_path_matches_legacy_path_and_does_less_work(self):
        for placement in ("instructions", "state"):
            for search_policy in ("legacy-v1", "scoped-v2-beta"):
                for canaries in ("on", "off"):
                    options = {"policy_placement": placement, "search_policy": search_policy,
                               "canaries": canaries}
                    label = f"{placement}-{search_policy}-{canaries}"
                    with self.subTest(**options):
                        fast = self.scan_once(ValidatedGateway, f"fast-{label}", **options)
                        legacy = self.scan_once(_Legacy, f"legacy-{label}", **options)
                        self.assertTrue(fast[1], "the scan must persist receipts")
                        self.assertEqual(fast[0], legacy[0])
                        self.assertEqual(fast[1], legacy[1])
                        self.assertEqual(fast[3], legacy[3])
                        self.assert_prepared_work(fast[2])
                        # The old path encodes once per evaluate and re-validates
                        # the answers it kept, from the engine itself.
                        self.assertEqual(legacy[2]["encode"], fast[2]["prepared"])
                        self.assertEqual(legacy[2]["evaluate_from_ask"], fast[2]["prepared"])
                        self.assertGreater(legacy[2]["loads_from_ask"], 0)
                        self.assertGreater(legacy[2]["validate_from_ask"], 0)

    def test_doubled_preamble_scan_matches_the_legacy_path(self):
        """A doubled preamble under state placement, in whole scans and both overflow modes.

        Only ``legacy-v1`` is scanned here. Under ``scoped-v2-beta`` the verify
        questions are built by the scoped path without the policy preamble, so
        a doubled preamble cannot be injected there; scoped scans are covered
        by ``test_prepared_path_matches_legacy_path_and_does_less_work``.

        The doubled batches go down the evaluate route, which is the base route,
        and the others take the prepared path. Both gateways send the same
        payloads and keep the same receipts and reports.
        """
        search_policy = "legacy-v1"
        for canaries in ("on", "off"):
            for overflow in (False, True):
                options = {"policy_placement": "state", "search_policy": search_policy,
                           "canaries": canaries}
                label = f"doubled-{search_policy}-{canaries}-{overflow}"
                limit = (patch.object(engine, "MAX_PREPARED_WIRE_BYTES", 1) if overflow
                         else nullcontext())
                with self.subTest(**options, overflow=overflow), limit:
                    fast = self.scan_once(ValidatedGateway, f"fast-{label}", doubled=True,
                                          **options)
                    legacy = self.scan_once(_Legacy, f"legacy-{label}", doubled=True,
                                            **options)
                    self.assertTrue(fast[1], "the scan must persist receipts")
                    self.assertEqual(fast[0], legacy[0])
                    self.assertEqual(fast[1], legacy[1])
                    self.assertEqual(fast[3], legacy[3])
                    counts = fast[2]
                    self.assertGreater(counts["doubled"], 0)
                    self.assertGreater(counts["evaluate_from_ask"], 0)
                    self.assertGreater(counts["prepared"], 0)
                    self.assertEqual(legacy[2]["prepared"], 0)
                    self.assertEqual(counts["evaluate_from_ask"] + counts["prepared"],
                                     legacy[2]["evaluate_from_ask"])
                    self.assertEqual(counts["encode_in_prepared"], 0)
                    self.assertEqual(counts["snapshot_in_prepared"], 0)
                    self.assertEqual(counts["key_mismatch"], 0)
                    self.assertEqual(counts["fallback"], 0)
                    # The restripping batches also skip re-validation: their answers
                    # come from the gateway's own validation (A3 on every route).
                    self.assertEqual(counts["validate_from_ask"], 0)
                    self.assertEqual(counts["questions_validate_from_ask"], 0)
                    if overflow:
                        self.assertGreater(counts["overflow_encode"], 0)

    def test_state_digest_slice_is_the_decoded_digest(self):
        for envelope in ENVELOPES:
            for controls in (False, True):
                with self.subTest(placed=envelope.policy is not None, controls=controls):
                    checked = 0
                    with using_request_envelope(envelope):
                        for batch, failure, wire, _state in _prepared_request_batches(
                                STATE, PREFIXED, controls=controls):
                            if wire is None:
                                self.assertIsNotNone(failure)
                                continue
                            with patch.object(engine, "_decoded_state_digest",
                                              wraps=engine._decoded_state_digest) as fallback:
                                self.assertEqual(engine._wire_state_digest(wire, compact(batch)),
                                                 engine.digest(json.loads(wire)["state"]))
                                self.assertEqual(fallback.call_count, 0)
                            checked += 1
                    self.assertGreater(checked, 0)

    def test_state_digest_falls_back_to_decoding_on_each_layout_mismatch(self):
        """Every layout the slice does not match decodes the wire, and only those.

        Each candidate is a valid request (its decoded digest is defined), except
        the missing closing brace, which is a caller's questions bytes without
        their final brace. Every mismatch is counted as one fallback.
        """
        (_batch, _failure, wire, _state), = _prepared_request_batches(STATE, QUESTIONS)
        raw = compact(QUESTIONS)
        body = wire[len(protocol.REQUEST_PREFIX):len(wire) - 1 - len(raw) - len(SEPARATOR)]
        self.assertEqual(wire, protocol.REQUEST_PREFIX + body + SEPARATOR + raw + b"}")
        cases = {
            "exact layout": (wire, raw, False),
            "questions bytes changed at the same length":
                (wire, raw[:-2] + bytes([raw[-2] ^ 1]) + raw[-1:], True),
            "wrong prefix": (b"{ " + wire[1:], raw, True),
            "separator replaced at the same length":
                (protocol.REQUEST_PREFIX + body + b',"qwestions":' + raw + b"}", raw, True),
            "missing closing brace": (wire, raw[:-1], True),
            "trailing byte": (wire + b"\n", raw, True),
        }
        expected = engine.digest(json.loads(wire)["state"])
        for name, (candidate, questions_raw, falls_back) in cases.items():
            with self.subTest(name), patch.object(
                    engine, "_decoded_state_digest",
                    wraps=engine._decoded_state_digest) as fallback:
                self.assertEqual(engine._wire_state_digest(candidate, questions_raw), expected)
                self.assertEqual(fallback.call_count, 1 if falls_back else 0)

    # (d) overflow -------------------------------------------------------------
    def test_overflow_wires_take_the_prepared_path_and_match(self):
        for placement in ("instructions", "state"):
            for search_policy in ("legacy-v1", "scoped-v2-beta"):
                for canaries in ("on", "off"):
                    options = {"policy_placement": placement, "search_policy": search_policy,
                               "canaries": canaries}
                    label = f"{placement}-{search_policy}-{canaries}"
                    with self.subTest(**options):
                        normal = self.scan_once(ValidatedGateway, f"normal-{label}", **options)
                        with patch.object(engine, "MAX_PREPARED_WIRE_BYTES", 1):
                            overflow = self.scan_once(ValidatedGateway, f"overflow-{label}",
                                                      **options)
                            legacy = self.scan_once(_Legacy, f"overflow-legacy-{label}",
                                                    **options)
                        self.assertEqual(overflow[0], normal[0])
                        self.assertEqual(overflow[1], normal[1])
                        self.assertEqual(overflow[0], legacy[0])
                        self.assertEqual(overflow[1], legacy[1])
                        self.assertEqual(overflow[3], legacy[3])
                        counts = overflow[2]
                        self.assertGreater(counts["overflow_encode"], 0)
                        self.assertEqual(counts["encode_in_prepared"], 0)
                        self.assertEqual(counts["encode"], 0)
                        self.assertEqual(counts["fallback"], 0)
                        self.assertEqual(counts["key_mismatch"], 0)
                        self.assertEqual(counts["loads_from_ask"], 0)
                        self.assertEqual(counts["validate_from_ask"], 0)
                        self.assertEqual(counts["questions_validate_from_ask"], 0)

    # The gateway answers are the engine's answers (A3) ----------------------
    def test_gateway_answers_are_fixed_points_of_revalidation(self):
        questions_ = {"q": deepcopy(QUESTION),
                      "c": {"type": "choice", "instructions": "Which option applies?",
                            "criteria": {"a": "first option", "b": "second option"}}}
        answers = {"q": {"type": "noul", "noul": Decimal("0.500")},
                   "c": {"type": "choice", "choice": "a", "confidence": 0.5,
                         "probabilities": {"a": Decimal("1.000"), "b": 0.0}}}
        provider = SyntheticProvider(ProviderResponse(answers, USAGE))
        with ValidatedGateway(provider, self.root / "fixed", **pinned()) as gateway:
            out = gateway.evaluate(STATE, questions_, metadata={"sequence": 1})
        self.assertEqual(out["c"]["probabilities"]["b"], Decimal("0.0"))
        self.assertEqual(typed(validate_answer_objects(out, questions_)), typed(out))

    def test_restripping_batch_answers_are_fixed_points_of_revalidation(self):
        """A doubled preamble takes the evaluate route; its answers are fixed points (A3)."""
        questions_ = {"q": deepcopy(DOUBLED["q"]),
                      "c": {"type": "choice", "instructions": "Which option applies?",
                            "criteria": {"a": "first option", "b": "second option"}}}
        answers = {"q": {"type": "noul", "noul": Decimal("0.500")},
                   "c": {"type": "choice", "choice": "a", "confidence": 0.5,
                         "probabilities": {"a": Decimal("1.000"), "b": 0.0}}}
        provider = SyntheticProvider(ProviderResponse(answers, USAGE))
        with using_request_envelope(ENVELOPES[1]):
            with ValidatedGateway(provider, self.root / "restrip", **pinned()) as gateway:
                out = gateway.evaluate(STATE, questions_, metadata={"sequence": 1})
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(typed(validate_answer_objects(out, questions_)), typed(out))

    def test_denormalized_probabilities_match_across_paths(self):
        fast = self.scan_once(ValidatedGateway, "denorm-fast",
                              lambda: Denormalized(fixture=FixtureProvider(BUGS)),
                              search_policy="legacy-v1")
        legacy = self.scan_once(_Legacy, "denorm-legacy",
                                lambda: Denormalized(fixture=FixtureProvider(BUGS)),
                                search_policy="legacy-v1")
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        self.assert_prepared_work(fast[2])

    def test_a3_refuses_answers_under_other_names_on_the_fast_path(self):
        """A missing or an extra name is ``response_schema`` on both paths (A3)."""
        for drop, extra in ((True, False), (False, True)):
            label = "drop" if drop else "extra"
            with self.subTest(case=label), misnamed_answers(drop=drop, extra=extra):
                fast = self.scan_once(ValidatedGateway, f"a3-fast-{label}")
                legacy = self.scan_once(_Legacy, f"a3-legacy-{label}")
            self.assertIn("response_schema", json.dumps(fast[0], default=str))
            self.assertEqual(fast[0], legacy[0])
            self.assertEqual(fast[1], legacy[1])
            self.assertEqual(fast[2]["validate_from_ask"], 0)
            self.assertEqual(fast[2]["encode_in_prepared"], 0)

    def test_validated_partial_batches_match_across_paths(self):
        """A3 on batches with a refusal and a defective choice (validated_partial)."""
        fast = self.scan_once(ValidatedGateway, "partial-fast", PartialJudge,
                              search_policy="legacy-v1")
        legacy = self.scan_once(_Legacy, "partial-legacy", PartialJudge,
                                search_policy="legacy-v1")
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        self.assertIn("validated_partial", json.dumps(fast[0], default=str))
        self.assertIn("question_refused", json.dumps(fast[0], default=str))
        self.assertGreater(fast[2]["prepared"], 0)
        self.assertEqual(fast[2]["validate_from_ask"], 0)
        self.assertEqual(fast[2]["fallback"], 0)

    def in_thread(self, call, seconds=5):
        """The outcome of *call* run on a helper thread, or ``("hung", None)``.

        A call that blocks where it should refuse leaves the thread unfinished,
        so the assertion fails within *seconds* instead of hanging the module.
        """
        box = []

        def run():
            try:
                box.append(self.outcome(call))
            except BaseException as exc:  # reported as the outcome, never lost
                box.append(("raised", type(exc).__name__))

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(seconds)
        return box[0] if box else ("hung", None)

    def test_prepared_path_refuses_a_busy_gateway_and_recovers(self):
        """The fast path takes the same non-blocking call lock as ``evaluate``."""
        (_batch, _failure, wire, _state), = _prepared_request_batches(STATE, QUESTIONS)
        key = hashlib.sha256(wire).hexdigest()
        provider = SyntheticProvider(ProviderResponse(ANSWERS, USAGE))
        with ValidatedGateway(provider, self.root / "busy", **pinned()) as gateway:
            with gateway._call_lock:
                busy = self.in_thread(
                    lambda: gateway._evaluate_prepared(wire, key, metadata={"sequence": 1}))
            self.assertEqual(busy, ("error", "transport_failed"))
            self.assertEqual(provider.requests, [])
            done = self.outcome(
                lambda: gateway._evaluate_prepared(wire, key, metadata={"sequence": 2}))
        self.assertEqual(done[0], "ok")
        self.assertEqual(len(provider.requests), 1)

    # (e) error parity between the paths --------------------------------------
    def outcome(self, call):
        try:
            return "ok", typed(call())
        except ProviderError as exc:
            return "error", exc.code

    def receipts(self, label):
        directory = self.root / label
        if not directory.exists():
            return []
        return sorted(canonical(receipt_scrub(json.loads(path.read_text(encoding="utf-8"))))
                      for path in directory.glob("*.json"))

    def paths_agree(self, label, wire, metadata, make_provider, **gateway_options):
        """One wire down both paths: the outcome, provider payloads and receipts agree.

        ``make_provider(wire)`` builds a provider for one wire. The legacy path
        gets the decoded wire, as the engine's fallback hands it over; the fast
        path gets the same bytes as packed. The caller holds the placement
        envelope. Returns the outcome both paths gave.
        """
        decoded = json.loads(wire)
        key = hashlib.sha256(wire).hexdigest()
        legacy_provider, fast_provider = make_provider(wire), make_provider(wire)
        with _Legacy(legacy_provider, self.root / f"{label}-legacy",
                     **pinned(**gateway_options)) as old:
            legacy = self.outcome(lambda: old.evaluate(decoded["state"], decoded["questions"],
                                                       metadata=metadata))
        with ValidatedGateway(fast_provider, self.root / f"{label}-fast",
                              **pinned(**gateway_options)) as new:
            fast = self.outcome(lambda: new._evaluate_prepared(wire, key, metadata=metadata))
        self.assertEqual(fast, legacy)
        self.assertEqual([request.payload for request in fast_provider.requests],
                         [request.payload for request in legacy_provider.requests])
        self.assertEqual(self.receipts(f"{label}-fast"), self.receipts(f"{label}-legacy"))
        return legacy

    def evaluate_route(self, label, wire, metadata, make_provider):
        """(outcome, payloads) of the evaluate route for *wire*: the decoded request, re-encoded.

        This is the route ``Search.ask`` takes for a batch the gateway would
        strip again, and the one the base engine takes for every batch.
        """
        decoded = json.loads(wire)
        provider = make_provider(wire)
        with _Legacy(provider, self.root / f"{label}-evaluate", **pinned()) as gateway:
            result = self.outcome(lambda: gateway.evaluate(
                decoded["state"], decoded["questions"], metadata=metadata))
        return result, [request.payload for request in provider.requests]

    def packed_wires(self, envelope, state, questions_, controls):
        """(batch, wire, overflow wire) for every fitting batch, under *envelope*."""
        with using_request_envelope(envelope):
            return [(batch, wire, encode_request(placed, batch))
                    for batch, _failure, wire, placed
                    in _prepared_request_batches(state, questions_, controls=controls)
                    if wire is not None]

    def test_packed_wires_match_the_base_path_under_both_placements(self):
        """Each packed request, normal and overflow, runs the same on both paths.

        The one exception is a batch that restrips under state placement (a
        doubled preamble, alone or beside a prefixed one): the packer's bytes
        differ from a re-encode, so the engine sends such a batch down the
        evaluate path instead. For those wires the evaluate route sends the
        re-encode of the decoded request, as the base route does. A normal
        wire differs from its re-encode; an overflow wire is already one.
        """
        cases = {"plain": QUESTIONS, "prefixed": PREFIXED, "doubled": DOUBLED, "mixed": MIXED}
        count = 0
        for envelope in ENVELOPES:
            for controls in (False, True):
                for name, questions_ in cases.items():
                    with self.subTest(policy=envelope.policy is not None,
                                      controls=controls, case=name):
                        for batch, wire, overflow in self.packed_wires(
                                envelope, STATE, questions_, controls):
                            with using_request_envelope(envelope):
                                restrips = engine._policy_restrips(batch)
                            if restrips:
                                self.assertIn(name, ("doubled", "mixed"))
                                self.assertIsNotNone(envelope.policy)
                                self.assertNotEqual(overflow, wire)
                                for kind, candidate in (("normal", wire),
                                                        ("overflow", overflow)):
                                    count += 1
                                    with using_request_envelope(envelope):
                                        result, payloads = self.evaluate_route(
                                            f"{name}-{controls}-{kind}-{count}", candidate,
                                            {"sequence": 1}, answers_wire)
                                        decoded = json.loads(candidate)
                                        sent = encode_request(decoded["state"],
                                                              decoded["questions"])
                                    self.assertEqual(result[0], "ok")
                                    self.assertEqual(payloads, [sent])
                                    if kind == "normal":
                                        self.assertNotEqual(sent, candidate)
                                    else:
                                        self.assertEqual(sent, candidate)
                                continue
                            self.assertEqual(overflow, wire)
                            for kind, candidate in (("normal", wire), ("overflow", overflow)):
                                count += 1
                                with using_request_envelope(envelope):
                                    outcome = self.paths_agree(
                                        f"{name}-{controls}-{kind}-{count}", candidate,
                                        {"sequence": 1}, answers_wire)
                                self.assertEqual(outcome[0], "ok")
        self.assertGreater(count, 0)

    def assert_error_parity(self, label, state, questions_, metadata, make_provider,
                            **gateway_options):
        """Each envelope and control setting: both paths agree on every packed wire.

        Returns the outcomes for the default envelope without controls.
        """
        outcomes = []
        for envelope in ENVELOPES:
            for controls in (False, True):
                for index, (_batch, wire, _overflow) in enumerate(
                        self.packed_wires(envelope, state, questions_, controls)):
                    with using_request_envelope(envelope):
                        outcome = self.paths_agree(
                            f"{label}-{envelope.policy is not None}-{controls}-{index}",
                            wire, metadata, make_provider, **gateway_options)
                    if envelope is DEFAULT_REQUEST_ENVELOPE and not controls:
                        outcomes.append(outcome)
        return outcomes

    def test_invalid_metadata_fails_identically(self):
        outcomes = self.assert_error_parity("metadata", STATE, QUESTIONS, {"unknown": 1},
                                            answers_wire)
        self.assertEqual(outcomes, [("error", "invalid_metadata")])

    def test_invalid_metadata_is_refused_before_a_credential_is_checked(self):
        """Metadata is validated before the state is checked for credentials, on both paths.

        The legacy path runs ``_metadata`` before ``check_sensitive``. A state that
        holds a credential with invalid metadata must therefore give
        ``invalid_metadata`` and send nothing, not ``sensitive_input``.
        """
        secret_state = {**STATE, "text": f"contains {SECRET}"}
        made = []

        def make(wire):
            made.append(SyntheticProvider(answers_for(wire), secret=SECRET))
            return made[-1]

        outcomes = self.assert_error_parity("metadata-and-secret", secret_state, QUESTIONS,
                                            {"unknown": 1}, make)
        self.assertEqual(outcomes, [("error", "invalid_metadata")])
        self.assertTrue(made)
        self.assertTrue(all(not provider.requests for provider in made))

    def test_credential_in_metadata_fails_identically(self):
        """The metadata is checked for credentials too, as the state and questions are."""
        outcomes = self.assert_error_parity(
            "metadata-secret", STATE, QUESTIONS, {"sequence": 1, "window_id": f"W-{SECRET}"},
            lambda wire: SyntheticProvider(answers_for(wire), secret=SECRET))
        self.assertEqual(outcomes, [("error", "sensitive_input")])

    def test_credential_in_state_fails_identically(self):
        secret_state = {**STATE, "text": f"contains {SECRET}"}
        outcomes = self.assert_error_parity(
            "state-secret", secret_state, QUESTIONS, {"sequence": 1},
            lambda wire: SyntheticProvider(answers_for(wire), secret=SECRET))
        self.assertEqual(outcomes, [("error", "sensitive_input")])

    def test_credential_in_question_text_fails_identically(self):
        questions_ = {"q": {**deepcopy(QUESTION), "instructions": f"Is {SECRET} here?"}}
        outcomes = self.assert_error_parity(
            "question-secret", STATE, questions_, {"sequence": 1},
            lambda wire: SyntheticProvider(answers_for(wire), secret=SECRET))
        self.assertEqual(outcomes, [("error", "sensitive_input")])

    def test_cost_budget_refusal_fails_identically(self):
        outcomes = self.assert_error_parity(
            "cost", STATE, QUESTIONS, {"sequence": 1}, lambda wire: PricedProvider(),
            max_cost=Decimal("0.0000001"))
        self.assertEqual(outcomes, [("error", "cost_budget_exhausted")])

    def test_denormalized_gateway_answers_fail_identically_or_match(self):
        questions_ = {"q": deepcopy(QUESTION),
                      "c": {"type": "choice", "instructions": "Which option applies?",
                            "criteria": {"a": "first option", "b": "second option"}}}
        hand = {"q": {"type": "noul", "noul": Decimal("0.500")},
                "c": {"type": "choice", "choice": "a", "confidence": 1,
                      "probabilities": {"a": Decimal("1.000"), "b": Decimal("0.00")}}}
        outcomes = self.assert_error_parity(
            "denormalized", STATE, questions_, {"sequence": 1},
            lambda wire: SyntheticProvider(ProviderResponse(
                {**answers_for(wire).answers, **hand}, USAGE)))
        self.assertEqual(outcomes[0][0], "ok")

    def test_doubled_preamble_is_the_only_case_the_engine_routes_to_evaluate(self):
        """The routing predicate: only a restripping batch under state placement.

        ``bare`` starts with the policy text and no space after it: that is not
        the preamble, so it stays on the fast path (R2-A3).
        """
        bare = {"q": {**deepcopy(QUESTION), "instructions": f"{POLICY}Is line 3 a bug?"}}
        for envelope in ENVELOPES:
            for name, questions_ in (("plain", QUESTIONS), ("prefixed", PREFIXED),
                                     ("doubled", DOUBLED), ("mixed", MIXED), ("bare", bare)):
                with self.subTest(policy=envelope.policy is not None, case=name):
                    with using_request_envelope(envelope):
                        batches = [batch for batch, _f, wire, _s in
                                   _prepared_request_batches(STATE, questions_) if wire]
                        flagged = [engine._policy_restrips(batch) for batch in batches]
                    expected = envelope.policy is not None and name in ("doubled", "mixed")
                    self.assertEqual(flagged, [expected])

    def test_any_restripping_question_routes_the_whole_batch_to_evaluate(self):
        """One doubled question in a batch is enough, whatever its neighbours hold (R3-A6)."""
        mixed_plain = {"a": DOUBLED["q"], "b": QUESTION}
        for name, questions_, expected in (("mixed", MIXED, True),
                                           ("mixed-plain", mixed_plain, True)):
            with self.subTest(case=name):
                with using_request_envelope(ENVELOPES[1]):
                    batches = [batch for batch, _f, wire, _s in
                               _prepared_request_batches(STATE, questions_) if wire]
                    self.assertEqual(len(batches), 1)
                    self.assertEqual([engine._policy_restrips(batch) for batch in batches],
                                     [expected])
        with using_request_envelope(DEFAULT_REQUEST_ENVELOPE):
            batches = [batch for batch, _f, wire, _s in
                       _prepared_request_batches(STATE, MIXED) if wire]
            self.assertEqual([engine._policy_restrips(batch) for batch in batches], [False])

    def test_control_questions_pass_validation(self):
        """Controls skip the base encode's validation on the fast path, so their texts must pass it.

        Every must-false word and the total_lines form are validated under both
        envelopes. The control texts are constants, so one check per text and
        placement is the proof; there is no runtime validation on the controlled
        request path (R3-E5).
        """
        words = CONTROL_ABSENT_WORDS
        # A source text that holds the first k words makes word k the first absent one.
        word_states = [{**STATE, "text": " ".join(words[:k]) or STATE["text"]}
                       for k in range(len(words))]
        total_values = (1, 2, 999999, 10 ** 10 - 1)
        line_states = [{**STATE, "text": " ".join(words), "total_lines": total_lines}
                       for total_lines in total_values]
        collected, line_texts = set(), []
        for state in word_states + line_states:
            for envelope in ENVELOPES:
                with using_request_envelope(envelope):
                    cap = envelope.limits(True)[0]
                    for batch, _failure, wire, _placed in _prepared_request_batches(
                            state, QUESTIONS, controls=True):
                        if wire is None:
                            continue
                        sent = json.loads(wire)["questions"]
                        if envelope.policy is not None:
                            # Under state placement the questions go out as batched.
                            self.assertEqual(sent, batch)
                        for qid, question in sent.items():
                            if not CONTROL_NAME.fullmatch(qid):
                                continue
                            protocol.validate_questions({qid: question}, max_questions=cap)
                            text = question["instructions"]
                            collected.add(text)
                            if state in line_states and text != CONTROL_MUST_TRUE:
                                line_texts.append((state["total_lines"], text))
        self.assertEqual(len(line_texts), len(total_values) * len(ENVELOPES))
        for total_lines, text in line_texts:
            self.assertIn(text, (CONTROL_TOTAL_LINES.format(n=total_lines + 1),
                                 CONTROL_TOTAL_LINES.format(n=total_lines - 1)))
        self.assertTrue(any(text.startswith("Does state.total_lines equal") for text in collected))
        self.assertEqual(
            collected,
            {CONTROL_MUST_TRUE}
            | {CONTROL_MUST_FALSE.format(word=word) for word in words}
            | {text for _n, text in line_texts})

    def test_public_packer_stays_a_three_tuple(self):
        """``prepared_question_batches`` keeps its 3-tuples; the private form adds the state."""
        for envelope in ENVELOPES:
            for controls in (False, True):
                with using_request_envelope(envelope):
                    public = list(questions.prepared_question_batches(
                        STATE, QUESTIONS, controls=controls))
                    private = list(_prepared_request_batches(STATE, QUESTIONS,
                                                             controls=controls))
                    self.assertTrue(public)
                    self.assertEqual(public, [(b, f, w) for b, f, w, _s in private])
                    self.assertTrue(all(type(item) is tuple and len(item) == 3
                                        for item in public))

    # Scan-level error parity: report (trace rows included), receipts, payloads ----
    def assert_scan_parity(self, label, make_provider, code, *, text=None, extra=None,
                           gateway_options=None):
        options = {"search_policy": "legacy-v1"}
        fast = self.scan_once(ValidatedGateway, f"{label}-fast", make_provider, text=text,
                              extra=extra, gateway_options=gateway_options, **options)
        legacy = self.scan_once(_Legacy, f"{label}-legacy", make_provider, text=text,
                                extra=extra, gateway_options=gateway_options, **options)
        self.assertIn(code, json.dumps(fast[0], default=str))
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        self.assertGreater(fast[2]["prepared"], 0)

    def test_credential_in_source_fails_identically_in_scans(self):
        """A credential in the source text is refused when the search is built, on both paths.

        The engine checks the source before any request, so the scan raises
        ``sensitive_input`` from its constructor: the same code and no payload
        on each path, and no prepared request is reached.
        """
        results = []
        for label, gateway_class in (("fast", ValidatedGateway), ("legacy", _Legacy)):
            provider = SyntheticProvider(fixture=FixtureProvider(BUGS), secret=SECRET)
            with pinned_clock(), instrumented() as counts:
                with gateway_class(provider, self.root / f"scan-source-{label}",
                                   **pinned()) as gateway:
                    with self.assertRaises(ProviderError) as caught:
                        scan(source(8, f"fixture line carries {SECRET}"), gateway,
                             Config(whole_file=False, search_policy="legacy-v1"))
            results.append((caught.exception.code, provider.requests, counts["prepared"]))
        self.assertEqual(results[0][0], "sensitive_input")
        self.assertEqual(results[0][0], results[1][0])
        self.assertEqual(results[0][1], results[1][1])
        self.assertEqual([request.payload for request in results[0][1]], [])
        self.assertEqual(results[0][2], 0)

    def test_credential_in_question_text_fails_identically_in_scans(self):
        self.assert_scan_parity(
            "scan-question", lambda: SyntheticProvider(fixture=FixtureProvider(BUGS),
                                                       secret=SECRET),
            "sensitive_input", extra=leaked_verify)

    def test_cost_budget_refusal_fails_identically_in_scans(self):
        self.assert_scan_parity(
            "scan-cost", PricedProvider, "cost_budget_exhausted",
            gateway_options={"max_cost": Decimal("0.0000001")})

    # Scan-level routing, singleton, hook, retry and scoped cases ---------------
    def test_oversized_singleton_is_refused_and_the_scan_goes_on(self):
        """A question too large for any request is a named failure on both paths (R2-A1)."""
        for placement in ("instructions", "state"):
            with self.subTest(placement=placement):
                options = {"policy_placement": placement, "search_policy": "legacy-v1"}
                fast = self.scan_once(ValidatedGateway, f"large-fast-{placement}",
                                      extra=oversized_verify, **options)
                legacy = self.scan_once(_Legacy, f"large-legacy-{placement}",
                                        extra=oversized_verify, **options)
                self.assertIn("question_too_large", json.dumps(fast[0], default=str))
                self.assertEqual(fast[0], legacy[0])
                self.assertEqual(fast[1], legacy[1])
                self.assertEqual(fast[3], legacy[3])
                self.assertGreater(fast[2]["prepared"], 0)
                self.assertEqual(fast[2]["fallback"], 0)

    def test_bare_policy_text_stays_on_the_fast_path_in_scans(self):
        """Text that starts with the policy and no space is not a preamble (R2-A3)."""
        options = {"policy_placement": "state", "search_policy": "legacy-v1"}
        fast = self.scan_once(ValidatedGateway, "bare-fast", extra=bare_verify, **options)
        legacy = self.scan_once(_Legacy, "bare-legacy", extra=bare_verify, **options)
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        self.assert_prepared_work(fast[2])
        self.assertGreater(legacy[2]["evaluate_from_ask"], 0)

    def test_instance_evaluate_hook_still_receives_every_call(self):
        """An instance whose evaluate was replaced takes the base route (R2-E1)."""
        recorded = {}
        fast = self.scan_once(ValidatedGateway, "hook-fast",
                              hook=lambda gateway: recorded.update(calls=watch(gateway)),
                              search_policy="legacy-v1")
        legacy = self.scan_once(_Legacy, "hook-legacy", search_policy="legacy-v1")
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        self.assertEqual(len(recorded["calls"]), len(fast[3]))
        self.assertGreater(len(recorded["calls"]), 0)
        self.assertEqual(fast[2]["prepared"], 0)
        self.assertGreater(fast[2]["loads_from_ask"], 0)

    def test_class_evaluate_hook_still_receives_every_call(self):
        """A class-level replacement of evaluate takes the base route too (R3-E1)."""
        original = ValidatedGateway.evaluate

        def hooked(label, gateway_class):
            calls = []

            def wrapper(self, state, questions_, *, metadata):
                calls.append(metadata)
                return original(self, state, questions_, metadata=metadata)

            with patch.object(ValidatedGateway, "evaluate", wrapper):
                return self.scan_once(gateway_class, label, search_policy="legacy-v1"), calls

        fast, fast_calls = hooked("class-hook-fast", ValidatedGateway)
        legacy, legacy_calls = hooked("class-hook-legacy", _Legacy)
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        self.assertGreater(len(fast_calls), 0)
        self.assertEqual(len(fast_calls), len(fast[3]))
        self.assertEqual(len(fast_calls), len(legacy_calls))
        self.assertEqual(fast[2]["prepared"], 0)
        self.assertGreater(fast[2]["loads_from_ask"], 0)

    def test_retried_request_matches_across_paths_in_scans(self):
        """A rate-limited first attempt runs the retry loop on both paths (R2-E2)."""
        def flaky():
            return FlakySynthetic([ProviderError("http_rate_limited")],
                                  fixture=FixtureProvider(BUGS))

        fast = self.scan_once(ValidatedGateway, "retry-fast", flaky, search_policy="legacy-v1")
        legacy = self.scan_once(_Legacy, "retry-legacy", flaky, search_policy="legacy-v1")
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        self.assertTrue(any('"attempt": 2' in item for item in fast[1]))
        self.assertTrue(any('"retry_reason": "http_rate_limited"' in item for item in fast[1]))
        self.assertGreater(fast[2]["prepared"], 0)

    def test_retried_wire_matches_across_paths(self):
        """One wire with a retryable first attempt: outcome, payloads and receipts agree (R2-E2)."""
        (_batch, _failure, wire, _state), = _prepared_request_batches(STATE, QUESTIONS)

        def flaky(wire_):
            return FlakySynthetic([ProviderError("http_rate_limited")],
                                  response=answers_for(wire_))

        outcome = self.paths_agree("retry-wire", wire, {"sequence": 1}, flaky)
        self.assertEqual(outcome[0], "ok")
        self.assertTrue(any('"attempt": 2' in item for item in self.receipts("retry-wire-fast")))

    def test_scoped_partial_batches_match_across_paths(self):
        """Refusals and defective choices under scoped-v2-beta: the scoped rows (R2-F3)."""
        fast = self.scan_once(ValidatedGateway, "scoped-partial-fast", PartialJudge,
                              search_policy="scoped-v2-beta")
        legacy = self.scan_once(_Legacy, "scoped-partial-legacy", PartialJudge,
                                search_policy="scoped-v2-beta")
        self.assertEqual(fast[0], legacy[0])
        self.assertEqual(fast[1], legacy[1])
        self.assertEqual(fast[3], legacy[3])
        report = json.dumps(fast[0], default=str)
        self.assertIn("validated_partial", report)
        self.assertIn('"scoped"', report)
        self.assertIn("question_refused", report)
        self.assert_prepared_work(fast[2])

    # The digest fallback is counted, never hidden -----------------------------
    def test_wire_decode_is_the_only_fallback(self):
        (_batch, _failure, wire, _state), = _prepared_request_batches(STATE, QUESTIONS)
        self.assertEqual(engine._wire_state_digest(wire, compact(QUESTIONS)),
                         engine._decoded_state_digest(wire))


def answers_wire(wire):
    """The judge the paths are compared under: ``answers_for`` the wire it is given."""
    return SyntheticProvider(answers_for(wire))


if __name__ == "__main__":
    unittest.main()
