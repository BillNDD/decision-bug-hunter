"""One body encode per attempt: the one-slot memo of ``HostedProvider``.

``ValidatedGateway`` calls ``wire_size`` once per logical request and
``decide`` once per attempt. The memo lets the first attempt reuse the body
that ``wire_size`` already encoded, and every retry encodes again. Offline
only: scripted sockets, a fake clock and sleep, and a seeded generator.

The oracles keep a frozen copy of the pre-memo ``wire_size`` and ``_prepare``
(``Frozen``) and a copy of the current code whose ``wire_size`` clears the
memo (``ClearsMemo``). Both must send exactly the bytes the memo path sends.
"""
from decimal import Decimal
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import decisions, openrouter
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import QUESTION, ProviderError, _json, _secret_in
from decision_bug_hunter.providers import ProviderRequest, RetryPolicy, ValidatedGateway
from tests.fakes import FakeClock, FakeSleep, Reply, ScriptedHTTPS, seeded_rng
from tests.support import openai_body, openrouter_body


KEY = "offline-memo-sentinel-credential-5b1e"
ANSWERS = {"screen": {"type": "noul", "noul": Decimal("0.95")},
           "where": {"type": "choice", "choice": "L1-1", "confidence": Decimal("0.9"),
                     "probabilities": {"L1-1": Decimal("0.95"), "none": Decimal("0.05")}}}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
METADATA = {"sequence": 1, "phase": "test"}
PREFIX = b'{"contract":"dbh-judge-v1","state":'
TEXTS = ("private-sample-line", "naive unicode line éü", 'quote " and \\ backslash',
         "tab\tinside", "x" * 40)
TIMEOUTS = (30.0, 0.5, 0.0, -1.0, float("nan"), 7, True, "5")


class Route:
    """One hosted route: its provider class, its module and its encode function."""

    def __init__(self, provider, module, encoder, body):
        self.provider = provider
        self.module = module
        self.encoder = encoder
        self.body = body


ROUTES = {
    "openrouter": Route(OpenRouterProvider, openrouter, "encode_request",
                        lambda: openrouter_body(ANSWERS)),
    "decisions": Route(DecisionsProvider, decisions, "_translate",
                       lambda: openai_body(ANSWERS)),
}


# -- frozen oracle: the code before the memo, copied verbatim --------------------
def old_wire_size(self, payload):
    if type(payload) is not bytes:
        return None
    try:
        body, _questions = self.encode(payload, self.payload_limits(payload)[0])
    except ProviderError:
        return None
    return len(body)


def old_prepare(self, request):
    self.require_available()
    assert self._api_key is not None
    if type(request) is not ProviderRequest:
        raise ProviderError("invalid_request")
    timeout = request.timeout_seconds
    if type(timeout) not in (int, float) or not math.isfinite(timeout):
        raise ProviderError("invalid_deadline")
    if timeout <= 0:
        raise ProviderError("deadline_exceeded")
    if type(request.payload) is not bytes:
        raise ProviderError("invalid_request")
    max_questions, max_bytes = self.payload_limits(request.payload)
    if len(request.payload) > max_bytes:
        raise ProviderError("request_too_large")
    body, questions = self.encode(request.payload, max_questions)
    if len(questions) > max_questions:
        raise ProviderError("request_too_large")
    if any(_secret_in(credential, [body]) for credential in self._credentials):
        raise ProviderError("sensitive_input")
    headers = {"Authorization": "Bearer " + self._api_key,
               "Content-Type": "application/json", "Accept": "application/json",
               "Accept-Encoding": "identity", **self.extra_headers()}
    return body, questions, headers, float(timeout)


class Frozen:
    """The pre-memo behaviour: no memo is ever written or read."""

    def wire_size(self, payload):
        return old_wire_size(self, payload)

    def _prepare(self, request):
        return old_prepare(self, request)


class ClearsMemo:
    """The current code with the memo dropped right after every ``wire_size``."""

    def wire_size(self, payload):
        size = super().wire_size(payload)
        self._encoded = None
        return size


def frozen(cls):
    return type("Frozen" + cls.__name__, (Frozen, cls), {})


def clearing(cls):
    return type("Clearing" + cls.__name__, (ClearsMemo, cls), {})


def envelope(state, questions):
    """A local envelope, built the way the gateway's protocol builds it."""
    return PREFIX + _json(state) + b',"questions":' + _json(questions) + b"}"


def random_state(rng, index):
    count = rng.randrange(1, 4)
    lines = [{"line": n, "text": rng.choice(TEXTS) + "-" + str(index) + "-" + str(n)}
             for n in range(1, count + 1)]
    return {"file": "example.txt", "total_lines": count,
            "excerpts": [{"start_line": 1, "end_line": count, "lines": lines}],
            "context_scope": "declared_standalone"}


def generated_payload(rng, index):
    """Valid, oversized, credential-bearing, malformed and mistyped payloads."""
    kind = rng.randrange(12)
    state = random_state(rng, index)
    if kind <= 4:
        questions = QUESTIONS if rng.random() < 0.7 else {**QUESTIONS, "extra": QUESTION}
        return envelope(state, questions)
    if kind == 5:
        many = {f"q{n}": QUESTION for n in range(rng.randrange(60, 70))}
        return envelope(state, many)
    if kind == 6:
        state["excerpts"][0]["lines"][0]["text"] = "leak " + KEY
        return envelope(state, QUESTIONS)
    if kind == 7:
        state["excerpts"][0]["lines"][0]["text"] = "y" * rng.randrange(20000, 30000)
        return envelope(state, QUESTIONS)
    if kind == 8:
        return b'{"contract":"dbh-judge-v1","questions":' + _json(QUESTIONS) + b',"state":' \
            + _json(state) + b"}"
    if kind == 9:
        return envelope(state, QUESTIONS) + b" "
    if kind == 10:
        return rng.choice(("text", None, 7, bytearray(envelope(state, QUESTIONS))))
    return envelope(random_state(rng, index), {"screen": QUESTION})


def outcome(call, *args):
    try:
        return ("ok", call(*args))
    except ProviderError as exc:
        return ("error", exc.code, exc.classification)


class Harness:
    """One scripted origin for a route, a provider over it and a gateway."""

    def __init__(self, test, route, provider_class, steps, *, retry_policy=None):
        self.clock = FakeClock()
        self.script = ScriptedHTTPS(list(steps), clock=self.clock, host=route.module.HOST)
        exchange = self.script.exchange(route.module.HOST, route.module.PATH)
        self.provider = provider_class(KEY, environ={}, exchange=exchange)
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.gateway = ValidatedGateway(
            self.provider, Path(tmp.name) / "receipts",
            retry_policy=RetryPolicy.none() if retry_policy is None else retry_policy,
            clock=self.clock, sleep=FakeSleep(self.clock), rng=seeded_rng(0))
        test.addCleanup(self.gateway.close)

    def run(self, state=STATE, questions=QUESTIONS):
        return self.gateway.evaluate(state, questions, metadata=METADATA)

    def receipts(self):
        return [json.loads(Path(path).read_text(encoding="utf-8"))
                for path in self.gateway.last_receipts]


def counted(route):
    """Counts calls to the route's encode function; the real function runs."""
    return patch.object(route.module, route.encoder,
                        wraps=getattr(route.module, route.encoder))


def ok_reply(route):
    return Reply(body=route.body())


class MemoContract:
    """Checks run once per route; each subclass names its route."""

    route_name = ""

    @property
    def route(self):
        return ROUTES[self.route_name]

    def wired(self, provider_class, steps, **kwargs):
        return Harness(self, self.route, provider_class, steps, **kwargs)

    def test_one_encode_per_attempt(self):
        route = self.route
        harness = self.wired(route.provider, [ok_reply(route)])
        with counted(route) as counter:
            answers = harness.run()
        self.assertEqual(counter.call_count, 1)
        self.assertEqual(harness.receipts()[-1]["status"], "validated")
        self.assertEqual(answers["screen"]["noul"], Decimal("0.95"))
        oracle = self.wired(frozen(route.provider), [ok_reply(route)])
        with counted(route) as old:
            oracle.run()
        self.assertEqual(old.call_count, 2)
        self.assertEqual(harness.script.requests[0].body, oracle.script.requests[0].body)
        self.assertIsNone(harness.provider._encoded)

    def test_retried_attempt_reencodes_and_sends_identical_bytes(self):
        route = self.route
        headers = [("Content-Type", "application/json"), ("Content-Length", "0"),
                   ("Retry-After", "1")]
        policy = RetryPolicy(not_sent=0, rejected=1, possible=0, stale_connection=0)
        steps = [Reply(status=429, body=b"", headers=headers), ok_reply(route)]
        harness = self.wired(route.provider, steps, retry_policy=policy)
        with counted(route) as counter:
            harness.run()
        # wire_size encodes once; the first attempt uses it; the retry encodes again.
        self.assertEqual(counter.call_count, 2)
        self.assertEqual(len(harness.receipts()), 2)
        requests = harness.script.requests
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0].body, requests[1].body)
        oracle = self.wired(frozen(route.provider), [ok_reply(route)])
        oracle.run()
        self.assertEqual(requests[0].body, oracle.script.requests[0].body)

    def test_different_payload_is_a_miss(self):
        route = self.route
        harness = self.wired(route.provider, [ok_reply(route)])
        provider = harness.provider
        first, second = envelope(STATE, QUESTIONS), envelope(random_state(seeded_rng(3), 0),
                                                              QUESTIONS)
        self.assertNotEqual(first, second)
        provider.wire_size(first)
        with counted(route) as counter:
            provider.decide(ProviderRequest(second, 30.0))
        self.assertEqual(counter.call_count, 1)
        expected = provider.encode(second, provider.payload_limits(second)[0])[0]
        self.assertEqual(harness.script.requests[0].body, expected)
        self.assertIsNone(provider._encoded)

    def test_equal_copy_of_payload_is_a_hit(self):
        route = self.route
        harness = self.wired(route.provider, [ok_reply(route)])
        payload = envelope(STATE, QUESTIONS)
        copy = bytes(bytearray(payload))
        self.assertIsNot(copy, payload)
        harness.provider.wire_size(payload)
        with counted(route) as counter:
            harness.provider.decide(ProviderRequest(copy, 30.0))
        self.assertEqual(counter.call_count, 0)
        expected = harness.provider.encode(payload, harness.provider.payload_limits(payload)[0])
        self.assertEqual(harness.script.requests[0].body, expected[0])

    def test_memo_under_other_limits_is_a_miss(self):
        route = self.route
        harness = self.wired(route.provider, [ok_reply(route)])
        provider = harness.provider
        payload = envelope(STATE, QUESTIONS)
        provider.wire_size(payload)
        stored, limit, _body, questions = provider._encoded
        # A memo whose limits differ must be ignored, whatever bytes it holds.
        provider._encoded = (stored, limit - 1, b"not the wire body", questions)
        with counted(route) as counter:
            provider.decide(ProviderRequest(payload, 30.0))
        self.assertEqual(counter.call_count, 1)
        expected = provider.encode(payload, provider.payload_limits(payload)[0])[0]
        self.assertEqual(harness.script.requests[0].body, expected)

    def test_refusals_leave_no_stale_memo(self):
        route = self.route
        valid = envelope(STATE, QUESTIONS)
        oversized = envelope({**STATE, "file": "y" * 30000}, QUESTIONS)
        secret_state = {**STATE, "file": "leak " + KEY}
        cases = (
            ("zero deadline", valid, 0.0, "deadline_exceeded", True),
            ("nan deadline", valid, float("nan"), "invalid_deadline", True),
            ("oversized local payload", oversized, 30.0, "request_too_large", False),
            ("credential in local data", envelope(secret_state, QUESTIONS), 30.0,
             "sensitive_input", False),
        )
        for label, payload, timeout, code, recovers in cases:
            with self.subTest(case=label):
                harness = self.wired(route.provider, [ok_reply(route)])
                provider = harness.provider
                provider.wire_size(payload)
                with self.assertRaises(ProviderError) as caught:
                    provider.decide(ProviderRequest(payload, timeout))
                self.assertEqual(caught.exception.code, code)
                self.assertIsNone(provider._encoded)
                if recovers:
                    # No stale memo: the retry on the same payload encodes again.
                    with counted(route) as counter:
                        provider.decide(ProviderRequest(payload, 30.0))
                    self.assertEqual(counter.call_count, 1)
                    expected = provider.encode(payload,
                                               provider.payload_limits(payload)[0])[0]
                    self.assertEqual(harness.script.requests[0].body, expected)

    def test_missing_key_refusal_leaves_no_memo(self):
        route = self.route
        exchange = ScriptedHTTPS([], clock=FakeClock(), host=route.module.HOST).exchange(
            route.module.HOST, route.module.PATH)
        provider = route.provider(None, environ={}, exchange=exchange)
        payload = envelope(STATE, QUESTIONS)
        provider.wire_size(payload)
        with self.assertRaises(ProviderError) as caught:
            provider.decide(ProviderRequest(payload, 30.0))
        self.assertEqual(caught.exception.code, "provider_unavailable")
        self.assertIsNone(provider._encoded)

    def test_exception_in_wire_size_leaves_no_stale_memo(self):
        route = self.route
        harness = self.wired(route.provider, [ok_reply(route)])
        provider = harness.provider
        payload = envelope(STATE, QUESTIONS)
        provider.wire_size(payload)
        with patch.object(route.module, route.encoder, side_effect=RuntimeError("fault")):
            with self.assertRaises(RuntimeError):
                provider.wire_size(envelope(random_state(seeded_rng(9), 1), QUESTIONS))
        self.assertIsNone(provider._encoded)
        with counted(route) as counter:
            provider.decide(ProviderRequest(payload, 30.0))
        self.assertEqual(counter.call_count, 1)
        expected = provider.encode(payload, provider.payload_limits(payload)[0])[0]
        self.assertEqual(harness.script.requests[0].body, expected)

    def test_prepare_matches_frozen_oracle_on_generated_inputs(self):
        route = self.route
        new = route.provider(KEY, environ={})
        old = frozen(route.provider)(KEY, environ={})
        rng = seeded_rng(20261007)
        payloads = [generated_payload(rng, index) for index in range(120)]
        values = [*payloads, None, "text", b""]
        for step in range(400):
            first, second = rng.choice(values), rng.choice(values)
            timeout = rng.choice(TIMEOUTS)
            middle = first if rng.random() < 0.5 else second
            sequences = []
            for provider in (new, old):
                sequences.append([
                    outcome(provider.wire_size, first),
                    outcome(provider._prepare, ProviderRequest(middle, timeout)),
                    outcome(provider._prepare, ProviderRequest(first, timeout)),
                ])
            with self.subTest(step=step):
                self.assertEqual(sequences[0], sequences[1])
                self.assertIsNone(new._encoded)

    def test_end_to_end_bodies_match_both_oracles(self):
        route = self.route
        for seed in range(4):
            state = random_state(seeded_rng(seed), seed)
            bodies = []
            for provider_class in (route.provider, frozen(route.provider),
                                   clearing(route.provider)):
                harness = self.wired(provider_class, [ok_reply(route)])
                harness.run(state=state)
                self.assertEqual(len(harness.script.requests), 1)
                bodies.append(harness.script.requests[0].body)
            with self.subTest(seed=seed):
                self.assertEqual(bodies[0], bodies[1])
                self.assertEqual(bodies[0], bodies[2])


class OpenRouterMemoTests(MemoContract, unittest.TestCase):
    route_name = "openrouter"


class DecisionsMemoTests(MemoContract, unittest.TestCase):
    route_name = "decisions"


if __name__ == "__main__":
    unittest.main()
