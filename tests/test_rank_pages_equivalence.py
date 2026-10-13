"""Old-versus-new oracles for rank-page sizing and its per-page encoder; no live calls.

``reference_rank_pages`` is the implementation before the state wire was
encoded once per placement. It is kept verbatim as the oracle, so every
generated case compares the pages and the raised errors of the old and new
code under both policy placements and both state layouts.
"""
import random
import unittest
from collections import Counter
from unittest import mock

from decision_bug_hunter import questions as questions_module
from decision_bug_hunter.core import Span
from decision_bug_hunter.protocol import (CONTRACT_VERSION, MAX_QUESTIONS, MAX_REQUEST_BYTES,
                                          MAX_STATE_BYTES, STATE_PLACEMENT_MAX_QUESTIONS,
                                          STATE_PLACEMENT_MAX_REQUEST_BYTES, ProviderError,
                                          RequestEnvelope, _json, _snapshot, encode_request,
                                          place_policy, request_envelope, using_request_envelope,
                                          validate_questions)
from decision_bug_hunter.questions import (MAX_RANK_PAGE, _encode_owned_state, _rank_pages,
                                           choice, load_pack, noul, policy, target_text,
                                           using_state_layout)

PACK, _ = load_pack()
RANK_TOO_LONG = dict(PACK, rank="q" * 12001)
LAYOUTS = ("v1", "v2")
ENVELOPE_CAPS = ((MAX_QUESTIONS, MAX_REQUEST_BYTES),
                 (STATE_PLACEMENT_MAX_QUESTIONS, STATE_PLACEMENT_MAX_REQUEST_BYTES),
                 (MAX_QUESTIONS, STATE_PLACEMENT_MAX_REQUEST_BYTES))


def reference_rank_pages(pack, region, targets, state, max_page=MAX_RANK_PAGE, reserve_bytes=0):
    """The pre-A7 ``_rank_pages``, verbatim except that it is named here."""
    if type(max_page) is not int or not 1 <= max_page <= MAX_RANK_PAGE:
        raise ValueError("invalid_rank_page_size")
    pages, page, entries, added, prepared = [], [], {}, 0, False
    for target in targets:
        if state is not None and not prepared:
            try:
                state = _snapshot(state)
                if type(state) is not dict:
                    raise ProviderError("invalid_request")
                template = choice(pack, "rank", region, [])
                validate_questions({"rank": template})
                placed_state, placed_questions, placed = place_policy(state,
                                                                      {"rank": template})
                _count, request_limit, state_limit = request_envelope().limits(placed)
                state_fits = len(_json(placed_state)) <= state_limit
                base = len(_json({"contract": CONTRACT_VERSION, "state": placed_state,
                                  "questions": placed_questions}))
                prepared = True
            except ProviderError:
                raise
            except (ValueError, TypeError, UnicodeError):
                raise ProviderError("invalid_request") from None
        fits = len(page) < max_page
        if state is not None:
            item = choice(pack, "rank", region, [target])
            validate_questions({"rank": item})
            try:
                entry = len(_json({target.id: target_text(target)})) - 1
            except (ValueError, TypeError, UnicodeError):
                raise ProviderError("invalid_request") from None
            predicted = added + entry - entries.get(target.id, 0)
            fits = (fits and state_fits
                    and base + predicted + reserve_bytes <= request_limit)
        if page and not fits:
            pages.append(page)
            page, entries, added = [], {}, 0
        page.append(target)
        if state is not None:
            added += entry - entries.get(target.id, 0)
            entries[target.id] = entry
    if page:
        pages.append(page)
    if state is not None:
        for page in pages:
            try:
                encode_request(state, {"rank": choice(pack, "rank", region, page)})
            except ProviderError as exc:
                if exc.code != "request_too_large" or len(page) != 1:
                    raise
    return pages


def _outcome(run):
    """The returned value, or the exception's type and code, for comparison."""
    try:
        return ("value", run())
    except ProviderError as exc:
        return ("provider", exc.code)
    except Exception as exc:
        return ("error", type(exc).__name__, str(exc))


def _assert_same(test, actual, expected):
    """assertEqual with a short failure text; pages and wires can be tens of KiB."""
    if actual == expected:
        return
    test.fail("outcomes differ: %r != %r" % (_brief(actual), _brief(expected)))


def _brief(outcome):
    if outcome[0] == "value" and type(outcome[1]) is list:
        return ("value", [len(page) for page in outcome[1]])
    if outcome[0] == "value":
        return ("value", len(outcome[1]))
    return outcome


def _envelope(rng, placement, layout):
    if placement == "instructions":
        return RequestEnvelope()
    return RequestEnvelope(policy(PACK, layout), *rng.choice(ENVELOPE_CAPS))


def _text_state(rng, target_bytes):
    """A state whose JSON is at most *target_bytes*, close to that size."""
    unit = rng.choice(("x", "雪", '\\"\n', "plain text ", "\u2028", "é"))
    per_unit = len(_json(unit)) - 2
    count = max(0, (target_bytes - len(_json({"text": ""}))) // per_unit)
    return {"text": unit * count}


def _state(rng, placement, layout):
    kind = rng.random()
    if kind < 0.04:
        return None
    if kind < 0.08:
        return rng.choice(([], "x", {"x": float("nan")}, {1: "a"}, {"s": "\ud800"}))
    if kind < 0.10:
        deep = {}
        for _ in range(rng.choice((10, 40))):
            deep = {"n": deep}
        return deep
    if kind < 0.16:
        # A policy entry: first and correct, misplaced, or wrong.
        text = policy(PACK, layout)
        choice_ = rng.choice(("first", "second", "wrong"))
        if choice_ == "first":
            return {"policy": text, "text": "body"}
        if choice_ == "second":
            return {"text": "body", "policy": text}
        return {"policy": text + "!", "text": "body"}
    target = rng.choice((0, 500, 4000, 12000, 15800, MAX_STATE_BYTES - 40,
                         MAX_STATE_BYTES, MAX_STATE_BYTES + 1, MAX_STATE_BYTES + 400))
    state = _text_state(rng, target)
    if rng.random() < 0.2:
        state["extra"] = [rng.randrange(100), {"k": "v" * rng.randrange(0, 300)}]
    return state


def _state_bytes(state):
    """JSON size of *state*, or 0 for a state that cannot be encoded at all."""
    try:
        return len(_json(state))
    except (ValueError, TypeError, UnicodeError):
        return 0


def _targets(rng):
    spans = []
    for _ in range(rng.choice((0, 1, 2, 3, 17, 60, 199, 200, 201, 333))):
        if spans and rng.random() < 0.04:
            spans.append(rng.choice(spans))
            continue
        start = rng.randrange(1, rng.choice((50, 10**4, 10**9)))
        spans.append(Span(start, start + rng.randrange(0, rng.choice((1, 8, 300)))))
    return spans


def _case(rng):
    layout = rng.choice(LAYOUTS)
    placement = rng.choice(("instructions", "state"))
    envelope = _envelope(rng, placement, layout)
    pack = RANK_TOO_LONG if rng.random() < 0.03 else PACK
    region = Span(rng.randrange(1, 10**4), 10**4 + rng.randrange(0, 30))
    targets = _targets(rng)
    state = _state(rng, placement, layout)
    max_page = rng.choice((1, 2, 5, 64, 199, MAX_RANK_PAGE))
    reserve = rng.choice((0, 0, 1, 250, 2000, 6000))
    return layout, envelope, pack, region, targets, state, max_page, reserve


class RankPageOracleTests(unittest.TestCase):
    def test_rank_pages_match_frozen_reference_on_generated_cases(self):
        rng = random.Random(20261007)
        seen = Counter()
        for case in range(400):
            layout, envelope, pack, region, targets, state, max_page, reserve = _case(rng)
            with self.subTest(case=case, placement=envelope.placement, layout=layout):
                with using_state_layout(layout), using_request_envelope(envelope):
                    expected = _outcome(lambda: reference_rank_pages(
                        pack, region, targets, state, max_page, reserve))
                    actual = _outcome(lambda: _rank_pages(
                        pack, region, targets, state, max_page, reserve))
                _assert_same(self, actual, expected)
                if actual[0] == "provider":
                    seen["provider:" + actual[1]] += 1
                elif actual[0] == "value":
                    seen["pages"] += 1
                    if len(actual[1]) > 1:
                        seen["multi_page"] += 1
                        if envelope.policy is not None:
                            seen["multi_page_state_placement"] += 1
                    if targets and _state_bytes(state) > MAX_STATE_BYTES:
                        seen["oversized_state_singletons"] += 1
        self.assertGreater(seen["multi_page_state_placement"], 0)
        self.assertGreater(seen["provider:invalid_request"], 0)
        self.assertGreater(seen["oversized_state_singletons"], 0)

    def test_invalid_page_size_fails_before_any_state_check(self):
        region, targets = Span(1, 1), [Span(1, 1)]
        for max_page in (0, MAX_RANK_PAGE + 1, True, "2", 2.0):
            for state in (None, [], {"x": "y"}):
                with self.subTest(max_page=max_page, state=state):
                    expected = _outcome(lambda: reference_rank_pages(
                        PACK, region, targets, state, max_page))
                    actual = _outcome(lambda: _rank_pages(PACK, region, targets, state, max_page))
                    _assert_same(self, actual, expected)
                    self.assertEqual(actual, ("error", "ValueError", "invalid_rank_page_size"))

    def test_empty_targets_skip_state_checks_in_both(self):
        for state in ([], {"x": float("nan")}, {"s": "\ud800"}):
            with self.subTest(state=state):
                expected = reference_rank_pages(PACK, Span(1, 1), [], state)
                self.assertEqual(_rank_pages(PACK, Span(1, 1), [], state), expected)
                self.assertEqual(expected, [])

    def test_owned_state_helper_matches_encode_request_with_shared_cache(self):
        rng = random.Random(20261008)
        for case in range(300):
            layout = rng.choice(LAYOUTS)
            envelope = _envelope(rng, rng.choice(("instructions", "state")), layout)
            region = Span(rng.randrange(1, 10**4), 10**4 + rng.randrange(0, 30))
            targets = _targets(rng)
            state = _state(rng, envelope.placement, layout)
            with self.subTest(case=case, placement=envelope.placement, layout=layout):
                with using_state_layout(layout), using_request_envelope(envelope):
                    try:
                        owned = _snapshot(state)
                    except ProviderError:
                        continue  # _rank_pages snapshots before any encoding.
                    wires = {}
                    for _ in range(4):
                        questions = _questions(rng, PACK, region, targets)
                        expected = _outcome(lambda: encode_request(owned, questions))
                        actual = _outcome(lambda: _encode_owned_state(owned, wires, questions))
                        _assert_same(self, actual, expected)

    def test_owned_state_helper_raises_the_same_codes_for_bad_questions(self):
        state = {"text": "body"}
        bad = ([], {}, {"bad name!": choice(PACK, "rank", Span(1, 1), [])},
               {"rank": choice(PACK, "rank", Span(1, 1), [Span(i, i) for i in range(1, 300)])},
               {"rank": noul(PACK, "screen", Span(1, 1))},
               {"rank": dict(choice(PACK, "rank", Span(1, 1), []), instructions="plain body")})
        for questions in bad:
            with self.subTest(questions=type(questions).__name__):
                expected = _outcome(lambda: encode_request(state, questions))
                actual = _outcome(lambda: _encode_owned_state(state, {}, questions))
                _assert_same(self, actual, expected)


def _questions(rng, pack, region, targets):
    """Question sets: valid pages, policy-free and invalid questions, and oversize menus."""
    subset = targets[:rng.randrange(0, len(targets) + 1)]
    kind = rng.random()
    if kind < 0.6:
        return {"rank": choice(pack, "rank", region, subset)}
    if kind < 0.7:
        return {"rank": noul(pack, "screen", region)}
    if kind < 0.8:
        return {"rank": dict(choice(pack, "rank", region, subset), instructions="plain body")}
    if kind < 0.85:
        return {}
    if kind < 0.9:
        return {"bad name!": choice(pack, "rank", region, subset)}
    return {"rank": choice(pack, "rank", region, [Span(i, i) for i in range(1, 300)])}


class FinalPageVerificationTests(unittest.TestCase):
    """The final authoritative encode of every page, after the sizing arithmetic.

    The arithmetic sizes pages from fragments; the last loop re-encodes each
    page exactly. It swallows only an oversized singleton and re-raises
    everything else, which these cases pin.
    """

    def test_a_page_the_arithmetic_let_through_but_the_encoder_refuses_is_raised(self):
        # A negative reserve makes the arithmetic accept far more than a request
        # holds, so a multi-entry page reaches the final encode and fails there.
        region = Span(1, 10**4)
        targets = [Span(10**6 + n, 10**6 + n + 5) for n in range(150)]
        for layout in LAYOUTS:
            for placement in ("instructions", "state"):
                with self.subTest(layout=layout, placement=placement):
                    state = _text_state(random.Random(1), 14000)
                    with using_state_layout(layout), using_request_envelope(
                            _envelope(random.Random(2), placement, layout)):
                        expected = _outcome(lambda: reference_rank_pages(
                            PACK, region, targets, state, 200, -9000))
                        actual = _outcome(lambda: _rank_pages(
                            PACK, region, targets, state, 200, -9000))
                    _assert_same(self, actual, expected)
                    self.assertEqual(actual, ("provider", "request_too_large"))

    def test_only_an_oversized_singleton_is_swallowed(self):
        target = Span(5, 9)
        state = {"text": "body"}
        too_large = ProviderError("request_too_large")
        with mock.patch.object(questions_module, "_encode_owned_state", side_effect=too_large):
            # One target on its page: kept as a page, for the execution layer to record.
            self.assertEqual(_rank_pages(PACK, Span(1, 20), [target], state), [[target]])
        other = ProviderError("invalid_request")
        with mock.patch.object(questions_module, "_encode_owned_state", side_effect=other):
            with self.assertRaises(ProviderError) as caught:
                _rank_pages(PACK, Span(1, 20), [target], state)
            self.assertEqual(caught.exception.code, "invalid_request")
        with mock.patch.object(questions_module, "_encode_owned_state", side_effect=too_large):
            # Two targets on one page: the same code is raised, not swallowed.
            with self.assertRaises(ProviderError) as caught:
                _rank_pages(PACK, Span(1, 20), [target, Span(11, 12)], state)
            self.assertEqual(caught.exception.code, "request_too_large")


if __name__ == "__main__":
    unittest.main()
