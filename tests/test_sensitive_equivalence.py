"""Old-versus-new equivalence for the credential scan (offline, seeded).

Covers the flat ``protocol._secret_in`` walker and the response scans of
``openrouter.decode_response`` and ``decisions.translate_response``, which
skip the decoded walk when the raw bytes hold no escape and every credential
is ASCII. The frozen copies below are the pre-change code and are the
oracles. Every generated input comes from a seed, and no socket is opened.
"""
from __future__ import annotations

import json
import random
import sys
import unittest
from decimal import Decimal

from decision_bug_hunter import decisions, openrouter, protocol
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import QUESTION, ProviderError
from decision_bug_hunter.providers import classify
from tests.support import openai_body, openrouter_body
from tests.test_openrouter import Harness, reply

SENTINEL = "offline-sensitive-scan-sentinel-5b1e"
QUESTIONS = {"q": dict(QUESTION)}
REFUSALS = ("response_sensitive", "response_invalid_json")

CREDENTIALS = ("sentinel-cred-0a9f", 'quo"te-cred7', "back\\slash-cred3", "spa ce-cred",
               "ünïcred-4", "ctl\x01cred", "line\nbreak-2", "cred/slash-1",
               "x", "")
FILLER = ("abc", "é", "中文", " ", "{}", "\\", '"', "\n", "", "xyz",
          "\U0001F600", "/", "\t", "sentinel")


class _Dict(dict):
    """A dict subclass: the frozen walker and the new one both ignore it."""


class _List(list):
    """A list subclass: the frozen walker and the new one both ignore it."""


def _old_secret_in(key, values):
    """Frozen pre-change protocol._secret_in (the two-call dict form)."""
    for value in values:
        if type(value) is str and key in value:
            return True
        if type(value) is bytes and key.encode("ascii") in value:
            return True
        if type(value) is dict:
            if _old_secret_in(key, value.keys()) or _old_secret_in(key, value.values()):
                return True
        if type(value) in (list, tuple) and _old_secret_in(key, value):
            return True
    return False


def _old_check_sensitive(credentials, values):
    """Frozen pre-change HostedProvider.check_sensitive."""
    for credential in credentials:
        if _old_secret_in(credential, values):
            raise ProviderError("sensitive_input")


def _old_response_scan(raw, credentials):
    """Frozen pre-change scan order of decode_response and translate_response.

    Returns None when the body passes the scan. Raises ProviderError with the
    old code, or lets UnicodeEncodeError escape from the raw scan, as the old
    code did for a non-ASCII credential.
    """
    credentials = tuple(item for item in credentials if item)
    if any(_old_secret_in(credential, [raw]) for credential in credentials):
        raise ProviderError("response_sensitive")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=protocol._pairs,
                          parse_float=protocol._decimal, parse_constant=protocol._constant)
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("response_invalid_json") from None
    if any(_old_secret_in(credential, [data]) for credential in credentials):
        raise ProviderError("response_sensitive")
    return None


def _result(function, *args):
    """What a call does, as ("value", result) or ("raised", type, code)."""
    try:
        return ("value", function(*args))
    except ProviderError as exc:
        return ("raised", ProviderError, exc.code)
    except Exception as exc:
        return ("raised", type(exc), None)


def _refusal(outcome):
    """True for the scan refusals and for the UnicodeEncodeError of a non-ASCII key."""
    if outcome[0] != "raised":
        return False
    if outcome[1] is UnicodeEncodeError:
        return True
    return outcome[1] is ProviderError and outcome[2] in REFUSALS


def _decode_call(raw, credentials):
    openrouter.decode_response(raw, QUESTIONS, credentials)


def _translate_call(raw, credentials):
    decisions.translate_response(raw, QUESTIONS, credentials)


# ---------------------------------------------------------------- generators

def _text(rng, credential):
    """Text with *credential* planted at a random place among filler text."""
    pieces = [rng.choice(FILLER) for _ in range(rng.randint(0, 3))]
    where = rng.random()
    if where < 0.2:
        pieces.insert(0, credential)
    elif where < 0.4:
        pieces.append(credential)
    elif where < 0.6:
        pieces.insert(rng.randint(0, len(pieces)), credential)
    return "".join(pieces)


def _key(rng, credential):
    roll = rng.random()
    if roll < 0.6:
        return _text(rng, credential)
    if roll < 0.7:
        return b"k" + credential.encode("utf-8")
    if roll < 0.8:
        return ("t", credential)
    return rng.choice((7, None, b"plain", ()))


def _leaf(rng, credential):
    roll = rng.random()
    if roll < 0.5:
        return _text(rng, credential)
    if roll < 0.6:
        return credential.encode("utf-8")
    if roll < 0.66:
        return _text(rng, credential).encode("utf-8")
    if roll < 0.72:
        return rng.choice((3, 2.5, True, None, Decimal("1.5"), ""))
    if roll < 0.76:
        return frozenset((credential,))
    if roll < 0.8:
        return credential
    return rng.choice(("", b"", "plain"))


def _tree(rng, credential, depth):
    if depth == 0 or rng.random() < 0.4:
        return _leaf(rng, credential)
    kind = rng.randrange(6)
    if kind == 0:
        return {_key(rng, credential): _tree(rng, credential, depth - 1)
                for _ in range(rng.randint(0, 3))}
    if kind == 1:
        return [_tree(rng, credential, depth - 1) for _ in range(rng.randint(0, 3))]
    if kind == 2:
        return tuple(_tree(rng, credential, depth - 1) for _ in range(rng.randint(0, 3)))
    if kind == 3:
        return _Dict({_key(rng, credential): _tree(rng, credential, depth - 1)})
    if kind == 4:
        return _List([_tree(rng, credential, depth - 1)])
    return {_key(rng, credential): _tree(rng, credential, depth - 1)}


def _u_escape(char):
    """*char* as backslash-u escapes, one per UTF-16 unit (astral characters get two)."""
    data = char.encode("utf-16-be")
    return "".join("\\u%04x" % int.from_bytes(data[index:index + 2], "big")
                   for index in range(0, len(data), 2))


def _escape_text(text, rng, ascii_only, rate):
    """JSON string content with random escapes, a bare slash and literal text."""
    out = []
    for char in text:
        if char in '"\\' or ord(char) < 0x20:
            out.append(json.dumps(char)[1:-1])
        elif rate and rng.random() < rate:
            out.append(_u_escape(char))
        elif char == "/" and rng.random() < 0.5:
            out.append("\\/")
        elif ascii_only:
            out.append(json.dumps(char)[1:-1])
        else:
            out.append(char)
    return "".join(out)


def _encode(value, rng, ascii_only, rate):
    if type(value) is dict:
        return "{" + ",".join(
            '"' + _escape_text(key, rng, ascii_only, rate) + '":' + _encode(item, rng, ascii_only, rate)
            for key, item in value.items()) + "}"
    if type(value) is list:
        return "[" + ",".join(_encode(item, rng, ascii_only, rate) for item in value) + "]"
    if type(value) is str:
        return '"' + _escape_text(value, rng, ascii_only, rate) + '"'
    return json.dumps(value)


def _body(rng, credential):
    """A response body that plants *credential* verbatim, as escapes, or both."""
    named = {"answers": _json_tree(rng, credential, 3),
             "usage": {"prompt_tokens": 1, "note": _text(rng, credential)}}
    if rng.random() < 0.5:
        named[_text(rng, credential)] = 1
    ascii_only = rng.random() < 0.3
    rate = rng.choice((0.0, 0.0, 0.15, 0.6))
    raw = _encode(named, rng, ascii_only, rate).encode("utf-8")
    roll = rng.random()
    if roll < 0.04:
        raw = raw[: len(raw) // 2]
    elif roll < 0.06:
        raw = b"\xff" + raw
    return raw


def _json_tree(rng, credential, depth):
    """A JSON-shaped tree of str keys and str or scalar leaves."""
    if depth == 0 or rng.random() < 0.4:
        return rng.choice((_text(rng, credential), _text(rng, credential), 3, None, True))
    if rng.random() < 0.5:
        return [_json_tree(rng, credential, depth - 1) for _ in range(rng.randint(0, 3))]
    return {_text(rng, credential) + str(index): _json_tree(rng, credential, depth - 1)
            for index in range(rng.randint(0, 3))}


class SensitiveEquivalence(unittest.TestCase):
    def test_flat_walker_matches_the_frozen_walker_on_seeded_structures(self):
        counts = {"True": 0, "False": 0, "raised": 0}
        for seed in range(3600):
            rng = random.Random(seed)
            credential = rng.choice(CREDENTIALS)
            values = [_tree(rng, credential, 4) for _ in range(rng.randint(1, 3))]
            if seed % 2:
                values = tuple(values)
            for key in (credential, rng.choice(CREDENTIALS)):
                new = _result(protocol._secret_in, key, values)
                old = _result(_old_secret_in, key, values)
                self.assertEqual(new, old, f"seed {seed} key {key!r}")
                if new[0] == "raised":
                    counts["raised"] += 1
                else:
                    counts[str(new[1])] += 1
        # The generator must reach each outcome, or the comparison proves little.
        self.assertTrue(all(count > 0 for count in counts.values()), counts)

    def test_response_scans_refuse_as_the_frozen_scan_does(self):
        seen = {"refused": 0, "passed": 0, "escape_only": 0, "skipped_walk": 0}
        for seed in range(1500):
            rng = random.Random(10_000 + seed)
            credentials = tuple(rng.choice(CREDENTIALS) for _ in range(rng.randint(1, 2)))
            raw = _body(rng, credentials[0])
            for function in (_decode_call, _translate_call):
                self._assert_scan_matches(function, raw, credentials, f"seed {seed}")
            old = _result(_old_response_scan, raw, credentials)
            refused = _refusal(old)
            seen["refused" if refused else "passed"] += 1
            if b"\\" not in raw and all(item.isascii() for item in credentials if item):
                seen["skipped_walk"] += 1
            if refused and old[1] is ProviderError and old[2] == "response_sensitive" and not any(
                    item.isascii() and item.encode("ascii") in raw for item in credentials if item):
                seen["escape_only"] += 1
        self.assertTrue(all(count > 0 for count in seen.values()), seen)

    def _assert_scan_matches(self, function, raw, credentials, label):
        old = _result(_old_response_scan, raw, credentials)
        new = _result(function, raw, credentials)
        if _refusal(old):
            self.assertEqual(new, old, label)
            return
        self.assertEqual(old, ("value", None), label)
        self.assertFalse(_refusal(new), label)
        # A body that passes the scan gets the same outcome as with no scan.
        self.assertEqual(new, _result(function, raw, ()), label)


class EscapeRegressions(unittest.TestCase):
    """Escape-free and escaped bodies carry a credential in a value, a key or only after unescaping."""

    @staticmethod
    def _escaped(text):
        return "".join("\\u%04x" % ord(char) for char in text)

    def test_refusals_match_for_each_placement(self):
        # (label, body text, credentials, expected refusal code or None)
        cases = [
            ("verbatim value, no escape", '{"note": "%s"}' % SENTINEL,
             (SENTINEL,), "response_sensitive"),
            ("verbatim key, no escape", '{"%s": 1}' % SENTINEL,
             (SENTINEL,), "response_sensitive"),
            ("value only after unescaping", '{"note": "%s"}' % self._escaped(SENTINEL),
             (SENTINEL,), "response_sensitive"),
            ("key only after unescaping", '{"%s": 1}' % self._escaped(SENTINEL),
             (SENTINEL,), "response_sensitive"),
            ("escaped slash in value", '{"note": "cred\\/slash-41"}',
             ("cred/slash-41",), "response_sensitive"),
            ("escaped newline in value", '{"note": "line\\nbreak-41"}',
             ("line\nbreak-41",), "response_sensitive"),
            ("escape elsewhere, no credential", '{"note": "\\u0041"}',
             (SENTINEL,), None),
        ]
        for label, text, credentials, expected in cases:
            raw = text.encode("utf-8")
            for function in (_decode_call, _translate_call):
                with self.subTest(case=label, function=function.__name__):
                    old = _result(_old_response_scan, raw, credentials)
                    new = _result(function, raw, credentials)
                    self.assertEqual(new, old)
                    if expected is None:
                        self.assertEqual(new, ("value", None))
                    else:
                        self.assertEqual(new, ("raised", ProviderError, expected))

    def test_recursion_limit_never_hides_a_credential(self):
        """At every depth the new walker answers as the old one did, or answers where it raised.

        Both walkers keep one call frame per container level, so they reach the
        recursion limit at nearly the same depth. Near the limit the old walker
        can raise RecursionError a level or two before the new one (seen on
        3.11). Where it does, the new walker must still answer, and the answer
        must be the correct one (the needle is there, so True). The new walker
        never raises where the old one answered, and never answers False for a
        credential that is present.

        The sweep is placed relative to the frames the test runner already
        uses, so it covers the limit under unittest, pytest or any wrapper.
        """
        used, frame = 0, sys._getframe()
        while frame is not None:
            used += 1
            frame = frame.f_back
        top = sys.getrecursionlimit() - used
        outcomes = set()
        for depth in range(top - 70, top):
            nested = "needle-depth"
            for index in range(depth):
                nested = [nested] if index % 2 else {"k": nested}
            with self.subTest(depth=depth):
                old = _result(_old_secret_in, "needle-depth", [nested])
                new = _result(protocol._secret_in, "needle-depth", [nested])
                if old == new:
                    if new[0] == "value":
                        self.assertEqual(new, ("value", True))
                    outcomes.add(new)
                    continue
                self.assertEqual(old, ("raised", RecursionError, None))
                self.assertEqual(new, ("value", True))
        self.assertIn(("value", True), outcomes)


def _nested(depth, shape, leaf):
    """*leaf* wrapped *depth* times in objects (``{"k": ...}``) or in arrays."""
    if shape == "object":
        return ('{"k": ' * depth + leaf + "}" * depth).encode("utf-8")
    return ("[" * depth + leaf + "]" * depth).encode("utf-8")


def _parser_reads(raw):
    """True when json.loads on the running build reads *raw*, False at its recursion limit."""
    try:
        json.loads(raw.decode("utf-8"))
    except RecursionError:
        return False
    return True


def _shape(outcome):
    """A decoder outcome as (error, sorted answer names, provenance), or the raised outcome."""
    if outcome[0] != "value":
        return outcome
    response = outcome[1]
    return ("value", response.error, sorted(response.answers), dict(response.provenance))


class DeepNestedBodies(unittest.TestCase):
    """Bodies nested beyond the recursion limit of about 1000 levels.

    The recursive credential rescan runs only when the raw bytes hold a
    backslash. An escape-free body skips it, so depth alone gives no
    RecursionError and the outcome is the documented one pinned below. A body
    with a backslash keeps the rescan, and its RecursionError, as the frozen
    full scan does. At top level, json.loads reads up to 2997 levels on Python
    3.12 and 2998 on 3.13 (3.11 shares the 1000-frame recursion limit and fails
    sooner); each expectation is taken from json.loads on the running build: a
    body it reads gets the pinned outcome, and a body it cannot read gets
    ProviderError response_invalid_json from both decoders.
    """

    DEPTHS = (1200, 2500)
    ABOVE_LIMIT = (5000, 20000)
    CREDENTIALS = (SENTINEL,)
    ANSWERS = {"q": {"type": "noul", "noul": Decimal("0.95")}}
    UNREADABLE = ("raised", ProviderError, "response_invalid_json")

    def deep_field(self, body, path, depth):
        """*body* with an escape-free array nested *depth* levels at the key *path*."""
        data = json.loads(body.decode("utf-8"))
        node = data
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = "__DEEP__"
        text = json.dumps(data).encode("utf-8")
        self.assertEqual(text.count(b'"__DEEP__"'), 1, path)
        return text.replace(b'"__DEEP__"', _nested(depth, "array", '"v"'))

    def test_parser_boundary_guards_hold_on_this_build(self):
        """Each depth sits on the right side of the parser limit, so no branch goes vacuous."""
        for shape in ("array", "object"):
            for depth in self.ABOVE_LIMIT:
                with self.subTest(depth=depth, shape=shape):
                    self.assertFalse(_parser_reads(_nested(depth, shape, "1")))
            if sys.version_info >= (3, 12):
                for depth in self.DEPTHS:
                    with self.subTest(depth=depth, shape=shape):
                        self.assertTrue(_parser_reads(_nested(depth, shape, "1")))

    def test_nested_builder_shapes(self):
        self.assertEqual(_nested(3, "object", "1"), b'{"k": {"k": {"k": 1}}}')
        self.assertEqual(_nested(2, "array", "1"), b"[[1]]")

    def test_escape_free_top_level_array_is_a_schema_refusal(self):
        """Both decoders raise response_schema for an escape-free array that json.loads reads.

        This differs from 1a5f5be, where these bodies raised RecursionError from
        the decoders, the gateway recorded internal_error and blocked. The change
        comes from skipping the credential rescan for escape-free bodies; it is
        the kept, documented behavior and this test pins it. An array
        that json.loads cannot read gets response_invalid_json instead.
        """
        for depth in self.DEPTHS + self.ABOVE_LIMIT:
            raw = _nested(depth, "array", "1")
            expected = (("raised", ProviderError, "response_schema")
                        if _parser_reads(raw) else self.UNREADABLE)
            with self.subTest(depth=depth):
                self.assertEqual(
                    _result(openrouter.decode_response, raw, QUESTIONS, self.CREDENTIALS),
                    expected)
                self.assertEqual(
                    _result(decisions.translate_response, raw, QUESTIONS, self.CREDENTIALS),
                    expected)

    def test_escape_free_top_level_object_is_an_unanswered_schema_refusal(self):
        """An escape-free top-level object returns a value, and does not raise.

        Both decoders return a ProviderResponse with error response_schema and no
        answers. The gateway turns that error into ProviderError response_schema,
        so the code matches the array shape, but the decoder-level outcome is a
        returned value rather than a raised ProviderError. This is the
        kept behavior, not a regression. An object that json.loads cannot read
        gets response_invalid_json from both decoders.
        """
        for depth in self.DEPTHS + self.ABOVE_LIMIT:
            raw = _nested(depth, "object", "1")
            with self.subTest(depth=depth):
                for function in (openrouter.decode_response, decisions.translate_response):
                    outcome = _result(function, raw, QUESTIONS, self.CREDENTIALS)
                    if not _parser_reads(raw):
                        self.assertEqual(outcome, self.UNREADABLE)
                        continue
                    self.assertEqual(outcome[0], "value")
                    self.assertEqual(outcome[1].error, "response_schema")
                    self.assertEqual(outcome[1].answers, {})

    @staticmethod
    def placed(body, function, placement, value):
        """*body* with the JSON text *value* added as a key of an object.

        ``top`` adds a top-level key, ``usage`` a key of the usage object and
        ``answers`` a key of the first answer object (the q answer).
        """
        if placement == "top":
            return body[:-1] + b', "deep": ' + value + b"}"
        if placement == "usage":
            anchor = b'"usage": {'
        elif function is openrouter.decode_response:
            anchor = b'{"q": {'
        else:
            anchor = b'{"type": "predicate", '
        at = body.index(anchor) + len(anchor)
        return body[:at] + b'"deep": ' + value + b", " + body[at:]

    def test_escape_free_deep_key_in_a_valid_body_is_ignored(self):
        valid = {openrouter.decode_response: openrouter_body(
                    self.ANSWERS, model=openrouter.MODEL),
                 decisions.translate_response: openai_body(
                    self.ANSWERS, model=decisions.MODEL)}
        for function, body in valid.items():
            for placement in ("top", "usage", "answers"):
                for depth in self.DEPTHS + self.ABOVE_LIMIT:
                    for shape in ("object", "array"):
                        raw = self.placed(body, function, placement,
                                          _nested(depth, shape, '"v"'))
                        label = dict(function=function.__name__, placement=placement,
                                     depth=depth, shape=shape)
                        with self.subTest(**label):
                            if not _parser_reads(raw):
                                self.assertEqual(
                                    _result(function, raw, QUESTIONS, self.CREDENTIALS),
                                    self.UNREADABLE)
                                continue
                            shallow = self.placed(body, function, placement,
                                                  _nested(1, shape, '"v"'))
                            outcome = _result(function, raw, QUESTIONS, self.CREDENTIALS)
                            # No RecursionError, and the deep value changes nothing
                            # compared with the same body holding a shallow value.
                            self.assertNotEqual(outcome, ("raised", RecursionError, None))
                            self.assertEqual(outcome, _result(function, shallow, QUESTIONS,
                                                              self.CREDENTIALS))
                            if placement == "top":
                                with self.subTest(**label, check="valid"):
                                    self.assertEqual(outcome, _result(
                                        function, body, QUESTIONS, self.CREDENTIALS))
                                    self.assertEqual(outcome[0], "value")
                                    self.assertIsNone(outcome[1].error)
                                    self.assertEqual(sorted(outcome[1].answers), ["q"])

    def test_backslash_bodies_keep_the_rescan_and_its_recursion_error(self):
        backslash = chr(92)
        leaf = '"v' + backslash + 'u0041"'
        valid = openrouter_body(self.ANSWERS, model=openrouter.MODEL)
        for depth in self.DEPTHS + self.ABOVE_LIMIT:
            for shape in ("object", "array"):
                nested = _nested(depth, shape, leaf)
                ignored = valid[:-1] + b', "deep": ' + nested + b"}"
                escaped_key = (valid[:-1] + b', "esc' + backslash.encode()
                               + b'u0041": 1, "deep": ' + nested + b"}")
                for raw in (nested, ignored, escaped_key):
                    with self.subTest(depth=depth, shape=shape, raw=raw[:24]):
                        # Readable: the rescan's RecursionError, as before. Unreadable:
                        # json.loads fails first, and every scan reports the decode error.
                        expected = (("raised", RecursionError, None)
                                    if _parser_reads(raw) else self.UNREADABLE)
                        self.assertEqual(
                            _result(_old_response_scan, raw, self.CREDENTIALS), expected)
                        self.assertEqual(
                            _result(openrouter.decode_response, raw, QUESTIONS,
                                    self.CREDENTIALS), expected)
                        self.assertEqual(
                            _result(decisions.translate_response, raw, QUESTIONS,
                                    self.CREDENTIALS), expected)

    def test_gateway_ends_each_deep_body_with_its_pinned_code(self):
        """Through the OpenRouter gateway: one call, one terminal receipt, the code pinned here.

        An escape-free body that json.loads reads fails its shape check with
        response_schema, and the gateway raises that code. A body with a backslash
        that json.loads reads keeps the rescan, whose RecursionError the gateway
        records as internal_error, and that failure blocks the gateway: the next
        call is refused without a request. A body that json.loads cannot read
        fails with response_invalid_json, which does not block: the next call
        dispatches and validates. A valid body with a deep unused key is a change
        from 1a5f5be: there the decoders raised RecursionError, the gateway
        recorded internal_error and blocked, while the rescan skip validates it;
        that is the kept, documented behavior.
        """
        backslash = chr(92)
        valid = openrouter_body(self.ANSWERS, model=openrouter.MODEL)
        for depth in self.DEPTHS + self.ABOVE_LIMIT:
            for shape in ("array", "object"):
                cases = (
                    ("escape-free", _nested(depth, shape, "1")),
                    ("backslash", _nested(depth, shape, '"v' + backslash + 'u0041"')),
                    ("valid", valid[:-1] + b', "deep": ' + _nested(depth, shape, '"v"') + b"}"),
                )
                for label, raw in cases:
                    with self.subTest(depth=depth, shape=shape, body=label):
                        readable = _parser_reads(raw)
                        if label == "valid" and readable:
                            harness = Harness(self, [reply(raw)])
                            answers, receipt = harness.evaluate(questions=QUESTIONS)
                            self.assertEqual(sorted(answers), ["q"])
                            self.assertEqual(receipt["status"], "validated")
                            self.assertEqual(len(harness.script.requests), 1)
                            continue
                        if not readable:
                            code = "response_invalid_json"
                        elif label == "escape-free":
                            code = "response_schema"
                        else:
                            code = "internal_error"
                        self.assertEqual(classify(code).scope,
                                         "run" if code == "internal_error" else "request")
                        harness = Harness(self, [reply(raw), reply(valid)])
                        outcome, receipt = harness.evaluate(questions=QUESTIONS)
                        self.assertIsInstance(outcome, ProviderError)
                        self.assertEqual(outcome.code, code)
                        self.assertEqual((receipt["status"], receipt["error"]),
                                         ("failed", code))
                        self.assertEqual(len(harness.script.requests), 1)
                        second, second_receipt = harness.evaluate(questions=QUESTIONS)
                        if code == "internal_error":
                            self.assertIsInstance(second, ProviderError)
                            self.assertEqual(second.code, "internal_error")
                            self.assertEqual(len(harness.script.requests), 1)
                        else:
                            self.assertEqual(sorted(second), ["q"])
                            self.assertEqual(second_receipt["status"], "validated")
                            self.assertEqual(len(harness.script.requests), 2)

    def test_escape_free_deep_consumed_fields_get_typed_codes(self):
        """Escape-free deep values in fields the decoders read, pinned as observed.

        Each body is a valid body with the placeholder at one path, replaced by
        an escape-free array nested DEPTH levels deep. On 1a5f5be the full rescan
        raised RecursionError here, the gateway recorded internal_error and
        blocked. The rescan skip gives the outcomes pinned below: the decoder value
        (its error, answer names and provenance), or ProviderError
        response_invalid_json when json.loads cannot read the body.
        """
        or_base = openrouter_body(self.ANSWERS, model=openrouter.MODEL)
        or_error_base = openrouter_body(self.ANSWERS, model=openrouter.MODEL,
                                        omit=("answers",))
        oa_base = openai_body(self.ANSWERS, model=decisions.MODEL)
        or_answers = ("value", None, ["q"], {"model_returned": openrouter.MODEL,
                                             "upstream_provider": "OpenAI"})
        cases = (
            ("openrouter model", openrouter.decode_response, or_base, ("model",),
             ("value", "response_model", [], {"upstream_provider": "OpenAI"})),
            ("openrouter usage.input_tokens", openrouter.decode_response, or_base,
             ("usage", "input_tokens"), or_answers),
            ("openrouter answers.q.noul", openrouter.decode_response, or_base,
             ("answers", "q", "noul"), or_answers),
            ("openrouter usage.cost", openrouter.decode_response, or_base, ("usage", "cost"),
             ("value", None, ["q"], {"model_returned": openrouter.MODEL,
                                     "upstream_provider": "OpenAI",
                                     "cost_error": "invalid"})),
            ("openrouter error.message", openrouter.decode_response, or_error_base,
             ("error", "message"),
             ("value", "provider_error_in_body", [],
              {"model_returned": openrouter.MODEL, "upstream_provider": "OpenAI",
               "moderation": False, "routing_metadata": False})),
            ("openai model", decisions.translate_response, oa_base, ("model",),
             ("value", "response_model", [], {})),
            ("openai usage.input_tokens", decisions.translate_response, oa_base,
             ("usage", "input_tokens"),
             ("value", None, ["q"], {"model_returned": decisions.MODEL})),
        )
        for label, function, base, path, expected in cases:
            for depth in self.DEPTHS + self.ABOVE_LIMIT:
                raw = self.deep_field(base, path, depth)
                with self.subTest(case=label, depth=depth):
                    if _parser_reads(raw):
                        self.assertEqual(
                            _shape(_result(function, raw, QUESTIONS, self.CREDENTIALS)),
                            expected)
                    else:
                        self.assertEqual(
                            _result(function, raw, QUESTIONS, self.CREDENTIALS),
                            self.UNREADABLE)

    def test_openrouter_model_field_gateway_codes(self):
        """The OpenRouter model case through the gateway: response_model, then a valid reply."""
        base = openrouter_body(self.ANSWERS, model=openrouter.MODEL)
        for depth in self.DEPTHS + self.ABOVE_LIMIT:
            raw = self.deep_field(base, ("model",), depth)
            code = "response_model" if _parser_reads(raw) else "response_invalid_json"
            with self.subTest(depth=depth):
                harness = Harness(self, [reply(raw), reply(base)])
                outcome, receipt = harness.evaluate(questions=QUESTIONS)
                self.assertIsInstance(outcome, ProviderError)
                self.assertEqual(outcome.code, code)
                self.assertEqual((receipt["status"], receipt["error"]), ("failed", code))
                self.assertEqual(len(harness.script.requests), 1)
                second, second_receipt = harness.evaluate(questions=QUESTIONS)
                self.assertEqual(sorted(second), ["q"])
                self.assertEqual(second_receipt["status"], "validated")
                self.assertEqual(len(harness.script.requests), 2)


class SensitiveFastPathCases(unittest.TestCase):
    """The 18 fixed cases of gateway/senscheck.py, as regression cases.

    Three credentials times six request shapes. A credential planted in a
    value, a key or an instruction is refused; the rest pass.
    """

    def test_eighteen_fixed_cases(self):
        count = 0
        for key in (SENTINEL, 'abc"defgh123', "back\\slashkey9"):
            provider = OpenRouterProvider(key, environ={}, exchange=object())
            q = {"q": dict(QUESTION)}
            cases = [
                ({"x": "clean"}, q, {}, None),
                ({"x": "pre" + key + "post"}, q, {}, "sensitive_input"),
                ({key: 1}, q, {}, "sensitive_input"),
                ({"x": "clean"}, {"q": {**QUESTION, "instructions": "has " + key}}, {},
                 "sensitive_input"),
                ({"x": 12345}, q, {}, None),
                ({"x": "clean"}, q, {"window_id": key[:8]}, None),
            ]
            for state, questions, meta, expected in cases:
                with self.subTest(key=key, state=state):
                    got = _result(provider.check_sensitive, state, questions, meta)
                    old = _result(_old_check_sensitive, (key,), (state, questions, meta))
                    self.assertEqual(got, old)
                    if expected is None:
                        self.assertEqual(got, ("value", None))
                    else:
                        self.assertEqual(got, ("raised", ProviderError, expected))
                count += 1
        self.assertEqual(count, 18)


if __name__ == "__main__":
    unittest.main()
