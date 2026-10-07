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
import unittest
from decimal import Decimal

from decision_bug_hunter import decisions, openrouter, protocol
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import QUESTION, ProviderError

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

    def test_recursion_limit_is_reached_at_the_same_depth(self):
        """The flat walker keeps one call frame per container level, as before."""
        for depth in range(930, 1000):
            nested = "needle-depth"
            for index in range(depth):
                nested = [nested] if index % 2 else {"k": nested}
            with self.subTest(depth=depth):
                self.assertEqual(_result(protocol._secret_in, "needle-depth", [nested]),
                                 _result(_old_secret_in, "needle-depth", [nested]))


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
