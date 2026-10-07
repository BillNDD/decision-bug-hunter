"""Old-versus-new oracles for the protocol snapshot and question validator.

The frozen copies below are the implementations before the inline-leaf
snapshot and the byte-size and whitespace changes. Every seeded input must
give the same value (types and content, order included) or the same
exception type and code.
"""
from collections import OrderedDict
from decimal import Decimal
import math
import random
import re
import unittest

from decision_bug_hunter import protocol


_WHITESPACE = [chr(code) for code in range(0x110000) if chr(code).isspace()]
_OLD_QUESTION_NAME = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")
_OLD_QUESTION_FIELDS = frozenset({"type", "instructions", "criteria"})
_OLD_NOUL_CRITERIA = frozenset({"true", "false"})
_OLD_MAX_BYTES = 12000


def _snapshot_old(value, depth=0):
    if depth > 32:
        raise protocol.ProviderError("invalid_request")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) is list:
        return [_snapshot_old(item, depth + 1) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _snapshot_old(item, depth + 1) for key, item in value.items()}
    raise protocol.ProviderError("invalid_request")


def _validate_questions_old(questions, max_questions=protocol.MAX_QUESTIONS):
    if type(questions) is not dict or not 1 <= len(questions) <= max_questions:
        raise protocol.ProviderError("invalid_request")
    for qid, q in questions.items():
        if (type(qid) is not str or not _OLD_QUESTION_NAME.fullmatch(qid)
                or type(q) is not dict or q.keys() != _OLD_QUESTION_FIELDS
                or type(q["instructions"]) is not str or not q["instructions"].strip()
                or len(q["instructions"].encode("utf-8")) > _OLD_MAX_BYTES):
            raise protocol.ProviderError("invalid_request")
        c = q["criteria"]
        if type(c) is not dict:
            raise protocol.ProviderError("invalid_request")
        if q["type"] == "noul":
            if c.keys() != _OLD_NOUL_CRITERIA:
                raise protocol.ProviderError("invalid_request")
        elif q["type"] == "choice":
            if not 2 <= len(c) <= 255:
                raise protocol.ProviderError("invalid_request")
        else:
            raise protocol.ProviderError("invalid_request")
        for key, text in c.items():
            if (type(key) is not str or not _OLD_QUESTION_NAME.fullmatch(key)
                    or type(text) is not str or not text.strip()
                    or len(text.encode("utf-8")) > _OLD_MAX_BYTES):
                raise protocol.ProviderError("invalid_request")


class _StrSub(str):
    pass


class _IntSub(int):
    pass


class _ListSub(list):
    pass


class _DictSub(dict):
    pass


class _Custom:
    pass


def _shape(value):
    """A comparable rendering of a snapshot: exact types, order and content."""
    kind = type(value)
    if kind is list:
        return ("list", tuple(_shape(item) for item in value))
    if kind is dict:
        return ("dict", tuple((_shape(key), _shape(item)) for key, item in value.items()))
    if kind is float:
        return ("float", repr(value))
    return (kind, value)


def _snapshot_outcome(function, value):
    try:
        return ("ok", _shape(function(value)))
    except Exception as exc:
        return ("error", type(exc), getattr(exc, "code", None))


def _validate_outcome(function, questions, limit):
    try:
        function(questions, limit)
    except Exception as exc:
        return ("error", type(exc), getattr(exc, "code", None))
    return ("ok", None)


# Valid leaves: exact str, bool, int, None and finite floats, plus empty
# containers. Invalid leaves are rejected by both versions.
_VALID_LEAVES = (
    lambda r: r.choice(["", "a", "x y", "é", " ", "\ud800", "\U0001F600", "\t"]),
    lambda r: r.randint(-2**40, 2**40),
    lambda r: 10**30,
    lambda r: r.choice([True, False]),
    lambda r: None,
    lambda r: r.uniform(-1e9, 1e9),
    lambda r: r.choice([-0.0, 1e308, 5e-324]),
    lambda r: [],
    lambda r: {},
)
_BAD_LEAVES = (
    lambda r: float("nan"),
    lambda r: r.choice([float("inf"), float("-inf")]),
    lambda r: Decimal("1.25"),
    lambda r: b"bytes",
    lambda r: (1, "t"),
    lambda r: {1, 2},
    lambda r: _Custom(),
    lambda r: _IntSub(3),
    lambda r: _StrSub("sub"),
    lambda r: _ListSub([1]),
    lambda r: _DictSub({"a": 1}),
    lambda r: {1: "non-str key"},
    lambda r: {_StrSub("k"): "v"},
    lambda r: OrderedDict(a=1),
)
_BAD_KEYS = (1, None, b"x", ("t",), _StrSub("z"), 2.5, True)


def _leaf(rng, bad_rate):
    if bad_rate and rng.random() < bad_rate:
        return rng.choice(_BAD_LEAVES)(rng)
    return rng.choice(_VALID_LEAVES)(rng)


def _spine_tree(rng):
    """A chain of 28-34 containers with siblings; leaves land at the limit."""
    bad_rate = rng.choice([0.0, 0.0, 0.0005, 0.005])
    value = _leaf(rng, bad_rate)
    for _ in range(rng.randint(28, 34)):
        if rng.random() < 0.5:
            items = [_leaf(rng, bad_rate) for _ in range(rng.randint(0, 2))]
            items.insert(rng.randint(0, len(items)), value)
            value = items
        else:
            mapping = {f"k{i}": _leaf(rng, bad_rate) for i in range(rng.randint(0, 2))}
            key = "spine"
            if bad_rate and rng.random() < bad_rate * 20:
                key = rng.choice(_BAD_KEYS)
            mapping[key] = value
            value = mapping
    return value


def _free_tree(rng, depth=0):
    """Unshaped trees: random containers, non-str keys, bad leaves."""
    bad_rate = 0.02
    if depth >= 36 or rng.random() < 0.3:
        return _leaf(rng, bad_rate)
    if rng.random() < 0.5:
        return [_free_tree(rng, depth + 1) for _ in range(rng.randint(0, 2))]
    mapping = {}
    for _ in range(rng.randint(0, 2)):
        key = f"f{rng.randint(0, 5)}"
        if rng.random() < 0.05:
            key = rng.choice(_BAD_KEYS)
        mapping[key] = _free_tree(rng, depth + 1)
    return mapping


class SnapshotEquivalenceTests(unittest.TestCase):
    def assert_same(self, value):
        old = _snapshot_outcome(_snapshot_old, value)
        new = _snapshot_outcome(protocol._snapshot, value)
        self.assertEqual(new, old)
        return old[0]

    def test_seeded_spine_trees_at_the_depth_limit(self):
        outcomes = {"ok": 0, "error": 0}
        for seed in range(3200):
            outcomes[self.assert_same(_spine_tree(random.Random(seed)))] += 1
        self.assertGreater(outcomes["ok"], 500)
        self.assertGreater(outcomes["error"], 500)

    def test_seeded_free_trees(self):
        outcomes = {"ok": 0, "error": 0}
        for seed in range(1200):
            outcomes[self.assert_same(_free_tree(random.Random(10_000 + seed)))] += 1
        self.assertGreater(outcomes["ok"], 100)
        self.assertGreater(outcomes["error"], 30)

    def test_depth_limit_is_exact(self):
        for containers in range(30, 35):
            for leaf in ("s", 1, True, None, 1.5, Decimal(1)):
                value = leaf
                for _ in range(containers):
                    value = [value]
                self.assert_same(value)
                mapping = leaf
                for _ in range(containers):
                    mapping = {"k": mapping}
                self.assert_same(mapping)

    def test_str_bool_int_none_children_at_the_limit(self):
        for depth in (31, 32, 33):
            nested = ["leaf"]
            for _ in range(depth):
                nested = [nested]
            self.assert_same(nested)
        self.assertEqual(protocol._snapshot([[None, 1, "x"]]), [[None, 1, "x"]])
        deep = "end"
        for _ in range(32):
            deep = [deep]
        self.assertEqual(protocol._snapshot(deep), _snapshot_old(deep))

    def test_subclasses_and_non_str_keys_are_rejected_as_before(self):
        cases = [_StrSub("a"), [_StrSub("a")], {"a": _IntSub(1)}, {1: "x"},
                 {"a": _ListSub()}, {"a": _DictSub()}, [(1, 2)], {"a": {b"k": 1}},
                 [float("nan")], {"a": [float("inf")]}, [Decimal(0)], [{1, 2}],
                 {"a": _Custom()}, [[[_IntSub(1)]]]]
        for value in cases:
            self.assert_same(value)

    def test_container_identity_and_leaf_objects_are_fresh(self):
        value = {"a": [1, "b", None], "c": {"d": True}}
        result = protocol._snapshot(value)
        self.assertEqual(result, value)
        self.assertIsNot(result, value)
        self.assertIsNot(result["a"], value["a"])
        self.assertIsNot(result["c"], value["c"])
        self.assertIs(type(result["a"][0]), int)
        self.assertIs(type(result["c"]["d"]), bool)


class ValidateQuestionsEquivalenceTests(unittest.TestCase):
    def assert_same(self, questions, limit=protocol.MAX_QUESTIONS):
        old = _validate_outcome(_validate_questions_old, questions, limit)
        new = _validate_outcome(protocol.validate_questions, questions, limit)
        self.assertEqual(new, old)
        return old[0]

    def test_strip_predicate_matches_isspace_for_every_code_point(self):
        # not t.strip() == (not t or t.isspace()) for every one-character str,
        # the empty string and the whitespace-only samples used below.
        mismatches = [code for code in range(0x110000)
                      if (not chr(code).strip()) != (not chr(code) or chr(code).isspace())]
        self.assertEqual(mismatches, [])
        self.assertEqual(not "".strip(), not "" or "".isspace())
        for text in ("", " ", "　 ", "a ", " a", "\x1c\x1d\x1e\x1f", "\udc00 "):
            self.assertEqual(not text.strip(), not text or text.isspace(), repr(text))

    def test_every_unicode_whitespace_code_point_as_instructions_and_criteria(self):
        self.assertGreater(len(_WHITESPACE), 20)
        for char in _WHITESPACE + ["", " \t\n　", "a"]:
            with self.subTest(char=hex(ord(char[0])) if char else "empty"):
                noul = {"type": "noul", "instructions": char,
                        "criteria": {"true": "t", "false": "f"}}
                self.assert_same({"q": noul})
                choice = {"type": "choice", "instructions": "Choose.",
                          "criteria": {"a": char, "b": "B"}}
                self.assert_same({"q": choice})
                noul_criteria = {"type": "noul", "instructions": "Judge.",
                                 "criteria": {"true": char, "false": char + "a" + char}}
                self.assert_same({"q": noul_criteria})

    def test_lone_surrogates_surface_the_same_encode_error(self):
        surrogates = ["\ud800", "a\udfff", "é\ud83d", "\ud800" + " " * 3, "x" * 5 + "\udc80"]
        for text in surrogates:
            with self.subTest(text=repr(text)):
                outcome = self.assert_same({"q": {"type": "noul", "instructions": text,
                                                  "criteria": {"true": "t", "false": "f"}}})
                self.assertEqual(outcome, "error")
                outcome = self.assert_same({"q": {"type": "noul", "instructions": "ok",
                                                  "criteria": {"true": text, "false": "f"}}})
                self.assertEqual(outcome, "error")
        self.assertIs(_validate_outcome(protocol.validate_questions,
                                        {"q": {"type": "noul", "instructions": "\ud800",
                                               "criteria": {"true": "t", "false": "f"}}},
                                        64)[1], UnicodeEncodeError)

    def test_byte_limit_at_and_one_past_for_each_utf8_width(self):
        # One character is 1, 2, 3 or 4 UTF-8 bytes, so each unit fills 12000 bytes.
        for unit, count in (("a", 12000), ("é", 6000), ("€", 4000), ("\U0001F600", 3000)):
            at_limit = unit * count
            past_limit = unit * (count + 1)
            with self.subTest(unit=unit):
                self.assertEqual(self.assert_same(self._noul(at_limit)), "ok")
                self.assertEqual(self.assert_same(self._noul(past_limit)), "error")
                self.assertEqual(self.assert_same(self._choice(at_limit)), "ok")
                self.assertEqual(self.assert_same(self._choice(past_limit)), "error")

    def test_characters_under_the_limit_but_bytes_over_it(self):
        # 4001 euro signs: 4001 characters, 12003 bytes.
        self.assertEqual(self.assert_same(self._noul("€" * 4001)), "error")
        # 11999 ASCII bytes plus one two-byte letter: exactly 12001 bytes.
        self.assertEqual(self.assert_same(self._noul("a" * 11999 + "é")), "error")
        self.assertEqual(self.assert_same(self._noul("a" * 11998 + "é")), "ok")

    def test_question_name_boundaries(self):
        body = {"type": "noul", "instructions": "Judge.",
                "criteria": {"true": "t", "false": "f"}}
        names = ["a" * 96, "a" * 97, "", "bad name", "x\n", "é", "q/1",
                 "ok.name-1_", "A" * 96 + "\n", 1, None, b"q", ("q",), _StrSub("sub")]
        for name in names:
            with self.subTest(name=repr(name)):
                self.assert_same({name: body})
                self.assert_same({"q": {"type": "choice", "instructions": "Choose.",
                                        "criteria": {name: "x", "b": "y"}}})

    def test_wrong_types_shapes_and_counts(self):
        good = {"type": "noul", "instructions": "Judge.",
                "criteria": {"true": "t", "false": "f"}}
        cases = [
            {}, [good], "q", None,
            {"q": None}, {"q": [good]}, {"q": _DictSub(good)},
            {"q": {**good, "extra": 1}}, {"q": {k: v for k, v in good.items() if k != "type"}},
            {"q": {**good, "type": "other"}}, {"q": {**good, "instructions": 1}},
            {"q": {**good, "instructions": None}}, {"q": {**good, "instructions": _StrSub("s")}},
            {"q": {**good, "instructions": ""}}, {"q": {**good, "instructions": "\t \n"}},
            {"q": {**good, "criteria": ["true", "false"]}},
            {"q": {**good, "criteria": {"true": "t"}}},
            {"q": {**good, "criteria": {"true": "t", "false": "f", "x": "y"}}},
            {"q": {**good, "criteria": {"true": 1, "false": "f"}}},
            {"q": {**good, "criteria": {"true": "", "false": "f"}}},
            {"q": {**good, "criteria": {"true": "t", "false": "f"}}, "r": 1},
            {"q": {"type": "choice", "instructions": "Choose.", "criteria": {"a": "x"}}},
            {"q": {"type": "choice", "instructions": "Choose.", "criteria": {}}},
            {"q": {"type": "choice", "instructions": "Choose.",
                   "criteria": {f"o{i}": "x" for i in range(255)}}},
            {"q": {"type": "choice", "instructions": "Choose.",
                   "criteria": {f"o{i}": "x" for i in range(256)}}},
            {"q": {"type": "choice", "instructions": "Choose.",
                   "criteria": {"a": "x", 2: "y"}}},
            {"q": {"type": "choice", "instructions": "Choose.",
                   "criteria": {"a": "x", "b": "\udc00"}}},
            {"q": {"type": "choice", "instructions": "Choose.",
                   "criteria": {"a": "x", "b": "y" * 12001}}},
            {"q": {"type": "choice", "instructions": "Choose.",
                   "criteria": {"a": "x", "b": "y" * 12000}}},
            {"q": {**good, "criteria": {"true": "t", "false": "y" * 12001}}},
            {"q": {**good, "criteria": {"true": "t", "false": "y" * 12000}}},
            {"q": {**good, "criteria": _DictSub({"true": "t", "false": "f"})}},
            {"q": {**good, "criteria": {"true": _StrSub("t"), "false": "f"}}},
            {"q": {**good, "criteria": {"true": ("t",), "false": "f"}}},
            {"q": {**good, "instructions": "x" * 12001}},
            {"q": {**good, "instructions": "x" * 12000}},
        ]
        for questions in cases:
            with self.subTest(questions=repr(questions)[:80]):
                self.assert_same(questions)
        for limit in (0, 1, 2, 64, 200):
            self.assert_same({"q": good, "r": good}, limit)
            self.assert_same({f"q{i}": good for i in range(3)}, limit)

    def test_question_count_boundaries(self):
        good = {"type": "noul", "instructions": "Judge.",
                "criteria": {"true": "t", "false": "f"}}
        self.assert_same({f"q{i}": good for i in range(64)})
        self.assert_same({f"q{i}": good for i in range(65)})
        self.assert_same({f"q{i}": good for i in range(200)}, 200)

    def test_seeded_random_question_maps(self):
        names = ["q1", "a" * 96, "a" * 97, "", "bad name", "x\n", "é", "ok.name-1_",
                 "q/1", 1, None, b"q", ("q",), _StrSub("sub")]
        valid_texts = ["Judge.", "a", "é" * 6000, "a" * 12000, "€" * 4000,
                       "\U0001F600" * 3000, "x" + " " * 11999, " a ", "Choose one.",
                       "é" * 5999]
        bad_texts = ["", " ", "\t\n", "　", "  ", "\ud800", "a\ud800",
                     "é" * 6001, "a" * 12001, "€" * 4001, "\U0001F600" * 3001,
                     "x" + " " * 12000, 1, None, _StrSub("s")]
        outcomes = {"ok": 0, "error": 0}
        for seed in range(2500):
            rng = random.Random(40_000 + seed)
            questions = {}
            for _ in range(rng.randint(0, 3)):
                name = rng.choice(names) if rng.random() < 0.1 else f"q{rng.randint(0, 9)}"
                if rng.random() < 0.08:
                    text = "".join(rng.choice(_WHITESPACE) for _ in range(rng.randint(1, 4)))
                else:
                    text = rng.choice(bad_texts if rng.random() < 0.08 else valid_texts)
                if rng.random() < 0.6:
                    kind = "noul"
                    criteria = {"true": rng.choice(valid_texts), "false": rng.choice(valid_texts)}
                    if rng.random() < 0.08:
                        criteria["false"] = rng.choice(bad_texts)
                else:
                    kind = "choice"
                    options = rng.choice([1, 2, 2, 3, 3, 255, 256])
                    criteria = {f"o{i}": rng.choice(valid_texts) for i in range(options)}
                    if rng.random() < 0.05:
                        criteria[rng.choice(names)] = "x"
                question = {"type": kind, "instructions": text, "criteria": criteria}
                if rng.random() < 0.03:
                    question.pop("criteria")
                questions[name] = question
            limit = rng.choice([1, 2, 3, 64])
            outcomes[self.assert_same(questions, limit)] += 1
        self.assertGreater(outcomes["ok"], 300)
        self.assertGreater(outcomes["error"], 300)

    @staticmethod
    def _noul(text):
        return {"q": {"type": "noul", "instructions": text,
                      "criteria": {"true": "t", "false": "f"}}}

    @staticmethod
    def _choice(text):
        return {"q": {"type": "choice", "instructions": text,
                      "criteria": {"a": "A", "b": "B"}}}


if __name__ == "__main__":
    unittest.main()
