"""Equivalence of the literal-head prefilter in ``secret_scan.scan_lines`` (offline).

``scan_lines`` returns early when no literal head of PATTERNS occurs in the
text. ``old_scan_lines`` below is a frozen copy of the scanner as it stood
before that early return, so each test compares the shipped function with the
old behavior on the same inputs. Tokens are built at runtime from fragments,
as in ``tests/test_secret_scan.py``.
"""
from bisect import bisect_right
import random
import re
import re._constants as sre_constants
import re._parser as sre_parser
import subprocess
import unittest
from unittest.mock import patch

from decision_bug_hunter import secret_scan
from decision_bug_hunter.secret_scan import PATTERN_IDS, PATTERNS, _PREFIXES, scan_lines
from tests.test_secret_scan import ROOT, token

BACKSLASH = chr(92)

# Frozen copy of the edge and of PATTERNS, taken before the prefilter.
_OLD_EDGE = (r"(?:(?<![A-Za-z0-9_-])|(?<=\x5c[abfnrtv0'\x22/])|(?<=\x5cu[0-9A-Fa-f]{4})"
             r"|(?<=\x5cx[0-9A-Fa-f]{2})|(?<=%[0-9A-Fa-f]{2}))")
_OLD_NO_EDGE = frozenset({"private_key"})
_OLD_PATTERNS: tuple[tuple[str, str], ...] = (
    ("openrouter", r"sk-or-v1-[0-9a-f]{64}"),
    ("anthropic", r"sk-ant-[a-z]{2,8}[0-9]{2}-[A-Za-z0-9_-]{32,}"),
    ("openai", r"sk-(?!or-|ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"),
    ("aws", r"(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Za-z])"),
    ("private_key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    ("github", r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
    ("slack", r"xox[abpr]-[0-9]{6,}-[A-Za-z0-9-]{8,}"),
    ("google", r"(?:AIza[0-9A-Za-z_-]{35}|GOCSPX-[A-Za-z0-9_-]{28})"),
    ("stripe", r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}"),
)
_OLD_IDS: tuple[str, ...] = tuple(pattern_id for pattern_id, _ in _OLD_PATTERNS)
_OLD_MIXED_BODY = frozenset({"openai"})
_OLD_SCANNER = re.compile("|".join(
    ("" if pattern_id in _OLD_NO_EDGE else _OLD_EDGE) + f"(?P<{pattern_id}>{pattern})"
    for pattern_id, pattern in _OLD_PATTERNS))


def _old_mixed(text: str) -> bool:
    return (any(c.isdigit() for c in text) and any(c.isupper() for c in text)
            and any(c.islower() for c in text))


def old_scan_lines(lines):
    """The scanner before the prefilter: one regular-expression pass, no early return."""
    lines = tuple(lines)
    if not lines:
        return []
    text = "\n".join(lines)
    starts = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    hits = set()
    for match in _OLD_SCANNER.finditer(text):
        pattern_id = match.lastgroup
        if pattern_id is None:
            continue
        if pattern_id in _OLD_MIXED_BODY and not _old_mixed(match.group(pattern_id)[3:]):
            continue
        hits.add((pattern_id, bisect_right(starts, match.start())))
    return sorted(hits, key=lambda hit: (hit[1], _OLD_IDS.index(hit[0])))


#: Near misses from tests/test_secret_scan.py: each one is not a token.
NEAR_MISSES = (
    "sk-" + "or-v1-" + "0123456789abcdef" * 3,
    "sk-" + "some-long-kebab-case-identifier-name-x",
    "AK" + "IA" + "SHORT",
    "-----" + "BEGIN PUBLIC KEY" + "-----",
    "gh" + "p_short",
    "xo" + "xb-notdigits-abcdefgh",
    "pk" + "_test_" + "Synthetic0Fixture0",
    "masked sk-" + "proj-ab***yz",
    "plain prose without credentials",
)
#: Escape and percent-encoded forms in front of a token, as in the existing tests.
ESCAPES = (BACKSLASH + "n", BACKSLASH + "t", BACKSLASH + chr(34), BACKSLASH + "u0022",
           BACKSLASH + "x22", "%3D", "%22", "%3d")
TOKENS = tuple(token(pattern_id) for pattern_id in PATTERN_IDS)
#: Case changes and truncations of each token, so near misses differ in case or length.
VARIANTS = tuple(variant for tok in TOKENS for variant in (
    tok[1:], tok[:-1], tok.swapcase(), tok.upper(), tok.lower(), "x" + tok, tok + "Z"))
FRAGMENTS = ("sk-", "SK-", "sk_", "sk_live", "AKIA", "AKIASHORT", "ASIA", "akia", "-----BEGIN ",
             "-----BEGIN", "PRIVATE KEY", "-----", "ghp_", "gho_", "GHP_", "github_pat_",
             "github_pat", "xoxb-", "xoxq-", "AIza", "AIz", "GOCSPX-", "GOCSPX", "sk_test_",
             "rk_live_", "rk_test", "eyJ", "eyJhbGci", "ey", "_", "-", ".", "x", " ", "\n",
             '"', "'", "abc", "tn", BACKSLASH, "%")
ALPHABET = "abcXYZ0129_-.=/ "


def fuzz_text(rng: random.Random) -> str:
    """A seeded text mixing real tokens, near misses, escapes and random filler."""
    parts = []
    for _ in range(rng.randint(1, 14)):
        roll = rng.random()
        if roll < 0.18:
            parts.append(rng.choice(TOKENS))
        elif roll < 0.30:
            parts.append(rng.choice(ESCAPES) + rng.choice(TOKENS))
        elif roll < 0.36:
            parts.append(rng.choice(VARIANTS))
        elif roll < 0.70:
            parts.append(rng.choice(FRAGMENTS))
        else:
            parts.append("".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 8))))
    return "".join(parts)


def _extend(heads: set[str], items) -> tuple[set[str], bool]:
    """Extend *heads* by *items*; the flag says whether every item was literal."""
    for op, av in items:
        if op is sre_constants.LITERAL:
            heads = {head + chr(av) for head in heads}
        elif op is sre_constants.IN and all(
                sub_op is sre_constants.LITERAL for sub_op, _ in av):
            heads = {head + chr(value) for head in heads for _, value in av}
        elif op is sre_constants.SUBPATTERN:
            heads, done = _extend(heads, av[-1].data)
            if not done:
                return heads, False
        elif op is sre_constants.BRANCH:
            results = [_extend(heads, alt.data) for alt in av[1]]
            heads = set().union(*(extended for extended, _ in results))
            if not all(done for _, done in results):
                return heads, False
        else:
            return heads, False
    return heads, True


def _heads(items) -> set[str]:
    """Literal strings that every match of *items* starts with, alternations expanded."""
    return _extend({""}, items)[0]


class PrefilterTests(unittest.TestCase):
    def test_oracle_expression_is_the_shipped_expression(self):
        self.assertEqual(_OLD_SCANNER.pattern, secret_scan._SCANNER.pattern)
        self.assertEqual(_OLD_IDS, PATTERN_IDS)

    def test_every_pattern_leading_literal_starts_with_a_prefix(self):
        for pattern_id, pattern in PATTERNS:
            with self.subTest(pattern=pattern_id):
                heads = _heads(sre_parser.parse(pattern).data)
                self.assertTrue(heads)
                for head in heads:
                    self.assertTrue(any(head.startswith(prefix) for prefix in _PREFIXES),
                                    head)
        every_head = set()
        for _, pattern in PATTERNS:
            every_head |= _heads(sre_parser.parse(pattern).data)
        for prefix in _PREFIXES:
            with self.subTest(prefix=prefix):
                self.assertTrue(any(head.startswith(prefix) for head in every_head))

    def test_prefilter_skips_the_expression_only_without_a_prefix(self):
        with patch.object(secret_scan, "_SCANNER", wraps=secret_scan._SCANNER) as scanner:
            self.assertEqual(scan_lines(["plain prose", "x = 1"]), [])
            self.assertEqual(scanner.finditer.call_count, 0)
            self.assertEqual(scan_lines(["a", "x = " + TOKENS[0]]), [("openrouter", 2)])
            self.assertEqual(scanner.finditer.call_count, 1)

    def test_positive_samples_match_the_oracle(self):
        for pattern_id in PATTERN_IDS:
            with self.subTest(pattern=pattern_id):
                plain = ["clean = 1", f"value = '{token(pattern_id)}'", "done"]
                self.assertEqual(scan_lines(plain), [(pattern_id, 2)])
                self.assertEqual(old_scan_lines(plain), [(pattern_id, 2)])
                for name, prefix in zip(("newline", "tab", "quote", "unicode", "hex",
                                         "percent equals", "percent quote",
                                         "lower percent"), ESCAPES):
                    line = f'value = "x{prefix}{token(pattern_id)}"'
                    with self.subTest(escape=name):
                        self.assertEqual(scan_lines([line]), [(pattern_id, 1)])
                        self.assertEqual(scan_lines([line]), old_scan_lines([line]))
                for glued in ("abc", "x_", "tn", "x-"):
                    line = glued + token(pattern_id)
                    self.assertEqual(scan_lines([line]), old_scan_lines([line]))

    def test_near_misses_match_the_oracle(self):
        self.assertEqual(scan_lines(list(NEAR_MISSES)), [])
        self.assertEqual(old_scan_lines(list(NEAR_MISSES)), [])
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                self.assertEqual(scan_lines([variant]), old_scan_lines([variant]))

    def test_seeded_fuzz_texts_match_the_oracle(self):
        mismatches = []
        hits = empty = 0
        for seed in range(3000):
            text = fuzz_text(random.Random(seed))
            lines = text.split("\n")
            # Alternate list and iterator input: both must give the same result.
            new = scan_lines(lines if seed % 2 else iter(lines))
            old = old_scan_lines(lines)
            if new != old:
                mismatches.append(seed)
            if old:
                hits += 1
            else:
                empty += 1
        self.assertEqual(mismatches, [])
        self.assertGreater(hits, 300)
        self.assertGreater(empty, 300)

    def test_repository_python_files_match_the_oracle(self):
        try:
            listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                                    capture_output=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("not a git checkout")
        checked = 0
        mismatches = []
        for name in filter(None, listed.decode("utf-8").split("\0")):
            if not name.endswith(".py"):
                continue
            try:
                text = (ROOT / name).read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            lines = text.splitlines()
            checked += 1
            if scan_lines(lines) != old_scan_lines(lines):
                mismatches.append(name)
        self.assertGreater(checked, 50)
        self.assertEqual(mismatches, [])

    def test_case_changed_prefixes_are_not_hits(self):
        # The expression is case-sensitive, so a case-changed head alone is no hit.
        for prefix in _PREFIXES:
            swapped = prefix.swapcase()
            if swapped == prefix:
                continue
            with self.subTest(prefix=prefix):
                line = swapped + "0123456789abcdefGHIJKLMNOPQRSTUVWXYZ"
                self.assertEqual(scan_lines([line]), old_scan_lines([line]))
