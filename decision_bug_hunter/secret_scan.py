"""Detect obvious credential-shaped text before any of it can be sent.

The scan is one regular-expression pass over the joined lines. It reports a
pattern id and a one-based line number per hit and never returns, prints or
stores the matched text. It is a guard against obvious accidents, not a
secret scanner: a token in an unrecognised shape passes, and a recognised
shape that is not a live credential is still reported (``--allow-secrets``
exists for that case).
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable, Sequence
import re

#: The edge in front of a token: not part of a longer identifier or token,
#: or directly after a backslash escape (\n, \t, \", \u0022, \x22) or a
#: percent-encoded byte (%3D, %22), whose last character would otherwise
#: look like part of an identifier.
#: (``\x5c`` is a literal backslash in the expression.)
_EDGE = (r"(?:(?<![A-Za-z0-9_-])|(?<=\x5c[abfnrtv0'\x22/])|(?<=\x5cu[0-9A-Fa-f]{4})"
         r"|(?<=\x5cx[0-9A-Fa-f]{2})|(?<=%[0-9A-Fa-f]{2}))")
#: Families that delimit themselves and need no edge: a PEM header cannot be
#: the tail of a longer identifier.
_NO_EDGE = frozenset({"private_key"})
#: Pattern ids in report order. Each id names a credential family only.
PATTERNS: tuple[tuple[str, str], ...] = (
    ("openrouter", r"sk-or-v1-[0-9a-f]{64}"),
    ("anthropic", r"sk-ant-[a-z]{2,8}[0-9]{2}-[A-Za-z0-9_-]{32,}"),
    # OpenAI project, service-account, admin and legacy user keys; the
    # OpenRouter and Anthropic prefixes are their own families.
    ("openai", r"sk-(?!or-|ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"),
    ("aws", r"(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Za-z])"),
    ("private_key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    ("github", r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
    ("slack", r"xox[abpr]-[0-9]{6,}-[A-Za-z0-9-]{8,}"),
    ("google", r"(?:AIza[0-9A-Za-z_-]{35}|GOCSPX-[A-Za-z0-9_-]{28})"),
    ("stripe", r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}"),
)
#: The literal head of every alternative in PATTERNS (tests check this). The
#: expression is case-sensitive, the edge only looks behind a head, and the
#: text is never normalised, so a match always contains one of these verbatim.
#: A text with none of them can be skipped without running the expression.
_PREFIXES: tuple[str, ...] = (
    "sk-", "AKIA", "ASIA", "-----BEGIN ", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "github_pat_", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "AIza", "GOCSPX-",
    "sk_live_", "sk_test_", "rk_live_", "rk_test_", "eyJ",
)
PATTERN_IDS: tuple[str, ...] = tuple(pattern_id for pattern_id, _ in PATTERNS)
#: Families whose random body must mix letter cases and digits, so that a
#: long kebab-case identifier after ``sk-`` is not taken for a key.
_MIXED_BODY = frozenset({"openai"})

_SCANNER = re.compile("|".join(
    ("" if pattern_id in _NO_EDGE else _EDGE) + f"(?P<{pattern_id}>{pattern})"
    for pattern_id, pattern in PATTERNS))


def _mixed(text: str) -> bool:
    return (any(c.isdigit() for c in text) and any(c.isupper() for c in text)
            and any(c.islower() for c in text))


def scan_lines(lines: Sequence[str] | Iterable[str]) -> list[tuple[str, int]]:
    """Sorted, distinct ``(pattern_id, line_no)`` pairs; never the matched text.

    *lines* are physical lines without their terminators; line numbers are
    one-based. No pattern spans a line break, so joining the lines is exact.
    """
    lines = tuple(lines)
    if not lines:
        return []
    text = "\n".join(lines)
    if not any(map(text.__contains__, _PREFIXES)):
        return []
    starts: list[int] = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    hits: set[tuple[str, int]] = set()
    for match in _SCANNER.finditer(text):
        pattern_id = match.lastgroup
        if pattern_id is None:  # pragma: no cover - every branch is named
            continue
        if pattern_id in _MIXED_BODY and not _mixed(match.group(pattern_id)[3:]):
            continue
        hits.add((pattern_id, bisect_right(starts, match.start())))
    return sorted(hits, key=lambda hit: (hit[1], PATTERN_IDS.index(hit[0])))


def describe(label: str, hits: Sequence[tuple[str, int]], limit: int = 20) -> str:
    """One stderr line naming *label*, line numbers and pattern ids only."""
    shown = ", ".join(f"line {line_no} ({pattern_id})"
                      for pattern_id, line_no in hits[:limit])
    more = f" (+{len(hits) - limit} more)" if len(hits) > limit else ""
    return f"Secret-shaped content in {label}: {shown}{more}."
