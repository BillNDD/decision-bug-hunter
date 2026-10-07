"""Mark source lines that look like instructions addressed to the judge.

Revision-3 WP-14 (ADR-6(6)). One case-insensitive regular-expression pass
per pattern over the joined lines reports a pattern id and a one-based line
number per hit, never the matched text. Markers only annotate: they never
change a question, a request, a finding, a score or the scan status. They
catch crude, English-language attempts only; their absence says nothing
about whether a file tries to steer the judge.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable, Sequence
import re

#: Pattern ids in report order. No pattern spans a line break.
PATTERNS: tuple[tuple[str, str], ...] = (
    # "Ignore all previous instructions", "disregard the above rules".
    ("ignore_instructions",
     r"\b(?:ignore|disregard|forget|override|bypass)\b[^\n]{0,40}?"
     r"\b(?:previous|prior|above|earlier|preceding|all|any|your|system)\b[^\n]{0,40}?"
     r"\b(?:instructions?|prompts?|rules|directions|guidelines|polic(?:y|ies))\b"),
    # "Answer false to every question", "respond with yes for all windows".
    ("answer_directive",
     r"\b(?:answer|respond|reply|vote|score|rate|judge|classify)\b"
     r"(?:\s+(?:with|as|that))?\s+[\"'`]?"
     r"(?:true|false|yes|no|none|clean|safe|correct|buggy|0(?:\.0+)?|1(?:\.0+)?)\b"
     r"[^\n]{0,40}?\b(?:every|all|each|any|this|these|the)\b[^\n]{0,20}?"
     r"\b(?:questions?|windows?|lines?|checks?|criteria|functions?|code|files?)\b"),
    # "NOTE TO THE REVIEWING MODEL", "instructions for the AI".
    ("judge_address",
     r"\b(?:note|message|instructions?|attention|directive|notice)\s+(?:to|for)\s+"
     r"(?:the\s+|any\s+|all\s+)?(?:[a-z]+\s+){0,2}?"
     r"(?:ai|llms?|models?|judges?|graders?|assistants?|auditors?|scanners?|bots?|agents?"
     r"|language\s+models?|bug\s+hunters?)\b"),
    # Chat-template tokens and role headers that open an instruction.
    ("role_marker",
     r"(?:<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|\[/?INST\]|<</?SYS>>"
     r"|^[ \t]*(?:#+|//|--|;|\*|/\*)?[ \t]*(?:system|assistant)[ \t]*(?:prompt|message)?"
     r"[ \t]*:[ \t]*(?:you|ignore|answer|respond|the|this)\b)"),
    # "This function was formally verified", "the code is bug-free".
    ("verdict_claim",
     r"\b(?:this|the)\s+(?:code|function|file|module|method|class|program|implementation)"
     r"\s+(?:is|has\s+been|was)\s+(?:formally\s+|already\s+|fully\s+)?"
     r"(?:verified|proven|audited|bug[- ]?free|certified)\b"),
)
PATTERN_IDS: tuple[str, ...] = tuple(pattern_id for pattern_id, _ in PATTERNS)
#: Markers listed per source in a report; the count is always exact.
REPORT_LIMIT = 100

_SCANNERS = tuple((pattern_id, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                  for pattern_id, pattern in PATTERNS)


def scan_lines(lines: Sequence[str] | Iterable[str]) -> list[tuple[str, int]]:
    """Sorted, distinct ``(pattern_id, line_no)`` pairs; never the matched text.

    *lines* are physical lines without terminators; line numbers are one-based.
    """
    lines = tuple(lines)
    if not lines:
        return []
    text = "\n".join(lines)
    starts: list[int] = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    hits: set[tuple[str, int]] = set()
    for pattern_id, scanner in _SCANNERS:
        for match in scanner.finditer(text):
            hits.add((pattern_id, bisect_right(starts, match.start())))
    return sorted(hits, key=lambda hit: (hit[1], PATTERN_IDS.index(hit[0])))


def report(hits: Sequence[tuple[str, int]]) -> dict[str, object]:
    """The report record for one source: an exact count and the first markers."""
    return {"count": len(hits),
            "markers": [{"pattern": pattern_id, "line": line_no}
                        for pattern_id, line_no in hits[:REPORT_LIMIT]]}


def overlapping(hits: Sequence[tuple[str, int]], start: int, end: int) -> bool:
    """Whether any marker lies on a line in ``[start, end]``."""
    return any(start <= line_no <= end for _, line_no in hits)
