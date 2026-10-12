"""Deterministic synthetic provider. Tests routing, NOT judge bug detection.

No network, no learned model, no runtime fallback. Faults are preassigned spans.
"""
from contextlib import contextmanager
from decimal import Decimal
import hashlib
import json
import os
import re
from typing import Iterator
from unittest.mock import patch

from decision_bug_hunter.core import Source, Span
from decision_bug_hunter import protocol
from decision_bug_hunter import questions as _questions

KEY = "offline-synthetic-key-not-a-real-credential"

#: Exact names removed by ``clean_provider_env`` besides the prefix rules.
PROVIDER_VARIABLES = ("DBH_JUDGE", "DBH_PROVIDER", "AZURE_ENTRA_TOKEN", "SSLKEYLOGFILE",
                      "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
PROVIDER_PREFIXES = ("OPENAI_", "OPENROUTER_", "DBH_FOUNDRY_")


def is_provider_variable(name):
    upper = name.upper()
    return (upper.endswith("_API_KEY") or upper.startswith(PROVIDER_PREFIXES)
            or upper in PROVIDER_VARIABLES)


@contextmanager
def clean_provider_env(*also_remove: str, **values: str) -> Iterator[None]:
    """Scrub every provider, credential, proxy and TLS key-log variable.

    Removes ``*_API_KEY``, ``OPENAI_*``, ``OPENROUTER_*``, ``DBH_FOUNDRY_*``,
    ``DBH_JUDGE``, ``DBH_PROVIDER``, ``AZURE_ENTRA_TOKEN``, ``SSLKEYLOGFILE`` and
    the proxy variables (any case), plus ``also_remove``;
    then sets ``values``. The original environment is restored on exit.
    """
    drop = {name.upper() for name in also_remove}
    kept = {k: v for k, v in os.environ.items()
            if not is_provider_variable(k) and k.upper() not in drop}
    with patch.dict(os.environ, kept, clear=True):
        os.environ.update(values)
        yield


def _number(value):
    """Fixture numbers go on the wire as plain JSON numbers."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def openrouter_body(answers, *, model="openai/gpt-6-luna-decisions-20261006",
                    provider="OpenAI", generation_id="gen-dec-offlinefixture0000000000000000",
                    input_tokens=100, output_tokens=0, cost=None, omit=(), **extra):
    """A 200 body in the shape OpenRouter returned on 2026-10-06.

    ``answers`` is the local map {name: answer}; OpenRouter returns the same
    map. ``cost`` defaults to input_tokens * 1e-7 (Luna bills input only).
    ``omit`` drops top-level keys; ``extra`` adds or replaces them.
    """
    if cost is None:
        cost = float(Decimal(input_tokens) * Decimal("1e-7"))
    data = {"answers": {name: {k: (_number(v) if k != "probabilities" else
                                   {o: _number(p) for o, p in v.items()})
                               for k, v in answer.items()}
                        for name, answer in answers.items()},
            "id": generation_id, "model": model, "provider": provider,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                      "cost": cost}}
    data.update(extra)
    for key in omit:
        data.pop(key, None)
    return json.dumps(data).encode()


def openai_body(answers, *, model="gpt-6-luna", input_tokens=100, output_tokens=0,
                omit=(), **extra):
    """A 200 body in the documented OpenAI Decisions shape.

    Local noul answers become ``predicate`` objects and choice answers carry a
    list of {value, probability}; the answers travel as a list with names.
    """
    documented = []
    for name, answer in answers.items():
        if answer["type"] == "noul":
            documented.append({"type": "predicate", "name": name,
                               "probability": _number(answer["noul"])})
        elif answer["type"] == "choice":
            documented.append({
                "type": "choice", "name": name, "choice": answer["choice"],
                "probabilities": [{"value": k, "probability": _number(v)}
                                  for k, v in answer["probabilities"].items()],
                "confidence": _number(answer["confidence"])})
        else:
            documented.append({"name": name, **answer})
    data = {"model": model, "answers": documented,
            "usage": {"input_tokens": input_tokens,
                      "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                      "output_tokens": output_tokens,
                      "output_tokens_details": {"reasoning_tokens": 0},
                      "total_tokens": input_tokens + output_tokens}}
    data.update(extra)
    for key in omit:
        data.pop(key, None)
    return json.dumps(data).encode()



def source(n, text=None):
    lines = tuple(text if text is not None else f"fixture line {i}"
                  for i in range(1, n + 1))
    return Source("fixture.txt", hashlib.sha256("\n".join(lines).encode()).hexdigest(),
                  lines, "utf-8")


_CONTROL_WORD = re.compile(r"Does any source line contain the word '([a-z]+)'\?\Z")
_CONTROL_LINES = re.compile(r"Does state\.total_lines equal ([0-9]+)\?\Z")


def control_answer(question, state):
    """A correct judge's answer to a DBH control question (WP-14).

    The OpenAI route appends the predicate criteria after a line break; the
    control itself is the first line.
    """
    text = question["instructions"].split("\n", 1)[0]
    word = _CONTROL_WORD.fullmatch(text)
    if text == _questions.CONTROL_MUST_TRUE:
        holds = bool(state.get("context_scope"))
    elif word:
        holds = word.group(1) in json.dumps(state, ensure_ascii=False).casefold()
    else:
        holds = int(_CONTROL_LINES.fullmatch(text).group(1)) == state.get("total_lines")
    return {"type": "noul", "noul": 0.99 if holds else 0.01}


def is_control(qid):
    return _questions.CONTROL_NAME.fullmatch(qid) is not None


def ranges(result):
    return {(f["start_line"], f["end_line"]) for f in result["findings"]}


def spans_in(text):
    return [Span(int(a), int(b)) for a, b in re.findall(r"L(\d+)-(\d+)", text)]


class FixtureProvider:
    provider_id = "offline-fixture"
    model_id = None
    synthetic = True
    rounding_places = 2
    def __init__(self, bugs=(), *, override=None, need_packet=None, control_override=None):
        self.bugs = [Span(*s) if isinstance(s, tuple) else s for s in bugs]
        self.override = override
        self.need_packet = need_packet
        # control_override(qid, question, state) -> answer or None (WP-14).
        self.control_override = control_override
        self.requests = []

    def contains_bug(self, span):
        return any(span.start <= b.start and b.end <= span.end for b in self.bugs)

    def answer(self, qid, q, state):
        if is_control(qid):
            answer = (self.control_override(qid, q, state)
                      if self.control_override else None)
            return answer if answer is not None else control_answer(q, state)
        parsed = spans_in(q["instructions"])
        target = parsed[0]
        answer = None
        if self.override:
            answer = self.override(qid, q, state, target)
        if answer is not None:
            return answer
        if q["type"] == "choice":
            if qid == "action":
                chosen = "finish"
                return {"type": "choice", "choice": chosen, "confidence": 1,
                        "probabilities": {k: int(k == chosen) for k in q["criteria"]}}
            options = [s for s in spans_in(" ".join(q["criteria"]))
                       if self.contains_bug(s)]
            if qid == "context_where":
                options = [s for s in spans_in(" ".join(q["criteria"]))
                           if self.need_packet is not None and
                           s.start <= self.need_packet <= s.end]
            elif qid == "where":
                # Prefer a known exact fixture span. When all have been selected,
                # abstain rather than invent a second independent defect.
                options = [s for s in options if s in self.bugs]
            chosen = min(options, key=lambda s: (s.size, s.start)).id if options else "none"
            return {"type": "choice", "choice": chosen, "confidence": 1,
                    "probabilities": {k: int(k == chosen) for k in q["criteria"]}}
        if qid.startswith(("read_with_", "requirement_", "action_requirement_",
                           "evidence_", "relation_", "verify_evidence_")):
            return {"type": "noul", "noul": 0.05}
        if qid == "continue":
            return {"type": "noul", "noul": 0.95}
        value = 0.95 if self.contains_bug(target) else 0.05
        if qid == "need_context":
            visible = {line["line"] for e in state["excerpts"] for line in e["lines"]}
            value = 0.95 if (self.need_packet is not None and
                    self.contains_bug(target) and self.need_packet not in visible) else 0.05
        elif qid.startswith("relevance_"):
            packet = parsed[0]
            value = 0.95 if (self.need_packet is not None and
                            packet.start <= self.need_packet <= packet.end) else 0.05
        elif qid == "covered":
            children = parsed[1:]
            relevant = [b for b in self.bugs if target.start <= b.start and b.end <= target.end]
            value = 0.95 if relevant and all(any(
                c.start <= b.start and b.end <= c.end for c in children)
                for b in relevant) else 0.05
        return {"type": "noul", "noul": value}

    def raw(self, state, questions):
        self.requests.append({"state": state, "questions": questions})
        return json.dumps({"contract": protocol.CONTRACT_VERSION,
            "answers": {qid: self.answer(qid, q, state) for qid, q in questions.items()},
            "usage": {"input_tokens": 100, "output_tokens": len(questions)}}).encode()

    def evaluate(self, state, questions, *, metadata):
        # Even pure engine tests use the real response validator.
        return protocol.validate_answers(self.raw(state, questions), questions, rounding_places=self.rounding_places)[0]



def scan(source, gateway, *args, context_scope="declared_standalone", **kwargs):
    """Test helper. The public scan() requires an explicit scope; tests
    declare theirs here, in one visible place, never via a silent default."""
    from decision_bug_hunter.core import scan as _scan
    return _scan(source, gateway, *args, context_scope=context_scope, **kwargs)
