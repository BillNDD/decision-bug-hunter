"""Versioned, generic decision questions. No bug taxonomy or generated text."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from decimal import Decimal
import hashlib
import json
import re
from importlib.resources import files

from .core import Source, Span, physical_lines, STATE_LAYOUTS, DEFAULT_STATE_LAYOUT
from .protocol import (encode_request, ProviderError, MAX_QUESTIONS, MAX_STATE_BYTES,
                  MAX_REQUEST_BYTES, CONTRACT_VERSION, _snapshot, _json, validate_questions,
                  _encode_validated_request)

#: Default request state layout (ADR-5(4)). ``"v1"`` is the pre-release layout
#: and policy (byte for byte, requirement wording excepted); ``"v2"`` puts the
#: four DBH-authored scalars first, moves ``specification.mode`` to top-level
#: ``specification_mode`` and adds the imitation warning to the policy. v1 is
#: the default because the labeled catalog showed v2 adding false positives on
#: corrected controls. It is read at call time; a scan selects its layout with
#: ``Config.state_layout``, which overrides this constant for the run.
STATE_LAYOUT = DEFAULT_STATE_LAYOUT
#: The only top-level fields DBH writes itself, in v2 wire order.
TRUSTED_STATE_FIELDS = ("source_sha256", "total_lines", "context_scope",
                        "specification_mode")
#: Fields that may carry untrusted text, in v2 wire order. Any other field
#: follows these in its existing order.
UNTRUSTED_STATE_FIELDS = ("file", "excerpts", "specification", "related_sources",
                          "investigation", "investigation_evidence")
#: The layout selected for the current scan (``using_state_layout``), if any.
_ACTIVE_LAYOUT: ContextVar[str | None] = ContextVar("dbh_state_layout", default=None)


def state_layout(layout=None):
    """Return the active layout name, validating an explicit override.

    Precedence: an explicit *layout*, then the scan's layout set by
    ``using_state_layout``, then the module constant ``STATE_LAYOUT``.
    """
    if layout is None:
        layout = _ACTIVE_LAYOUT.get()
    if layout is None:
        layout = STATE_LAYOUT
    if layout not in STATE_LAYOUTS:
        raise ValueError("invalid_state_layout")
    return layout


@contextmanager
def using_state_layout(layout):
    """Build every state and policy inside the block under *layout*."""
    token = _ACTIVE_LAYOUT.set(state_layout(layout))
    try:
        yield
    finally:
        _ACTIVE_LAYOUT.reset(token)


def _ordered_state(state, layout=None):
    """Return *state* in the active layout without mutating the argument.

    v1 is the identity, so it reproduces pre-release bytes exactly. v2 lifts a
    nested ``specification.mode`` to ``specification_mode`` (unless one is
    already present) and orders trusted scalars, then untrusted fields, then
    every remaining field in its existing order. Applying it twice is a no-op.
    """
    if state_layout(layout) == "v1" or type(state) is not dict:
        return state
    moved = dict(state)
    spec = moved.get("specification")
    if type(spec) is dict and "mode" in spec and "specification_mode" not in moved:
        moved["specification_mode"] = spec["mode"]
        moved["specification"] = {k: v for k, v in spec.items() if k != "mode"}
    ordered = {k: moved[k] for k in TRUSTED_STATE_FIELDS if k in moved}
    ordered.update((k, moved[k]) for k in UNTRUSTED_STATE_FIELDS if k in moved)
    ordered.update((k, v) for k, v in moved.items() if k not in ordered)
    return ordered


def policy(pack, layout=None):
    """The policy preamble that matches the active state layout."""
    return pack["policy"] if state_layout(layout) == "v2" else pack["policy_v1"]


def load_pack():
    raw = files("decision_bug_hunter").joinpath("question_pack.json").read_bytes()
    pack = json.loads(raw)
    expected = {"version", "policy", "policy_v1", "screen", "verify", "need_context", "rank",
                "localize", "relevance", "evidence_relevance", "relation",
                "verify_with_evidence", "continue_investigation", "next_action",
                "covered", "yes", "no", "none", "unlocalized", "context_pick",
                "read_with", "requirement", "lens_functional", "lens_contract",
                "lens_boundary", "lens_state", "lens_integration"}
    if (type(pack) is not dict or set(pack) != expected
            or any(type(v) is not str or not v.strip() for v in pack.values())):
        raise ValueError("invalid_question_pack")
    return pack, hashlib.sha256(raw).hexdigest()


def target_text(span):
    # Question IDs are not sent to the model. The bounds MUST be in instructions.
    return f"{span.id} (inclusive original lines {span.start} through {span.end})"


def noul(pack, kind, span, **values):
    # Callers supply only generated IDs and coordinates. Filtering controls is
    # formatting hygiene, NOT an injection boundary for arbitrary source text.
    clean = {k: "".join(ch for ch in str(v) if ch == " " or ch.isprintable())
             for k, v in values.items()}
    body = pack[kind].format(target=target_text(span), **clean)
    return {"type": "noul", "instructions": policy(pack) + " " + body,
            "criteria": {"true": pack["yes"], "false": pack["no"]}}


def choice(pack, kind, span, candidates):
    criteria = {s.id: target_text(s) for s in candidates}
    criteria.update(none=pack["none"], unlocalized=pack["unlocalized"])
    return {"type": "choice", "instructions": policy(pack) + " " +
            pack[kind].format(target=target_text(span)), "criteria": criteria}


LENS_KINDS = ("lens_functional", "lens_contract", "lens_boundary",
              "lens_state", "lens_integration")


#: Targets per rank page without a rounding cap (pre-WP-15 behaviour).
MAX_RANK_PAGE = 200


def singleton_candidates(span):
    """One single-line option per target line (localization menu F15)."""
    if span.size > 20:
        raise ValueError("localization_region_too_large")
    return [Span(line, line) for line in range(span.start, span.end + 1)]


#: The inverted screen for the polarity-twin diagnostic (ADR-6(6)), phrased
#: like S06's line_ok twin. Diagnostic only, so it is not a pack question.
POLARITY_TWIN = ("Is {target} correct as written with respect to the supplied "
                 "specification, or conservatively inferred intent when no "
                 "specification is supplied?")


def twin(pack, span):
    """The polarity twin of ``screen`` for *span*: P(true) ~ 1 - P(screen)."""
    return {"type": "noul", "instructions": policy(pack) + " " +
            POLARITY_TWIN.format(target=target_text(span)),
            "criteria": {"true": pack["yes"], "false": pack["no"]}}


def screening(pack, region, targets, *, bug_lenses=True, state=None,
              max_page=MAX_RANK_PAGE, reserve_bytes=0, polarity_twin=False):
    result = {"screen_" + span.id: noul(pack, "screen", span) for span in targets}
    if bug_lenses:
        for span in targets:
            for kind in LENS_KINDS:
                result[f"{kind}_{span.id}"] = noul(pack, kind, span)
    if polarity_twin:
        for span in targets:
            result["twin_" + span.id] = twin(pack, span)
    result["need_context"] = noul(pack, "need_context", region)
    # Rank pages separately. Never compare probabilities across different menus.
    pages = _rank_pages(pack, region, targets, state, max_page, reserve_bytes)
    for index, page in enumerate(pages):
        result[f"rank_{index}"] = choice(pack, "rank", region, page)
    return result


def _rank_pages(pack, region, targets, state, max_page=MAX_RANK_PAGE, reserve_bytes=0):
    """Size growing menus from exact JSON fragments, validating each final page.

    A menu adds entries before the two fixed sentinels. Fragment sizes include
    their commas, so UTF-8, escaping and duplicate span IDs have the same byte
    cost as the former full-state serialization at every candidate. A page
    holds at most *max_page* targets (200, or the rounding cap of ADR-4(3)).
    *reserve_bytes* is left free in every request (the judge controls).
    """
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
                state_fits = len(_json(state)) <= MAX_STATE_BYTES
                base = len(_json({"contract": CONTRACT_VERSION, "state": state,
                                  "questions": {"rank": template}}))
                prepared = True
            except ProviderError:
                raise
            except (ValueError, TypeError, UnicodeError):
                raise ProviderError("invalid_request") from None
        fits = len(page) < max_page
        if state is not None:
            # Keep field/schema validation even though these are generated
            # coordinates. The complete page is authoritatively encoded below.
            item = choice(pack, "rank", region, [target])
            validate_questions({"rank": item})
            try:
                entry = len(_json({target.id: target_text(target)})) - 1
            except (ValueError, TypeError, UnicodeError):
                raise ProviderError("invalid_request") from None
            predicted = added + entry - entries.get(target.id, 0)
            fits = (fits and state_fits
                    and base + predicted + reserve_bytes <= MAX_REQUEST_BYTES)
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
                # The existing contract retains an oversized singleton as a
                # named question failure for the execution layer to record.
                if exc.code != "request_too_large" or len(page) != 1:
                    raise
    return pages


def action_choice(pack, span, options):
    """Choice over a caller-supplied closed action vocabulary."""
    if type(options) is not dict or len(options) < 2:
        raise ValueError("action_choice_needs_options")
    return {"type": "choice",
            "instructions": policy(pack) + " " +
                pack["next_action"].format(target=target_text(span)),
            "criteria": dict(options)}


def evidence_noul(pack, kind, target, label):
    key = "evidence_relevance" if kind == "relevance" else kind
    return noul(pack, key, target, evidence=label)


def _source_ranges(source, region, halo, extras=()):
    ranges = [Span(max(1, region.start - halo),
                   min(len(source.lines), region.end + halo)), *extras]
    merged = []
    for span in sorted(ranges):
        if merged and span.start <= merged[-1].end + 1:
            merged[-1] = Span(merged[-1].start, max(merged[-1].end, span.end))
        else:
            merged.append(span)
    return merged


def _source_excerpts(source, region, halo, extras=()):
    return [{"start_line": span.start, "end_line": span.end,
             "lines": [{"line": i, "text": source.lines[i - 1]}
                       for i in range(span.start, span.end + 1)]}
            for span in _source_ranges(source, region, halo, extras)]


def _state_with_excerpts(source, excerpts, spec, context_scope):
    state = {"source_sha256": source.sha256, "file": source.name,
            "total_lines": len(source.lines),
            "excerpts": excerpts,
            "specification": {
                "mode": "provided" if spec else "inferred",
                # Numbered lines so questions can reference SPEC:R{a}-R{b}
                # without repeating untrusted text in instructions.
                "lines": [{"line": i, "text": line}
                          for i, line in enumerate(physical_lines(spec or ""), 1)]}}
    if context_scope is not None:
        state["context_scope"] = context_scope
    return _ordered_state(state)


def state_for(source, region, halo, spec, extras=(), *, context_scope=None):
    # Keep construction order for unsupported library inputs: source metadata,
    # then line access, then specification parsing.
    state = {"source_sha256": source.sha256, "file": source.name,
             "total_lines": len(source.lines),
             "excerpts": _source_excerpts(source, region, halo, extras),
             "specification": {"mode": "provided" if spec else "inferred",
                               "lines": [{"line": i, "text": line}
                                         for i, line in enumerate(physical_lines(spec or ""), 1)]}}
    if context_scope is not None:
        state["context_scope"] = context_scope
    return _ordered_state(state)


def _mandatory_view_too_large(source, region, halo, spec, probe, extras, context_scope):
    """Prove all halo choices exceed the state cap without rendering doomed rows.

    Each physical line requires at least 20 JSON bytes plus its text, before
    commas. Charging 21 per line is still a lower bound: each nonempty excerpt
    has a header larger than its missing first comma. Excerpt headers are
    otherwise ignored, so halo-induced merging cannot invalidate the bound.

    Only immutable primitive inputs use this path. All initially visible text
    and the original probe must validate before rejection; unsupported or
    invalid inputs fall through to the ordinary renderer and its error order.
    Nothing is cached across calls, and a potentially fitting view is unchanged.
    """
    if (type(source) is not Source or type(source.lines) is not tuple
            or type(source.name) is not str or type(source.sha256) is not str
            or type(region) is not Span or type(halo) is not int or halo < 0
            or type(extras) is not tuple
            or any(type(span) is not Span for span in extras)
            or (spec is not None and type(spec) is not str)
            or (context_scope is not None and type(context_scope) is not str)):
        return False
    lines = source.lines
    if region.end > len(lines) or any(span.end > len(lines) for span in extras):
        return False
    try:
        minimum = 0
        mandatory = _source_ranges(source, region, 0, extras) if extras else (region,)
        for span in mandatory:
            for i in range(span.start - 1, span.end):
                line = lines[i]
                if type(line) is not str:
                    return False
                minimum += 21 + len(line)
                if minimum > MAX_STATE_BYTES:
                    break
            if minimum > MAX_STATE_BYTES:
                break
        # This only bypasses an optional optimization for ordinary small views;
        # the normal path still performs the complete request validation.
        if minimum < MAX_STATE_BYTES // 2:
            return False
        fixed = _state_with_excerpts(source, [], spec, context_scope)
        if minimum + len(_json(fixed)) <= MAX_STATE_BYTES:
            return False
        for span in _source_ranges(source, region, halo, extras):
            for i in range(span.start - 1, span.end):
                line = lines[i]
                if type(line) is not str:
                    return False
                if not line.isascii():
                    line.encode("utf-8")
        try:
            encode_request(fixed, {"probe": probe})
        except ProviderError as exc:
            if exc.code != "request_too_large":
                return False
        return True
    except (ProviderError, ValueError, TypeError, UnicodeError, IndexError, AttributeError):
        return False


def fitting_state(source, region, halo, spec, probe, extras=(), *, context_scope=None):
    """Reduce optional halo only; all target and selected context stays intact."""
    if _mandatory_view_too_large(source, region, halo, spec, probe, extras, context_scope):
        return None
    state = state_for(source, region, halo, spec, extras, context_scope=context_scope)
    while True:
        try:
            encode_request(state, {"probe": probe})
            return state
        except ProviderError as exc:
            if exc.code != "request_too_large":
                raise
            if halo == 0:
                return None
            halo //= 2
            # The specification, scope and source identity are invariant across
            # halo probes; keep this private state and replace only its excerpts.
            state["excerpts"] = _source_excerpts(source, region, halo, extras)


#: Judge controls (canaries; revision-3 WP-14, ADR-6). Two noul questions
#: with known answers, generated by DBH from the state it wrote, ride in every
#: request when Config.canaries is "on". The wording is the set S12c and
#: S13a/b/c measured on the live route (must-true 1.00, must-false 0.00, and
#: zero change to every other answer), not the ADR-6 draft wording.
CONTROL_SET = "dbh-controls-v1"
CONTROL_COUNT = 2
CONTROL_NAME = re.compile(r"ctl_[0-9a-f]{8}\Z")
#: Pre-registered thresholds (ADR-6(3)); never widened after the fact.
CONTROL_MUST_TRUE_MIN = Decimal("0.90")
CONTROL_MUST_FALSE_MAX = Decimal("0.10")
CONTROL_CRITERIA = {"true": "Yes, the statement holds.",
                    "false": "No, the statement does not hold."}
CONTROL_MUST_TRUE = "Does the supplied state declare a context_scope value?"
CONTROL_MUST_FALSE = "Does any source line contain the word '{word}'?"
#: Must-false words, in order; the first one absent from the request state
#: (case-insensitively, anywhere in its JSON) is asked. "zebra" is the word
#: measured live. When the state contains all of them, the must-false control
#: asks whether total_lines equals a wrong value instead.
CONTROL_ABSENT_WORDS = ("zebra", "quokka", "narwhal", "axolotl", "pangolin",
                        "okapi", "wombat", "tapir")
CONTROL_TOTAL_LINES = "Does state.total_lines equal {n}?"


def _control(instructions):
    return {"type": "noul", "instructions": instructions, "criteria": dict(CONTROL_CRITERIA)}


def _control_fragment_size(instructions):
    return len(_json({"ctl_00000000": _control(instructions)})) - 2


#: Bytes the two control fragments and their commas can add to a request: the
#: must-true text plus the largest must-false text (any listed word, or a
#: total_lines value of up to eleven digits).
CONTROL_RESERVE_BYTES = (
    _control_fragment_size(CONTROL_MUST_TRUE)
    + max([_control_fragment_size(CONTROL_MUST_FALSE.format(word=w))
           for w in CONTROL_ABSENT_WORDS]
          + [_control_fragment_size(CONTROL_TOTAL_LINES.format(n=10 ** 10))])
    + 2)


def control_role(question):
    """"must_true" or "must_false" for a control question made here."""
    return "must_true" if question["instructions"] == CONTROL_MUST_TRUE else "must_false"


def control_passed(role, value):
    """The pre-registered pass rule for one control answer (P(true), or None)."""
    if value is None:
        return False
    if role == "must_true":
        return value >= CONTROL_MUST_TRUE_MIN
    return value <= CONTROL_MUST_FALSE_MAX


class _Controls:
    """The controls for one request state (ADR-6(1), (2)).

    Names are ``ctl_`` + 8 hex characters and positions come from one hash of
    the set, the source hash and the control-free request bytes, so identical
    requests stay identical (and reusable) while names and positions vary per
    request. A state without a context_scope declaration, or whose
    total_lines is unusable when every listed word occurs, gets no controls.
    """

    def __init__(self, state, state_wire):
        scope = state.get("context_scope")
        lines = state.get("total_lines")
        folded = state_wire.decode("utf-8").casefold()
        self.word = next((w for w in CONTROL_ABSENT_WORDS if w not in folded), None)
        self.total_lines = lines if type(lines) is int and lines >= 1 else None
        self.source = state.get("source_sha256")
        self.available = (type(scope) is str and bool(scope.strip())
                          and (self.word is not None or self.total_lines is not None))

    def seed(self, base_wire):
        raw = "|".join((CONTROL_SET, str(self.source), hashlib.sha256(base_wire).hexdigest()))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def questions(self, seed):
        """((must-true name, question), (must-false name, question))."""
        names, digest = [], seed
        while len(names) < CONTROL_COUNT:
            for start in range(0, 64, 8):
                name = "ctl_" + digest[start:start + 8]
                if name not in names and len(names) < CONTROL_COUNT:
                    names.append(name)
            digest = hashlib.sha256(digest.encode("ascii")).hexdigest()
        if self.word is not None:
            false_text = CONTROL_MUST_FALSE.format(word=self.word)
        else:
            step = 1 if int(seed[32:34], 16) % 2 == 0 else -1
            false_text = CONTROL_TOTAL_LINES.format(n=self.total_lines + step)
        return ((names[0], _control(CONTROL_MUST_TRUE)), (names[1], _control(false_text)))

    def insert(self, state_wire, batch, fragments, base_wire):
        """(batch, wire) with both controls at hash-derived positions, or None
        when they do not fit the request."""
        seed = self.seed(base_wire)
        pairs = list(self.questions(seed))
        if int(seed[34:36], 16) % 2:
            pairs.reverse()
        order = [(qid, question, fragment)
                 for (qid, question), fragment in zip(batch.items(), fragments)]
        for offset, (qid, question) in zip((16, 24), pairs):
            if qid in batch:
                raise ProviderError("invalid_request")
            position = int(seed[offset:offset + 8], 16) % (len(order) + 1)
            order.insert(position, (qid, question, _json({qid: question})[1:-1]))
        try:
            wire = _encode_validated_request(
                state_wire, b"{" + b",".join(item[2] for item in order) + b"}")
        except ProviderError as exc:
            if exc.code != "request_too_large":
                raise
            return None
        return {qid: question for qid, question, _ in order}, wire


def prepared_question_batches(state, questions, *, controls=False):
    """Own and validate values once, then assemble exact UTF-8 batch fragments.

Preserves option, question, state and batch order. A singleton that cannot fit
is returned as a named failure. The caller still validates each actual response
atomically. No evidence or question is dropped to make a request smaller.

With *controls*, every batch leaves room for the two judge controls (two
questions and ``CONTROL_RESERVE_BYTES``) and carries them at hash-derived
positions. A singleton that fits only without them is sent without them; its
batch then holds no ``ctl_`` name.
"""
    if not questions:
        return
    try:
        state, questions = _snapshot(state), _snapshot(questions)
        if type(state) is not dict or type(questions) is not dict:
            raise ProviderError("invalid_request")
        state_wire = _json(state)
        state_fits = len(state_wire) <= MAX_STATE_BYTES
        base = len(_encode_validated_request(state_wire, b"{}")) if state_fits else 0
        checks = _Controls(state, state_wire) if controls else None
        if checks is not None and not checks.available:
            checks = None
        if checks is not None and any(CONTROL_NAME.fullmatch(qid) for qid in questions):
            raise ProviderError("invalid_request")
        reserve = CONTROL_RESERVE_BYTES if checks is not None else 0
        limit = MAX_QUESTIONS - (CONTROL_COUNT if checks is not None else 0)

        def finish(batch, fragments, size):
            wire = _encode_validated_request(state_wire, b"{" + b",".join(fragments) + b"}")
            if len(wire) != size:
                raise ProviderError("invalid_request")
            if checks is not None:
                controlled = checks.insert(state_wire, batch, fragments, wire)
                if controlled is not None:
                    return controlled[0], None, controlled[1]
            return batch, None, wire

        batch, fragments, size = {}, [], base
        for qid, question in questions.items():
            validate_questions({qid: question})
            fragment = _json({qid: question})[1:-1]
            entry_size = len(fragment)
            predicted = size + entry_size + bool(batch)
            if batch and (len(batch) == limit or predicted + reserve > MAX_REQUEST_BYTES):
                yield finish(batch, fragments, size)
                batch, fragments, size = {}, [], base
            if not state_fits or base + entry_size > MAX_REQUEST_BYTES:
                yield {}, qid, None
                continue
            size += entry_size + bool(batch)
            batch[qid] = question
            fragments.append(fragment)
        if batch:
            yield finish(batch, fragments, size)
    except ProviderError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise ProviderError("invalid_request") from None


def pack_questions(state, questions):
    """Public pair-form iterator; preparation also exposes each validated wire."""
    for batch, failure, _wire in prepared_question_batches(state, questions):
        yield batch, failure
