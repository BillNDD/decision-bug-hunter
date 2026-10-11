"""The request planner of the ``tile-sieve-beta`` search policy (whole-file mode).

A file that fits in one request is read in two looks. Each look asks line, block
and granule questions over the whole file, and a flagged region then gets one
focus request. This module builds those requests, byte for byte, and decides
whether the file fits. Nothing is sent from here and nothing reads a clock or a
network.

Every request is assembled by ``assemble``, which asserts the OpenAI-direct caps
on any route and for any judge: at most 64 questions (the two canaries
included), at most 24,064 B of request and at most 15,872 B of state (the placed
policy entry included, which is stricter than DBH's own state cap). A request
that does not fit raises ``Overflow``; ``plan_whole_file`` turns that into a
``Fallback`` and the scan then runs ``legacy-v1``. Nothing is ever returned that
exceeds a cap, and nothing is split or tiled.

Look 1 is planned only for files of more than 8 lines. A file of 8 lines or
fewer is read once, and that one request records that it serves both looks.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
from importlib.resources import files
import json

from . import protocol as P
from . import questions as Q
from . import tile_sieve_index as ci
from .core import Source, Span
from .evidence import EvidenceRef, evidence_label

#: Caps, always OpenAI direct's (owner decision), whatever the route or judge.
MAX_QUESTIONS = P.MAX_QUESTIONS
ENVELOPE_BYTES = P.MAX_REQUEST_BYTES
MARGIN = 512
MAX_REQUEST_BYTES = ENVELOPE_BYTES - MARGIN        # 24,064
MAX_STATE_BYTES = P.MAX_STATE_BYTES - MARGIN       # 15,872

#: Grid periods: leaf, block and granule cells (lines).
LEAF = 16
BLOCK = 48
GRAN = 8
#: Per-look phases (tile offset, leaf, block, granule). The tile offset is unused: a whole file is one core.
PHASES = ((0, 0, 0, 0), (72, 8, 24, 4))
#: A file of at most this many lines is read once; look 1 is planned only above it.
SINGLE_LOOK_MAX_LINES = 8

SPEC_SLICE_BYTES = 1536
FOCUS_HALO = 16
FOCUS_PARTNER_LINES = 80
PER_PARTNER_LINES = 40
FOCUS_CELL = 4
FOCUS_SHIFT = 2
MAX_RELATIONS = 3
MAX_REQUIREMENTS = 2
LENS_NAMES = ("functional", "contract", "boundary", "state", "integration")

_PACK_KEYS = frozenset({"version", "rank_granule", "rank_requirement", "multiple", "requirement_none"})
#: Fallback reasons of ``plan_whole_file``; ``provider_<code>`` is a packer refusal.
FALLBACK_REASONS = ("request_bytes", "state_bytes", "too_many_questions", "split_into_batches",
                    "canaries_do_not_fit", "question_too_large", "empty_file")


class Overflow(Exception):
    """A request did not fit a cap; ``reason`` is the fallback code and ``detail`` a dict."""

    def __init__(self, reason, detail=None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


class PlanError(Exception):
    """A request cannot be built within the caps even after every truncation."""

    def __init__(self, reason, detail=None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


class IntegrityError(Exception):
    """The planner's own guarantee failed: the bytes it hashed are not the bytes the gateway would
    send. It is deliberately neither an ``Overflow`` nor a ``PlanError``: it is never a fallback."""


# -- grids ------------------------------------------------------------------------------

@dataclass(frozen=True, order=True)
class Cell:
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start + 1

    @property
    def id(self) -> str:
        return f"L{self.start}-{self.end}"


def _ceil_div(a, b):
    return -((-a) // b)


def cells_owned(n, period, phase, lo, hi):
    """Cells of the grid (period, phase) whose first clipped line is in [lo, hi].

    A grid of period p at phase a has cell boundaries at a + k*p. Cells are clipped to
    [1, n]; the cell that straddles line 1 (when phase > 0) starts at line 1."""
    if n < 1 or lo > hi:
        return []
    lo = max(1, lo)
    hi = min(n, hi)
    out = []
    k = -1 if (phase > 0 and lo == 1) else _ceil_div(lo - phase - 1, period)
    while True:
        natural = phase + 1 + k * period
        start = max(1, natural)
        if start > hi:
            break
        end = min(n, natural + period - 1)
        if start >= lo and end >= start:
            out.append(Cell(start, end))
        k += 1
    return out


def cell_containing(n, period, phase, line):
    """The cell of the grid that contains *line* (clipped)."""
    k = (line - phase - 1) // period
    natural = phase + 1 + k * period
    return Cell(max(1, natural), min(n, natural + period - 1))


def local_cells(lo, hi, size, shift=0):
    """Consecutive *size*-line cells over [lo, hi]; a *shift* makes the first cell short."""
    out, start = [], lo
    first_end = lo + (shift - 1 if shift else size - 1)
    end = min(hi, first_end)
    while start <= hi:
        out.append(Cell(start, end))
        start = end + 1
        end = min(hi, start + size - 1)
    return out


# -- wording -------------------------------------------------------------------------------

def _read_pack_file():
    raw = files("decision_bug_hunter").joinpath("tile_sieve_pack.json").read_bytes()
    pack = json.loads(raw)
    if (type(pack) is not dict or set(pack) != _PACK_KEYS
            or any(type(v) is not str or not v.strip() for v in pack.values())):
        raise ValueError("invalid_tile_sieve_pack")
    return pack, hashlib.sha256(raw).hexdigest()


def tile_sieve_pack_sha256():
    """The sha256 of the shipped ``tile_sieve_pack.json``."""
    return _read_pack_file()[1]


def load_tile_sieve_pack():
    """DBH's question pack with the pack's wording entries added.

    ``question_pack.json`` is never changed, and its own ``version`` key is kept."""
    base, _sha = Q.load_pack()
    extra, _tile_sha = _read_pack_file()
    merged = dict(base)
    merged.update((key, value) for key, value in extra.items() if key != "version")
    return merged


class SpecPassage:
    """A spec passage as a choice option: id ``R3-5``, labelled with its coordinates."""

    def __init__(self, start, end):
        self.start, self.end = start, end

    @property
    def id(self):
        return f"R{self.start}-{self.end}"

    @property
    def size(self):
        return self.end - self.start + 1


def spec_body(passage):
    """The label DBH uses to name a spec passage inside a question."""
    return (f"SPEC:R{passage.start}-R{passage.end} (inclusive specification lines "
            f"{passage.start} through {passage.end}) supplied in state")


def leaf_q(pack, span):
    return Q.noul(pack, "screen", span)


def need_ctx_q(pack, region):
    return Q.noul(pack, "need_context", region)


def granule_q(pack, region, granules):
    return Q.choice(pack, "rank_granule", region, granules)


def lens_choice_q(pack, kind, region, blocks):
    return Q.choice(pack, kind, region, blocks)


def requirement_choice_q(pack, region, passages):
    criteria = {p.id: spec_body(p) for p in passages}
    criteria["none"] = pack["requirement_none"]
    return {"type": "choice",
            "instructions": Q.policy(pack) + " " + pack["rank_requirement"].format(
                target=Q.target_text(region)),
            "criteria": criteria}


def verify_q(pack, region):
    return Q.noul(pack, "verify", region)


def twin_q(pack, region):
    return Q.twin(pack, region)


def lens_q(pack, kind, region):
    return Q.noul(pack, kind, region)


def relation_q(pack, region, label):
    return Q.evidence_noul(pack, "relation", region, label)


def requirement_q(pack, region, passage):
    return Q.noul(pack, "requirement", region, passage=spec_body(passage))


def multiple_q(pack, region):
    return Q.noul(pack, "multiple", region)


def localize_q(pack, region, cells):
    return Q.choice(pack, "localize", region, cells)


# -- requests ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class Request:
    """One planned request: the wire bytes, their hash and what the engine needs to ask it.

    ``state`` and ``questions`` are the request as sent (the policy placed in state, the
    canaries inserted). ``meta`` carries ``roles`` (what each question is) and the geometry
    of the request: for a tile its look(s), cells and display, for a focus its K, partners
    and truncation."""

    kind: str                       # "tile" | "focus"
    wire: bytes
    sha256: str
    nq: int
    state_bytes: int
    meta: dict
    state: dict = field(repr=False)
    questions: dict = field(repr=False)

    @property
    def request_bytes(self) -> int:
        return len(self.wire)

    @property
    def roles(self) -> dict:
        return self.meta["roles"]

    @property
    def looks(self) -> tuple:
        """The looks this request serves (a tile only)."""
        return tuple(self.meta.get("looks", ()))


@dataclass(frozen=True)
class Fallback:
    """The file does not fit in one request: ``reason`` is one of ``FALLBACK_REASONS`` or
    ``provider_<code>``, and ``detail`` a small dict (bytes and the limit, a count)."""

    reason: str
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class WholeFilePlan:
    """The look requests of a file that fits.

    ``looks`` holds the distinct requests in look order. A request serves several looks when
    they would be the same bytes (a file of at most 4 lines) or when look 1 is not planned
    (at most 8 lines); ``Request.looks`` then reads ``(0, 1)``."""

    n: int
    looks: tuple
    planner: Planner = field(repr=False, compare=False)

    @property
    def requests(self) -> tuple:
        return self.looks

    def request_for_look(self, look):
        for request in self.looks:
            if look in request.looks:
                return request
        raise ValueError("invalid_look")


def assemble(state, questions, policy, roles=None):
    """``(wire, sha256, state as sent, questions as sent, state bytes, question count)``.

    Raises ``Overflow`` when the request does not fit one batch and every cap, and
    ``IntegrityError`` when the wire does not re-encode to the same bytes."""
    envelope = P.RequestEnvelope(policy, MAX_QUESTIONS, ENVELOPE_BYTES)
    placed_bytes = len(P._json(state)) + envelope.state_allowance
    if placed_bytes > MAX_STATE_BYTES:
        raise Overflow("state_bytes", {"bytes": placed_bytes, "limit": MAX_STATE_BYTES})
    try:
        with P.using_request_envelope(envelope):
            batches = list(Q.prepared_question_batches(state, questions, controls=True))
    except P.ProviderError as exc:
        raise Overflow("provider_" + exc.code) from None
    if len(batches) != 1:
        raise Overflow("split_into_batches", {"batches": len(batches)})
    batch, failed, wire = batches[0]
    if failed is not None or wire is None:
        raise Overflow("question_too_large")
    controls = [qid for qid in batch if Q.CONTROL_NAME.fullmatch(qid)]
    if len(controls) != Q.CONTROL_COUNT:
        raise Overflow("canaries_do_not_fit")
    if len(batch) > MAX_QUESTIONS:
        raise Overflow("too_many_questions", {"questions": len(batch), "limit": MAX_QUESTIONS})
    if len(wire) > MAX_REQUEST_BYTES:
        raise Overflow("request_bytes", {"bytes": len(wire), "limit": MAX_REQUEST_BYTES})
    sent = json.loads(wire)
    state_bytes = len(P._json(sent["state"]))
    if state_bytes > MAX_STATE_BYTES:
        raise Overflow("state_bytes", {"bytes": state_bytes, "limit": MAX_STATE_BYTES})
    with P.using_request_envelope(envelope):
        again = P.encode_request(sent["state"], sent["questions"])
    if again != wire:       # the gateway re-encodes; the hash must agree
        raise IntegrityError("wire_not_stable_under_reencoding")
    if roles is not None:
        for qid, question in batch.items():
            if Q.CONTROL_NAME.fullmatch(qid):
                roles[qid] = {"role": Q.control_role(question)}
    return wire, hashlib.sha256(wire).hexdigest(), sent["state"], sent["questions"], state_bytes, len(batch)


def _pairs(cells):
    return [[c.start, c.end] for c in cells]


def _is_primary(entry, source):
    return entry.source is source or (source.path is not None and entry.source.path == source.path)


def _json_line_bytes(line, text):
    # {"line":N,"text":"..."} without the separating comma
    return 17 + len(str(line)) + len(json.dumps(text, ensure_ascii=False).encode("utf-8"))


class Planner:
    """Requests for one file: its whole-file looks and a focus request per region.

    *project_entries* are the project files of the scan (``ProjectEntry``); every one except the
    primary file goes into ``related_sources`` in full, in index order. A planner is cheap to
    build, and everything it returns is deterministic."""

    def __init__(self, source, spec_source=None, project_entries=(), context_scope="declared_standalone"):
        if not isinstance(source, Source):
            raise ValueError("invalid_source")
        self.source = source
        self.n = len(source.lines)
        self.spec_lines = tuple(spec_source.lines) if spec_source is not None else ()
        self.related = tuple(e for e in project_entries if not _is_primary(e, source))
        self.context_scope = context_scope
        self.pack = load_tile_sieve_pack()
        with Q.using_state_layout("v1"):
            self.policy = Q.policy(self.pack)
        self._index = None
        self._related_sources = None
        self._floor_checked = {}

    @property
    def index(self):
        """The code index, built on first use (a file that is refused never needs it)."""
        if self._index is None:
            self._index = ci.CodeIndex(self.source.lines, self.source.name)
        return self._index

    # -- state ---------------------------------------------------------------------------
    def _check_floor(self, whole_file):
        """Refuse early a state whose lines alone cannot fit the state cap.

        Every line costs its JSON text plus a fixed 17 bytes, so a huge file or project is
        rejected after a few hundred lines instead of being built whole. A whole-file look
        shows the file and the related sources; a focus request shows only the related
        sources (its own lines are a small window)."""
        if self._floor_checked.get(whole_file):
            return
        total = self._floor_bytes(whole_file, MAX_STATE_BYTES)
        if total > MAX_STATE_BYTES:
            raise Overflow("state_bytes", {"bytes": total, "limit": MAX_STATE_BYTES, "at_least": True})
        self._floor_checked[whole_file] = True

    def _floor_bytes(self, whole_file, limit=None):
        """The bytes of the line entries alone (a lower bound of the state), comma included.

        With a *limit* the sum stops at the first line that takes it past the limit."""
        total = 0
        groups = ([self.source.lines] if whole_file else []) + [e.source.lines for e in self.related]
        for lines in groups:
            for line, text in enumerate(lines, 1):
                total += _json_line_bytes(line, text) + 1
                if limit is not None and total > limit:
                    return total
        return total

    def related_sources(self):
        if self._related_sources is None:
            self._related_sources = [
                {"file": e.relpath, "source_sha256": e.source.sha256, "start_line": 1,
                 "end_line": len(e.source.lines),
                 "lines": [{"line": i, "text": t} for i, t in enumerate(e.source.lines, 1)]}
                for e in self.related]
        return self._related_sources

    def base_state(self, disp, spec_entries, *, extras=(), evidence=()):
        """The state of every request, in the pilot's key order."""
        state = {"source_sha256": self.source.sha256, "file": self.source.name,
                 "total_lines": self.n,
                 "excerpts": Q._source_excerpts(self.source, Span(disp[0], disp[1]), 0, tuple(extras)),
                 "specification": {"mode": "provided" if spec_entries else "inferred",
                                   "lines": spec_entries}}
        if self.related:
            state["related_sources"] = self.related_sources()
        state["context_scope"] = self.context_scope
        if evidence:
            state["evidence_coordinates"] = [
                {"id": r.id, "file": r.label, "source_sha256": r.source.sha256,
                 "start_line": r.span.start, "end_line": r.span.end} for r in evidence]
        return Q._ordered_state(state)

    def _request(self, kind, state, questions, roles, meta):
        wire, sha, sent_state, sent_questions, state_bytes, nq = assemble(
            state, questions, self.policy, roles)
        return Request(kind, wire, sha, nq, state_bytes, dict(meta, roles=roles),
                       sent_state, sent_questions)

    # -- whole-file looks ----------------------------------------------------------------
    def whole_tile(self, look):
        """The request of one look over the whole file, or ``Overflow``."""
        if look not in (0, 1):
            raise ValueError("invalid_look")
        n = self.n
        if n == 0:
            raise Overflow("empty_file")
        self._check_floor(True)
        _offset, a, b, g = PHASES[look]
        leaves = cells_owned(n, LEAF, a, 1, n)
        blocks = cells_owned(n, BLOCK, b, 1, n)
        grans = cells_owned(n, GRAN, g, 1, n)
        region = Span(1, n)
        spec_entries, found = ci.spec_slice(self.spec_lines, self.index.idents_in(1, n), SPEC_SLICE_BYTES)
        kept = [SpecPassage(p.start, p.end) for p in found]
        with Q.using_state_layout("v1"):
            questions, roles = self._tile_questions(leaves, blocks, grans, region, kept)
            state = self.base_state((1, n), spec_entries)
            meta = {"name": self.source.name, "n": n, "look": look, "looks": [look], "core": [1, n],
                    "display": [1, n], "spec_entries": len(spec_entries),
                    "spec_passages": [[p.start, p.end] for p in kept],
                    "cells": {"leaf": _pairs(leaves), "block": _pairs(blocks), "gran": _pairs(grans)}}
            return self._request("tile", state, questions, roles, meta)

    def _tile_questions(self, leaves, blocks, grans, region, passages):
        """The questions of a look in the pilot's order: leaves, blocks, need_ctx, granules,
        the five lenses over the blocks, and the requirement choice when passages were kept."""
        pack = self.pack
        qs, roles = {}, {}

        def add(qid, q, **role):
            qs[qid] = q
            roles[qid] = role

        for c in leaves:
            add(f"leaf_{c.id}", leaf_q(pack, Span(c.start, c.end)), role="leaf", cell=[c.start, c.end])
        for c in blocks:
            add(f"block_{c.id}", leaf_q(pack, Span(c.start, c.end)), role="block", cell=[c.start, c.end])
        add("need_ctx", need_ctx_q(pack, region), role="need_ctx")
        if grans:
            add("gran", granule_q(pack, region, grans), role="gran", cells=_pairs(grans))
        if blocks:
            for name, kind in zip(LENS_NAMES, Q.LENS_KINDS):
                add(f"lens_{name}", lens_choice_q(pack, kind, region, blocks), role="lens", lens=name,
                    cells=_pairs(blocks))
        if passages:
            add("req", requirement_choice_q(pack, region, passages), role="req",
                passages=[[p.start, p.end] for p in passages])
        return qs, roles

    # -- focus ---------------------------------------------------------------------------
    def focus(self, K, need_ctx=False, lens_order=None):
        """The focus request for the region *K* = (lo, hi), or ``PlanError``.

        *need_ctx* asks for the nearest definitions when no def-use edge crosses K (the shipped
        flow never sets it); *lens_order* is the order of the five lens predicates (default
        ``LENS_NAMES``). When the request does not fit, the truncation ladder trims the
        partners, then the spec, then the halo, then the optional questions."""
        n = self.n
        lo, hi = max(1, K[0]), min(n, K[1])
        try:
            self._check_floor(False)
        except Overflow as exc:
            raise PlanError("focus_unfittable", {"K": [lo, hi], "overflow": exc.reason}) from None
        found = self.index.partners(lo, hi, FOCUS_HALO, max_lines=FOCUS_PARTNER_LINES,
                                    per_partner=PER_PARTNER_LINES)
        if not found and need_ctx:
            found = ci.nearest_defs(self.index, lo, hi)
        partners = list(found)
        order = list(lens_order or LENS_NAMES)
        last = None
        with Q.using_state_layout("v1"):
            for st in _truncation_settings(len(partners)):
                try:
                    return self._focus_once((lo, hi), st, partners, order, bool(need_ctx))
                except Overflow as exc:
                    last = exc
        raise PlanError("focus_unfittable", {"K": [lo, hi], "overflow": last.reason if last else None})

    def _focus_once(self, K, st, partners, lens_order, need_ctx):
        pack = self.pack
        lo, hi = K
        n = self.n
        disp = (max(1, lo - st["halo"]), min(n, hi + st["halo"]))
        use = _cut_partners(partners[:st["partners"]], st["partner_cap"])
        refs = [EvidenceRef(self.source, self.source.name, Span(s.start, s.end), "source")
                for _d, s, _l in use]
        extras = tuple(r.span for r in refs)
        code_idents = self.index.idents_in(lo, hi)
        spec_entries, passages = ci.spec_slice(self.spec_lines, code_idents, st["spec"],
                                               linked_only=st["linked"])
        region = Span(lo, hi)
        qs, roles = {}, {}

        def add(qid, q, **role):
            qs[qid] = q
            roles[qid] = role

        loc_a = local_cells(lo, hi, FOCUS_CELL)
        loc_b = local_cells(lo, hi, FOCUS_CELL, FOCUS_SHIFT)
        add("loc_a", localize_q(pack, region, loc_a), role="loc_a", cells=_pairs(loc_a))
        add("loc_b", localize_q(pack, region, loc_b), role="loc_b", cells=_pairs(loc_b))
        add("verify", verify_q(pack, region), role="verify")
        add("twin", twin_q(pack, region), role="twin")
        for name in lens_order[:st["lenses"]]:
            add(f"lens_{name}", lens_q(pack, Q.LENS_KINDS[LENS_NAMES.index(name)], region),
                role="lens", lens=name)
        for r in refs[:st["relations"]]:
            add(f"rel_{r.id}", relation_q(pack, region, evidence_label(r)),
                role="relation", partner=[r.span.start, r.span.end])
        words = ci.ident_words(code_idents)
        ranked = sorted(passages, key=lambda p: (-ci.passage_score(self.spec_lines, p, words), p.start))
        for p in ranked[:MAX_REQUIREMENTS]:
            sp = SpecPassage(p.start, p.end)
            add(f"reqm_{sp.id}", requirement_q(pack, region, sp), role="requirement",
                passage=[p.start, p.end])
        add("need_ctx", need_ctx_q(pack, region), role="need_ctx")
        add("multiple", multiple_q(pack, region), role="multiple")
        state = self.base_state(disp, spec_entries, extras=extras, evidence=refs)
        meta = {"name": self.source.name, "n": n, "K": [lo, hi], "display": list(disp),
                "partners": [[s.start, s.end, lab] for _d, s, lab in use],
                "truncation": dict(st), "need_ctx_tile": need_ctx}
        return self._request("focus", state, qs, roles, meta)

    # -- the plan ------------------------------------------------------------------------
    def plan(self):
        """A ``WholeFilePlan`` when every look request fits, else a ``Fallback``."""
        if self.n == 0:
            return Fallback("empty_file")
        try:
            requests = [self.whole_tile(0)]
            if self.n > SINGLE_LOOK_MAX_LINES:
                second = self.whole_tile(1)
                if second.sha256 != requests[0].sha256:
                    requests.append(second)
                    return WholeFilePlan(self.n, tuple(requests), self)
        except Overflow as exc:
            return Fallback(exc.reason, exc.detail)
        both = replace(requests[0], meta=dict(requests[0].meta, looks=[0, 1]))
        return WholeFilePlan(self.n, (both,), self)


def plan_whole_file(source, spec_source=None, project_entries=(), context_scope="declared_standalone"):
    """Plan the two whole-file looks of *source*: a ``WholeFilePlan`` or a ``Fallback``."""
    return Planner(source, spec_source, project_entries, context_scope).plan()


def _cut_partners(partners, cap):
    """Reduce each partner span to at most *cap* lines (None = unchanged)."""
    if cap is None:
        return partners
    return [(d, Span(s.start, min(s.end, s.start + cap - 1)), lab) for d, s, lab in partners]


def _truncation_settings(n_partners):
    """The truncation order of a focus request:
    1. the farthest def-use partners, then the partner line count;
    2. spec passages, down to the sentences linked to K;
    3. outside context, K +- 16 down to K +- 8;
    4. optional questions (relations beyond 1, lenses beyond the top 3).
    K's own lines and the canaries are never dropped. As a last resort the remaining
    partner goes too."""
    out = [{"partners": n_partners, "partner_cap": None, "spec": SPEC_SLICE_BYTES, "linked": False,
            "halo": FOCUS_HALO, "relations": MAX_RELATIONS, "lenses": 5}]

    def push(**kw):
        cur = dict(out[-1])
        cur.update(kw)
        out.append(cur)

    for k in range(n_partners - 1, 0, -1):
        push(partners=k)
    for cap in (24, 12, 6):
        if n_partners:
            push(partner_cap=cap)
    for budget, linked in ((768, False), (384, True), (192, True)):
        push(spec=budget, linked=linked)
    push(halo=8)
    push(relations=1, lenses=3)
    if n_partners:
        push(partners=0)
    push(halo=0, spec=96, linked=True)
    return out
