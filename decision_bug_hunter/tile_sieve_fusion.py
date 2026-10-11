"""The client-side steps of the ``tile-sieve-beta`` search policy after the judge answers.

Screening reads the answers of a look and flags leaf cells. Flagged cells are
merged into clusters, a focus request scores each cluster, a report rule decides
it, and the localization answers of the reported clusters become line runs that
are reconciled into findings. Nothing here is sent, and nothing reads a clock or
a network; the only file read is the packaged ``tile_sieve_thresholds.json``.

The thresholds are data. ``load_thresholds(judge)`` returns the set that was
calibrated for one judge, and a judge without a set is refused with
``LookupError("tile_sieve_uncalibrated")``. Values are decimal strings in the file
and ``float(str)`` here, which gives the same floats as the pilot's constants.

The report rule is the owner's rule 8C, with no second stage. A cluster is
*strong* when a member leaf or an overlapping granule scored at least
``strong_cell``. A strong cluster is reported at ``tau_strong``, any other
cluster at ``tau_rep(n)`` for the file's own line count, and a cluster whose
relation score reaches ``tau_rel`` is reported from ``tau_gray`` upward. Every
other cluster is clear. A cluster with no score is ``unmeasured``.

Two screening variants exist and the threshold file selects one per judge:
``pilot-full`` (the pilot's rule: leaf or granule score, orphan blocks, orphan
lenses, the none rule and tail cells) and ``leaf-only`` (the 16-line leaf
predicate alone).

Floating-point behavior is the pilot's, bit for bit: answers go through
``float()``, the focus score accumulates its terms in the pilot's order, and the
runs are computed on exact fractions of the printed probabilities.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
import hashlib
from importlib.resources import files
import json
import math
import re

from . import questions as Q
from .core import Span

#: Cluster geometry: flagged cells merge across gaps of at most CLUSTER_GAP lines, a merged run
#: is cut into pieces of at most CLUSTER_MAX lines, and each piece is padded by CLUSTER_PAD lines.
CLUSTER_GAP = 8
CLUSTER_MAX = 48
CLUSTER_PAD = 4

THRESHOLDS_VERSION = "tile-sieve-thresholds/1"
SCREENING_RULES = ("pilot-full", "leaf-only")

_INVALID = "invalid_tile_sieve_thresholds"
_ENTRY_KEYS = frozenset({"basis", "screening_rule", "pilot_full", "leaf_only", "strong_cell",
                         "tau_ctx", "tau_mult", "e_weights", "tau_strong", "tau_gray", "tau_rel",
                         "tau_rep_points"})
_PILOT_FULL_KEYS = frozenset({"weights", "tau_s", "tau_c", "tau_block", "tau_lens", "tau_none"})
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
_JUDGE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_MAX_WEIGHT = Decimal(16)
_MAX_POINTS = 16


# -- thresholds -----------------------------------------------------------------------------

@dataclass(frozen=True)
class ThresholdSet:
    """The calibrated values of one judge; built only by ``load_thresholds``."""

    judge: str
    basis: str
    #: ``pilot-full`` or ``leaf-only``: which screening variant ``flag_tile`` applies
    screening_rule: str
    #: weights of the fused leaf score: leaf, block share, granule mass, lens mass
    weights: tuple
    tau_s: float
    tau_c: float
    tau_block: float
    tau_lens: float
    tau_none: float
    tau_leaf: float
    #: a leaf or granule at this score or more makes its cluster strong
    strong_cell: float
    tau_ctx: float
    tau_mult: float
    #: weights of the focus score: verify, 1 - twin, strongest lens
    e_weights: tuple
    tau_strong: float
    tau_gray: float
    tau_rel: float
    #: ((n, tau), ...) in increasing n; tau_rep is linear in log n between the points
    tau_rep_points: tuple

    def tau_rep(self, n):
        """The report bar of a non-strong cluster in a file of *n* lines: clamped to the first
        point at or below it and to the last point at or above it, else interpolated in log n
        and rounded to four places."""
        pts = sorted(self.tau_rep_points)
        if n <= pts[0][0]:
            return pts[0][1]
        if n >= pts[-1][0]:
            return pts[-1][1]
        for (n0, t0), (n1, t1) in zip(pts, pts[1:]):
            if n0 <= n <= n1:
                w = (math.log(n) - math.log(n0)) / (math.log(n1) - math.log(n0))
                return round(t0 + w * (t1 - t0), 4)
        return pts[-1][1]

    def as_dict(self):
        """The values as plain JSON data, for a report."""
        return {"judge": self.judge, "screening_rule": self.screening_rule,
                "weights": list(self.weights), "tau_s": self.tau_s, "tau_c": self.tau_c,
                "tau_block": self.tau_block, "tau_lens": self.tau_lens,
                "tau_none": self.tau_none, "tau_leaf": self.tau_leaf,
                "strong_cell": self.strong_cell, "tau_ctx": self.tau_ctx,
                "tau_mult": self.tau_mult, "e_weights": list(self.e_weights),
                "tau_strong": self.tau_strong, "tau_gray": self.tau_gray,
                "tau_rel": self.tau_rel,
                "tau_rep_points": [[n, tau] for n, tau in self.tau_rep_points]}


def tau_rep(n, ts):
    """``ts.tau_rep(n)``: the report bar of a non-strong cluster in a file of *n* lines."""
    return ts.tau_rep(n)


def _bad():
    return ValueError(_INVALID)


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise _bad()
        out[key] = value
    return out


def _no_constant(_name):
    raise _bad()


def _number(value, high=Decimal(1)):
    """A decimal string such as ``0.96`` in [0, high], as a float (``float(str)``)."""
    if type(value) is not str or len(value) > 24 or _DECIMAL.fullmatch(value) is None:
        raise _bad()
    if Decimal(value) > high:
        raise _bad()
    return float(value)


def _numbers(value, count, high):
    if type(value) is not list or len(value) != count:
        raise _bad()
    out = tuple(_number(item, high) for item in value)
    if not any(out):
        raise _bad()
    return out


def _points(value):
    if type(value) is not list or not 1 <= len(value) <= _MAX_POINTS:
        raise _bad()
    out = []
    for item in value:
        if type(item) is not list or len(item) != 2:
            raise _bad()
        n, tau = item
        if type(n) is not int or n < 1 or (out and n <= out[-1][0]):
            raise _bad()
        out.append((n, _number(tau)))
    return tuple(out)


def _entry(judge, entry):
    if type(entry) is not dict or set(entry) != _ENTRY_KEYS:
        raise _bad()
    basis = entry["basis"]
    if type(basis) is not str or not basis.strip():
        raise _bad()
    if entry["screening_rule"] not in SCREENING_RULES:
        raise _bad()
    full = entry["pilot_full"]
    if type(full) is not dict or set(full) != _PILOT_FULL_KEYS:
        raise _bad()
    leaf_only = entry["leaf_only"]
    if type(leaf_only) is not dict or set(leaf_only) != {"tau_leaf"}:
        raise _bad()
    e_weights = _numbers(entry["e_weights"], 3, _MAX_WEIGHT)
    if not e_weights[0]:
        # E is undefined without verify: fuse_e reports a missing verify as unmeasured
        raise _bad()
    return ThresholdSet(
        judge=judge, basis=basis, screening_rule=entry["screening_rule"],
        weights=_numbers(full["weights"], 4, _MAX_WEIGHT),
        tau_s=_number(full["tau_s"]), tau_c=_number(full["tau_c"]),
        tau_block=_number(full["tau_block"]), tau_lens=_number(full["tau_lens"]),
        tau_none=_number(full["tau_none"]), tau_leaf=_number(leaf_only["tau_leaf"]),
        strong_cell=_number(entry["strong_cell"]), tau_ctx=_number(entry["tau_ctx"]),
        tau_mult=_number(entry["tau_mult"]), e_weights=e_weights,
        tau_strong=_number(entry["tau_strong"]), tau_gray=_number(entry["tau_gray"]),
        tau_rel=_number(entry["tau_rel"]), tau_rep_points=_points(entry["tau_rep_points"]))


def _parse_file(raw):
    """Every set in the file, validated whole: a defect anywhere refuses the file."""
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _bad() from None
    if type(data) is not dict or set(data) != {"version", "judges"}:
        raise _bad()
    if data["version"] != THRESHOLDS_VERSION:
        raise _bad()
    judges = data["judges"]
    if type(judges) is not dict or not judges:
        raise _bad()
    out = {}
    for judge, entry in judges.items():
        if type(judge) is not str or _JUDGE_NAME.fullmatch(judge) is None:
            raise _bad()
        out[judge] = _entry(judge, entry)
    return out


def _read_file():
    return files("decision_bug_hunter").joinpath("tile_sieve_thresholds.json").read_bytes()


def parse_thresholds(raw, judge):
    """The set of *judge* in the threshold file bytes *raw* (``load_thresholds`` reads the
    packaged file). A malformed file is ``ValueError("invalid_tile_sieve_thresholds")``; a
    judge without an entry is ``LookupError("tile_sieve_uncalibrated")``."""
    sets = _parse_file(raw)
    found = sets.get(judge) if type(judge) is str else None
    if found is None:
        raise LookupError("tile_sieve_uncalibrated")
    return found


def load_thresholds(judge):
    """The calibrated ``ThresholdSet`` of *judge*, from the packaged threshold file."""
    return parse_thresholds(_read_file(), judge)


def thresholds_sha256():
    """The sha256 of the shipped ``tile_sieve_thresholds.json``."""
    return hashlib.sha256(_read_file()).hexdigest()


# -- reading a look's answers ---------------------------------------------------------------

def canaries_pass(meta, answers):
    """(passed, detail) by DBH's pre-registered rule over the request's two canaries.

    A request with no canary role does not pass."""
    detail, ok = {}, True
    for qid, role in meta["roles"].items():
        if role.get("role") not in ("must_true", "must_false"):
            continue
        a = answers.get(qid)
        value = Decimal(str(a["noul"])) if a and "noul" in a else None
        passed = Q.control_passed(role["role"], value)
        detail[qid] = {"role": role["role"], "p": None if value is None else float(value),
                       "passed": passed}
        ok = ok and passed
    if not detail:
        return False, detail
    return ok, detail


def _noul(answers, qid):
    a = answers.get(qid)
    if a is None or "noul" not in a:
        return None
    return float(a["noul"])


def _choice(answers, qid):
    a = answers.get(qid)
    if a is None or "probabilities" not in a:
        return None
    return {k: float(v) for k, v in a["probabilities"].items()}


def _ov(cell, a, b):
    return max(0, min(cell[1], b) - max(cell[0], a) + 1)


def tile_features(meta, answers):
    """Everything screening needs from one look; ``None`` stands for a missing answer."""
    feat = {"leaf": {}, "block": {}, "gran": {}, "gran_none": None, "gran_unloc": None,
            "lens": {}, "need_ctx": _noul(answers, "need_ctx"),
            "cells": meta["cells"], "core": meta["core"]}
    for qid, role in meta["roles"].items():
        kind = role.get("role")
        if kind in ("leaf", "block"):
            feat[kind][tuple(role["cell"])] = _noul(answers, qid)
        elif kind == "gran":
            ch = _choice(answers, qid)
            if ch is not None:
                for s, e in role["cells"]:
                    feat["gran"][(s, e)] = ch.get(f"L{s}-{e}", 0.0)
                feat["gran_none"] = ch.get("none")
                feat["gran_unloc"] = ch.get("unlocalized")
        elif kind == "lens":
            ch = _choice(answers, qid)
            if ch is not None:
                feat["lens"][role["lens"]] = {
                    "blocks": {(s, e): ch.get(f"L{s}-{e}", 0.0) for s, e in role["cells"]},
                    "none": ch.get("none"), "unloc": ch.get("unlocalized")}
    return feat


def _top2_share(feat, block, leaf):
    """sum over the top-2 granules g of the block of w(g) * |g n leaf| / |g|.

    The design sums the two shares unweighted. An unweighted second granule is an arbitrary
    tie-break when the judge puts no mass on it, so each share is weighted by the granule's
    mass relative to the top one (w = p(g) / p(top), at most 1): the pilot's reading of the
    "monotone fusion" whose weights the screening fit chooses.
    """
    grans = [(g, p) for g, p in feat["gran"].items() if _ov(g, *block) * 2 >= (g[1] - g[0] + 1)]
    grans.sort(key=lambda gp: (-gp[1], gp[0]))
    top = grans[0][1] if grans else 0.0
    if top <= 0:
        return 0.0
    return sum((p / top) * _ov(g, *leaf) / (g[1] - g[0] + 1) for g, p in grans[:2])


def leaf_components(feat):
    """{leaf cell: {"leaf", "blk", "gran", "lens"}} for the leaves a look owns."""
    out = {}
    blocks = list(feat["block"].keys()) or [tuple(c) for c in feat["cells"]["block"]]
    lens_blocks = {}
    for t, d in feat["lens"].items():
        lens_blocks[t] = d["blocks"]
    for cell in (tuple(c) for c in feat["cells"]["leaf"]):
        size = cell[1] - cell[0] + 1
        leaf = feat["leaf"].get(cell)
        blk = 0.0
        for b in blocks:
            if _ov(b, *cell) and feat["block"].get(b) is not None:
                blk += feat["block"][b] * min(1.0, _top2_share(feat, b, cell))
        # plain left-to-right sums, so the last bit does not depend on the interpreter (fuse_e)
        gran = 0.0
        for g, p in feat["gran"].items():
            gran += p * _ov(g, *cell) / (g[1] - g[0] + 1)
        lens = 0.0
        for t, bp in lens_blocks.items():
            mass = 0.0
            for b, p in bp.items():
                mass += p * _ov(b, *cell) / size
            lens = max(lens, mass)
        out[cell] = {"leaf": leaf, "blk": min(1.0, blk) if feat["block"] else None,
                     "gran": min(1.0, gran) if feat["gran"] else None,
                     "lens": min(1.0, lens) if lens_blocks else None}
    return out


def fuse_z(comp, weights):
    """Monotone fusion: the weighted max of the available components."""
    vals = [w * c for w, c in zip(weights, (comp["leaf"], comp["blk"], comp["gran"], comp["lens"]))
            if c is not None and w > 0]
    return max(vals) if vals else None


# -- screening ------------------------------------------------------------------------------

def flag_tile_pilot_full(feat, ts):
    """Per-leaf flags of one look by the pilot's rule.

    A leaf is flagged when its fused score reaches ``tau_s`` or an overlapping granule reaches
    ``tau_c``. Coarse signals may only add: a block (or a lens mass on it) at its threshold
    flags every leaf of the block when no leaf inside is flagged; a low "none" mass on the
    granule question flags the leaves of the top two granules when nothing else is flagged; and
    a granule or block that no owned leaf covers becomes a flagged row of its own.

    Returns [{"cell", "z", "flag", "why", "comps"}] in cell order.
    """
    comps = leaf_components(feat)
    rows = []
    for cell in sorted(comps):
        z = fuse_z(comps[cell], ts.weights)
        why = []
        if z is not None and z >= ts.tau_s:
            why.append("z")
        for g, p in feat["gran"].items():
            if _ov(g, *cell) and p >= ts.tau_c:
                why.append("granule")
                break
        rows.append({"cell": cell, "z": z, "flag": bool(why), "why": why, "comps": comps[cell]})
    for b, pb in feat["block"].items():
        lens_hi = max((d["blocks"].get(b, 0.0) for d in feat["lens"].values()), default=0.0)
        if (pb is not None and pb >= ts.tau_block) or lens_hi >= ts.tau_lens:
            inside = [r for r in rows if _ov(r["cell"], *b)]
            if inside and not any(r["flag"] for r in inside):
                for r in inside:
                    r["flag"] = True
                    r["why"].append("orphan_block")
    if feat["gran"] and feat["gran_none"] is not None and feat["gran_none"] < ts.tau_none:
        if not any(r["flag"] for r in rows):
            top = sorted(feat["gran"].items(), key=lambda gp: (-gp[1], gp[0]))[:2]
            for r in rows:
                if any(_ov(g, *r["cell"]) for g, _p in top):
                    r["flag"] = True
                    r["why"].append("orphan_none")
    _tail_rows(rows, feat, ts)
    return rows


def _tail_rows(rows, feat, ts):
    """A short tail core can own a granule or a block whose lines lie in a leaf owned by the
    previous core (no leaf of its own). Such an owned cell still has to count: when the judge puts
    its mass on it, it becomes a flagged row of its own (``tail``)."""
    owned = [r["cell"] for r in rows]
    for g, p in feat["gran"].items():
        if p >= ts.tau_c and not any(_ov(g, *c) for c in owned):
            rows.append({"cell": g, "z": p, "flag": True, "why": ["granule_tail"], "comps": {},
                         "tail": True})
    for b, pb in feat["block"].items():
        lens_hi = max((d["blocks"].get(b, 0.0) for d in feat["lens"].values()), default=0.0)
        if (((pb is not None and pb >= ts.tau_block) or lens_hi >= ts.tau_lens)
                and not any(_ov(b, *c) for c in [r["cell"] for r in rows])):
            rows.append({"cell": b, "z": pb, "flag": True, "why": ["block_tail"], "comps": {},
                         "tail": True})
    rows.sort(key=lambda r: r["cell"])


def flag_tile_leaf_only(feat, ts):
    """Per-leaf flags of one look by the leaf predicate alone: a leaf is flagged when its
    16-line predicate reaches ``tau_leaf``. There is no granule, block, lens, none or tail rule.

    Returns rows of the same shape as ``flag_tile_pilot_full``."""
    comps = leaf_components(feat)
    rows = []
    for cell in sorted(comps):
        z = comps[cell]["leaf"]
        flag = z is not None and z >= ts.tau_leaf
        rows.append({"cell": cell, "z": z, "flag": flag, "why": ["z"] if flag else [],
                     "comps": comps[cell]})
    return rows


def flag_tile(feat, ts):
    """The flags of one look by the screening variant of the set (``ts.screening_rule``)."""
    if ts.screening_rule == "pilot-full":
        return flag_tile_pilot_full(feat, ts)
    if ts.screening_rule == "leaf-only":
        return flag_tile_leaf_only(feat, ts)
    raise ValueError("invalid_screening_rule")


# -- clusters -------------------------------------------------------------------------------

def make_clusters(intervals, n, gap=CLUSTER_GAP, cap=CLUSTER_MAX, pad=CLUSTER_PAD):
    """Union of flagged leaf intervals, merged when the gap is <= *gap* lines, split into
    pieces of <= *cap* lines, each padded by *pad* lines (clipped to the file)."""
    return [c["K"] for c in make_clusters_ex(intervals, n, gap, cap, pad)]


def make_clusters_ex(intervals, n, gap=CLUSTER_GAP, cap=CLUSTER_MAX, pad=CLUSTER_PAD):
    """Like make_clusters, with the unpadded core of each piece: [{"core", "K"}]."""
    spans = sorted((int(a), int(b)) for a, b in intervals)
    merged = []
    for a, b in spans:
        if merged and a - merged[-1][1] - 1 <= gap:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    out = []
    for a, b in merged:
        size = b - a + 1
        pieces = max(1, -(-size // cap))
        step = -(-size // pieces)
        s = a
        while s <= b:
            e = min(b, s + step - 1)
            out.append({"core": (s, e), "K": (max(1, s - pad), min(n, e + pad))})
            s = e + 1
    return out


def cluster_peak(cluster, look_features):
    """The largest leaf predicate score of a leaf overlapping the cluster's core, or granule
    probability of a granule overlapping it, over the features of every look of the file.

    *cluster* is a ``make_clusters_ex`` item or a bare ``(first, last)`` core. The raw scores are
    read, not the flags, so the value means the same under every screening variant. With the
    shipped weights the fused leaf score is the leaf predicate."""
    a, b = cluster["core"] if isinstance(cluster, dict) else cluster
    best = 0.0
    for feat in look_features:
        for cell, p in feat["leaf"].items():
            if p is not None and _ov(cell, a, b) and p > best:
                best = p
        for g, p in feat["gran"].items():
            if p is not None and _ov(g, a, b) and p > best:
                best = p
    return best


def cluster_strength(cluster, look_features, ts):
    """True when the cluster is strong: a member leaf or an overlapping granule scored at least
    ``ts.strong_cell`` in some look. Computed whatever the screening variant."""
    return cluster_peak(cluster, look_features) >= ts.strong_cell


# -- focus: scores, report rule, runs -------------------------------------------------------

def focus_scores(meta, answers, ts):
    """(p, E): the inputs and the fused focus score of one focus request.

    ``p["twin_refused"]`` is True when the request asked the twin and has no usable answer to
    it; the score then rests on verify alone. ``E`` is None when verify has no answer."""
    p = {"verify": None, "twin": None, "twin_refused": False, "lens": 0.0, "relation": 0.0,
         "multiple": None, "need_ctx": None, "requirement": 0.0}
    asked_twin = False
    for qid, role in meta["roles"].items():
        kind = role.get("role")
        v = _noul(answers, qid)
        if kind in ("verify", "twin", "multiple", "need_ctx"):
            p[kind] = v
            asked_twin = asked_twin or kind == "twin"
        elif kind == "lens" and v is not None:
            p["lens"] = max(p["lens"], v)
        elif kind == "relation" and v is not None:
            p["relation"] = max(p["relation"], v)
        elif kind == "requirement" and v is not None:
            p["requirement"] = max(p["requirement"], v)
    p["twin_refused"] = asked_twin and p["twin"] is None
    return p, fuse_e(p, ts)


def fuse_e(p, ts):
    """E = (w_v * verify + w_t * (1 - twin) + w_l * lens) / (sum of the used weights), summed in
    that order. A missing twin leaves its term and its weight out, so E is verify alone; a
    missing verify gives None."""
    verify = p["verify"]
    if verify is None:
        return None
    parts = [verify, None if p["twin"] is None else 1 - p["twin"], p["lens"]]
    # A plain left-to-right loop: the built-in sum() is compensated from Python 3.12 and naive
    # before, which would move the last bit of a three-term score between interpreters.
    num = den = 0.0
    for w, x in zip(ts.e_weights, parts):
        if x is not None and w > 0:
            num += w * x
            den += w
    return None if den == 0 else num / den


def report_bar(strong, n, ts):
    """(name, value) of the bar a cluster must reach: ("strong", tau_strong) or
    ("tau_rep", tau_rep(n))."""
    if strong:
        return "strong", ts.tau_strong
    return "tau_rep", ts.tau_rep(n)


def focus_decision(p, e, n, strong, ts):
    """'report' | 'clear' | 'unmeasured' for one cluster of a file of *n* lines.

    Report when E reaches the bar of the cluster (``tau_strong`` if strong, else ``tau_rep(n)``),
    or when the relation score reaches ``tau_rel`` and E reaches ``tau_gray``; otherwise clear.
    No score at all is unmeasured."""
    if e is None:
        return "unmeasured"
    _name, bar = report_bar(strong, n, ts)
    if e >= bar or (p["relation"] >= ts.tau_rel and e >= ts.tau_gray):
        return "report"
    return "clear"


# -- runs and findings ----------------------------------------------------------------------

def _fractions(answer):
    return {"probabilities": {k: Fraction(str(v)) for k, v in answer["probabilities"].items()}}


def combined_runs(answers, meta, limit, threshold=Fraction(1, 2), roles=("loc_a", "loc_b")):
    """Mass-gate runs of loc_a + loc_b: per-line mass averaged over the two menus, the DBH
    rule (hidden mass none + unlocalized + undisplayed must stay below one half).
    *roles* narrows the menus (("loc_a",) measures what loc_b adds).

    Returns (runs, number of runs with mass); no run when the hidden mass reaches one half."""
    # imported here, not at module level: the engine loads this module for its thresholds
    from .engine import hidden_choice_mass, line_overlap_mass
    menus = []
    for qid, role in meta["roles"].items():
        if role.get("role") in roles and qid in answers and "probabilities" in answers[qid]:
            menus.append((answers[qid], {f"L{s}-{e}": Span(s, e) for s, e in role["cells"]}))
    if not menus:
        return [], 0
    mass, hidden = {}, Fraction(0)
    zero = Fraction(0)
    for answer, options in menus:
        hidden += hidden_choice_mass(_fractions(answer))
        for line, m in line_overlap_mass(_fractions(answer), options, zero).items():
            mass[line] = mass.get(line, Fraction(0)) + m
    k = len(menus)
    hidden /= k
    if hidden >= Fraction(1, 2):
        return [], 0
    mass = {line: m / k for line, m in mass.items()}
    runs, current = [], []
    for line in sorted(mass):
        if mass[line] < Fraction(threshold):
            continue
        if current and line == current[-1] + 1:
            current.append(line)
        else:
            if current:
                runs.append(current)
            current = [line]
    if current:
        runs.append(current)
    runs.sort(key=lambda ls: (-max(mass[x] for x in ls), -sum(mass[x] for x in ls), ls[0]))
    return [(ls[0], ls[-1]) for ls in runs[:max(0, limit)]], len(runs)


def report_runs(answers, meta, p, ts, roles=("loc_a", "loc_b")):
    """(runs, runs with mass): up to 3 runs when the multiple score reaches ``tau_mult``, else
    the top one."""
    limit = 3 if (p.get("multiple") or 0) >= ts.tau_mult else 1
    return combined_runs(answers, meta, limit, roles=roles)


def reconcile(intervals):
    """Interval union of reported runs; keep both when they overlap by < 50% of the smaller."""
    out = []
    for a, b in sorted(intervals):
        for i, (c, d) in enumerate(out):
            ov = min(b, d) - max(a, c) + 1
            small = min(b - a + 1, d - c + 1)
            if ov > 0 and ov >= 0.5 * small:
                out[i] = (min(a, c), max(b, d))
                break
        else:
            out.append((a, b))
    return sorted(out)
