"""The engine of the ``tile-sieve-beta`` search policy (whole-file mode).

A file that fits in one request is read in one or two whole-file looks: one for
a file of at most 8 lines or when both looks' requests come out identical, two
otherwise. Each look asks leaf (16-line), block (48-line) and granule (8-line)
cell questions over the whole file, the second look on a grid shifted against
the first. Flagged regions are merged into clusters, and each cluster gets one
focus request: the owner's rule 8C then reports it at ``tau_strong`` when it is
strong and at ``tau_rep(n)`` otherwise, and the localization answers of the
reported clusters become the findings. There is no second stage, and no extra
call is made for the handoff: findings are annotated from the evidence already
in hand.

Every request goes through ``Search.ask``, so the cache, the budgets, the judge
controls, the receipts and the trace rows are the legacy engine's own. The
requests are built by ``tile_sieve_plan`` and sent as planned: the planner's
sha256 is checked against the one ``ask`` computed, and a difference is an
integrity failure, never a fallback. A file that does not fit one request is
scanned by ``legacy-v1`` and the report says why.

The report is schema 9 with a ``tile_sieve`` block and the handoff is version 6.
A cluster whose twin was refused but whose verify answer is present is decided
on verify alone and carries a non-blocking ``twin_refused`` note; any other
missing answer leaves the cluster unmeasured and the scan incomplete.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import injection_markers
from . import protocol as P
from . import questions as Q
from . import tile_sieve_fusion as F
from . import tile_sieve_plan as TP
from .core import Span, _coverage
from .handoff import DISPLAY_REFS, LIMITS, compact_report
from .protocol import ANSWER_SCOPED_CODES

VERSION = "tile-sieve-beta/1"
POLICY = "tile-sieve-beta"
FOCUS_PHASE = "ts-focus"
#: A requirement predicate at this score or more names its passage in the handoff.
REQUIREMENT_MIN = 0.5
CAPS = {"max_questions": TP.MAX_QUESTIONS, "max_request_bytes": TP.MAX_REQUEST_BYTES,
        "max_state_bytes": TP.MAX_STATE_BYTES}


def _text(value):
    return None if value is None else str(value)


def _noncontrol(request):
    return [qid for qid in request.questions if not Q.CONTROL_NAME.fullmatch(qid)]


def _overlaps(cell, lo, hi):
    return cell[0] <= hi and lo <= cell[1]


@dataclass
class _Look:
    """One planned look request and what the judge answered."""

    request: TP.Request
    assessed: bool = False
    features: dict | None = None
    rows: list = field(default_factory=list)

    @property
    def need_ctx(self):
        return None if self.features is None else self.features["need_ctx"]


@dataclass
class _Cluster:
    """A flagged region, its focus request and the decision taken on it."""

    core: tuple
    K: tuple
    strong: bool
    bar: str
    bar_value: float
    request: TP.Request | None = None
    answers: dict = field(default_factory=dict)
    p: dict | None = None
    e: float | None = None
    decision: str = "unmeasured"
    twin_refused: bool = False
    runs: list = field(default_factory=list)
    fell_back_to_k: bool = False


class TileSieve:
    """Whole-file Tile Sieve for one ``Search``; composed into it like ``ScopedClaims``."""

    def __init__(self, search):
        self.search = search
        judge = getattr(search.gw, "judge", None)
        #: True when the gateway names its judge; a custom gateway uses the OpenAI set.
        self.judge_declared = type(judge) is str
        self.thresholds_set = judge if self.judge_declared else "openai"
        try:
            self.ts = F.load_thresholds(self.thresholds_set)
        except LookupError:
            # A known judge with no calibrated set: refused before any call.
            raise ValueError("invalid_search_configuration") from None
        #: The planner's ``Fallback`` when the file did not fit, set by the engine.
        self.fallback = None
        #: True while a whole-file run is in progress or done.
        self.active = False

    # -- planning ------------------------------------------------------------------------
    def plan(self):
        """A ``WholeFilePlan`` when both looks fit one request, else a ``Fallback``."""
        search = self.search
        entries = search.project.entries if search.project is not None else ()
        return TP.plan_whole_file(search.source, search.spec_source, entries,
                                  search.context_scope)

    @staticmethod
    def fits(plan):
        return isinstance(plan, TP.WholeFilePlan)

    # -- the run -------------------------------------------------------------------------
    def run(self, plan):
        """Run the whole-file policy on *plan* and return the schema 9 report."""
        self.active = True
        envelope = P.RequestEnvelope(plan.planner.policy, TP.MAX_QUESTIONS, TP.ENVELOPE_BYTES)
        with P.using_request_envelope(envelope):
            looks, clusters, merged = self._measure(plan)
        return self._report(plan, looks, clusters, merged)

    def _measure(self, plan):
        search, ts, n = self.search, self.ts, plan.n
        whole = Span(1, n)
        looks = [self._screen(request, whole) for request in plan.looks]
        assessed = [look for look in looks if look.assessed]
        flagged = [row["cell"] for look in assessed for row in look.rows if row["flag"]]
        if any(look.need_ctx is not None and look.need_ctx >= ts.tau_ctx for look in assessed):
            search.issue("context_unresolved", whole, "ts-screen")
        features = [look.features for look in assessed]
        clusters = [self._focus(plan.planner, found, features, n)
                    for found in F.make_clusters_ex(flagged, n)]
        merged = F.reconcile([run for cluster in clusters for run in cluster.runs])
        return looks, clusters, merged

    def _ask(self, request, region, phase):
        """Ask one planned request and return its answers; the wire is the planned one."""
        origins = []
        answers = self.search.ask(
            request.state, {qid: q for qid, q in request.questions.items()
                            if not Q.CONTROL_NAME.fullmatch(qid)},
            region, phase, origins=origins)
        for origin in origins:
            sha = origin["request_sha256"]
            if sha is not None and sha != request.sha256:
                raise TP.IntegrityError("planned_request_differs_from_sent")
        return answers

    def _screen(self, request, whole):
        look = _Look(request)
        answers = self._ask(request, whole, f"ts-screen-l{request.looks[0]}")
        # A look counts only if every non-control answer is present: there is no
        # re-ask and no split, since a whole-file re-ask is the same bytes.
        look.assessed = all(qid in answers for qid in _noncontrol(request))
        if look.assessed:
            look.features = F.tile_features(request.meta, answers)
            look.rows = F.flag_tile(look.features, self.ts)
        return look

    def _defects(self, sha256):
        """The answer-scoped defects of the request with this hash, by question name."""
        for row in reversed(self.search.trace):
            if row["request_sha256"] == sha256:
                return dict(row.get("scoped") or {})
        return {}

    def _focus(self, planner, found, features, n):
        search, ts = self.search, self.ts
        lo, hi = found["K"]
        strong = F.cluster_strength(found, features, ts)
        bar, bar_value = F.report_bar(strong, n, ts)
        cluster = _Cluster(tuple(found["core"]), (lo, hi), strong, bar, bar_value)
        try:
            request = planner.focus((lo, hi))
        except TP.PlanError:
            search.issue("tile_sieve_focus_unfittable", Span(lo, hi), FOCUS_PHASE)
            return cluster
        # A span with a focus request is a span the scan looked at: ``answer_quality``
        # reads ``support`` to tell whether a refused window overlaps one.
        search.support.setdefault(Span(lo, hi), [])
        answers = self._ask(request, Span(lo, hi), FOCUS_PHASE)
        cluster.request, cluster.answers = request, answers
        cluster.p, e = F.focus_scores(request.meta, answers, ts)
        missing = [qid for qid in _noncontrol(request) if qid not in answers]
        twins = [qid for qid, role in request.roles.items() if role.get("role") == "twin"]
        refused = (missing == twins and len(twins) == 1
                   and self._defects(request.sha256).get(twins[0]) == "question_refused")
        if missing and not refused:
            return cluster
        cluster.e = e
        cluster.decision = F.focus_decision(cluster.p, e, n, strong, ts)
        if cluster.decision == "unmeasured":
            return cluster
        if refused:
            # The twin decides nothing here: verify alone does. The refusal is a
            # note on the scan, not a reason to call it incomplete.
            cluster.twin_refused = True
            search.issue("twin_refused", Span(lo, hi), FOCUS_PHASE, affects=False)
            for item in search.issues:
                if (item["code"] == "question_refused" and item["range"] == [lo, hi]
                        and item["phase"] == FOCUS_PHASE):
                    item["affects_completion"] = False
        if cluster.decision == "report":
            runs, _count = F.report_runs(answers, request.meta, cluster.p, ts)
            if not runs:
                runs, cluster.fell_back_to_k = [(lo, hi)], True
            cluster.runs = [tuple(run) for run in runs]
        return cluster

    # -- the report ----------------------------------------------------------------------
    def assessment(self, target):
        """Every finding rests on its focus request."""
        return "focus-supported"

    def _report(self, plan, looks, clusters, merged):
        search, n = self.search, plan.n
        coverage = _coverage([Span(1, n)] if all(look.assessed for look in looks) else [], n)
        complete = (coverage["all_lines_assessed"]
                    and not any(cluster.decision == "unmeasured" for cluster in clusters)
                    and not any(issue["affects_completion"] for issue in search.issues))
        return search._result(
            schema_version=9, scan_status="complete" if complete else "incomplete",
            complete=complete, handoff_incomplete=False,
            findings=self._findings(merged, clusters, looks), gating={}, coverage=coverage,
            tile_sieve=self._block(plan, looks, clusters))

    def _findings(self, merged, clusters, looks):
        findings = []
        for index, (first, last) in enumerate(merged, 1):
            span = Span(first, last)
            owners = [cluster for cluster in clusters if cluster.decision == "report"
                      and any(first <= a and b <= last for a, b in cluster.runs)]
            support = []
            for cluster in owners:
                support.extend(self._flag_support(cluster, looks))
                support.append({"origin": "focus", "request_sha256": cluster.request.sha256,
                                "E": str(cluster.e)})
            findings.append({
                "window_id": span.id, "start_line": first, "end_line": last,
                "resolution": "focus_reported", "support": support,
                "support_paths": sorted({row["origin"] for row in support}),
                "finding_id": f"F{index}", "assessment": self.assessment(span),
                "read_with": self._read_with(owners),
                "relevant_requirement": self._requirement(owners),
                "unresolved_parents": [], "limitations": self._limitations(span),
                "handoff_incomplete": False})
        return findings

    @staticmethod
    def _flag_support(cluster, looks):
        lo, hi = cluster.core
        return [{"origin": "tile_screen", "look": look.request.looks[0],
                 "request_sha256": look.request.sha256,
                 "cell": [row["cell"][0], row["cell"][1]], "why": list(row["why"])}
                for look in looks if look.assessed for row in look.rows
                if row["flag"] and _overlaps(row["cell"], lo, hi)]

    def _limitations(self, span):
        search, limits = self.search, set()
        for issue in search.issues:
            lo, hi = issue["range"]
            if not issue["affects_completion"] and issue["code"] not in ANSWER_SCOPED_CODES:
                continue
            if lo <= span.end and span.start <= hi:
                limits.add(LIMITS.get(issue["code"], "evaluation-failed"))
        if injection_markers.overlapping(search.injection_markers, span.start, span.end):
            limits.add("injection-marker")
        return sorted(limits)

    @staticmethod
    def _selected(owners, role_name, key, floor):
        """(ranges, answers read): the spans named by the *key* of each answered question of
        role *role_name* whose predicate reached *floor*, strongest first."""
        found, assessed = {}, 0
        for cluster in owners:
            for qid, role in cluster.request.roles.items():
                if role.get("role") != role_name or qid not in cluster.answers:
                    continue
                assessed += 1
                score = float(cluster.answers[qid]["noul"])
                if score >= floor:
                    pair = tuple(role[key])
                    found[pair] = max(score, found.get(pair, 0.0))
        ordered = sorted(found.items(), key=lambda item: (-item[1], item[0][1] - item[0][0],
                                                          item[0][0]))
        return [list(pair) for pair, _score in ordered], assessed

    def _read_with(self, owners):
        """In-file partners whose relation answer reached ``tau_rel``."""
        ranges, assessed = self._selected(owners, "relation", "partner", self.ts.tau_rel)
        return {"status": "selected" if ranges else "not-identified",
                "ranges": ranges[:DISPLAY_REFS],
                "refs": [{"file": None, "range": pair} for pair in ranges[:DISPLAY_REFS]],
                "all_refs": [{"file": None, "range": pair} for pair in ranges],
                "additional_count": max(0, len(ranges) - DISPLAY_REFS),
                "all_ranges": ranges, "candidates_assessed": assessed}

    def _requirement(self, owners):
        """Specification passages whose requirement answer reached ``REQUIREMENT_MIN``."""
        if self.search.spec_source is None:
            return {"status": "not-supplied", "ranges": [], "refs": [], "additional_count": 0,
                    "all_ranges": [], "candidates_assessed": 0}
        ranges, assessed = self._selected(owners, "requirement", "passage", REQUIREMENT_MIN)
        return {"status": "selected" if ranges else "not-identified",
                "ranges": ranges[:DISPLAY_REFS],
                "refs": [{"file": "SPEC", "range": pair} for pair in ranges[:DISPLAY_REFS]],
                "additional_count": max(0, len(ranges) - DISPLAY_REFS),
                "all_ranges": ranges, "candidates_assessed": assessed}

    def _block(self, plan, looks, clusters):
        ts = self.ts
        return {
            "version": VERSION, "mode": "whole-file", "policy_run": POLICY,
            "looks": len(looks), "phases": [list(phase) for phase in TP.PHASES],
            "grids": {"leaf": TP.LEAF, "block": TP.BLOCK, "granule": TP.GRAN},
            "caps": dict(CAPS), "pack_sha256": TP.tile_sieve_pack_sha256(),
            "thresholds_set": self.thresholds_set, "judge_declared": self.judge_declared,
            "thresholds_sha256": F.thresholds_sha256(), "screening_rule": ts.screening_rule,
            "thresholds": ts.as_dict(), "thresholds_basis": ts.basis,
            "tau_rep_used": str(ts.tau_rep(plan.n)),
            "looks_detail": [{
                "look": look.request.looks[0], "looks_served": list(look.request.looks),
                "request_sha256": look.request.sha256, "questions": look.request.nq,
                "request_bytes": look.request.request_bytes,
                "state_bytes": look.request.state_bytes, "assessed": look.assessed,
                "need_context": _text(look.need_ctx),
                "flagged": [list(row["cell"]) for row in look.rows if row["flag"]]}
                for look in looks],
            "clusters": [self._cluster_record(cluster) for cluster in clusters]}

    @staticmethod
    def _cluster_record(cluster):
        p = cluster.p or {}
        return {"K": list(cluster.K), "core": list(cluster.core),
                "focus_sha256": None if cluster.request is None else cluster.request.sha256,
                "strong": cluster.strong, "bar": cluster.bar,
                "bar_value": str(cluster.bar_value), "E": _text(cluster.e),
                "verify": _text(p.get("verify")), "twin": _text(p.get("twin")),
                "twin_refused": cluster.twin_refused,
                "relation_max": _text(p.get("relation")), "multiple": _text(p.get("multiple")),
                "decision": cluster.decision, "runs": [list(run) for run in cluster.runs],
                "runs_fell_back_to_K": cluster.fell_back_to_k}

    # -- the fallback --------------------------------------------------------------------
    def wrap_fallback(self, result):
        """The legacy-v1 report of a file that did not fit, marked as tile-sieve-beta's."""
        fallback = self.fallback
        result["schema_version"] = 9
        result["tile_sieve"] = {
            "version": VERSION, "mode": "legacy-fallback", "policy_run": "legacy-v1",
            "reason": fallback.reason, "detail": dict(fallback.detail), "caps": dict(CAPS)}
        del result["handoff"]
        result["handoff"] = compact_report(result)
        return result
