"""judge-led speculative screening, context selection and interval localization.

Only the gateway judges text. This executor supplies real candidate IDs, enforces
bounds, preserves unresolved suspicions, and builds a compact debugger handoff.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
import math
import re
import time

from . import __version__
from .claims import select_exploration, identity
from .core import Config, Source, Span, _coverage, windows, multiscale
from .core import contiguous_candidates, _window_count, _window_at
from .evidence import EvidenceRef, evidence_label, fitting_pair_state, excerpt
from .protocol import (ProviderError, encode_request, plain, validate_answer_objects, validate_usage,
                  CONTRACT_VERSION, MAX_QUESTIONS, MAX_REQUEST_BYTES, MAX_STATE_BYTES,
                  DEFAULT_CHOICE_ROUNDING_PLACES, ANSWER_SCOPED_CODES, RequestEnvelope,
                  request_envelope, using_request_envelope)
from .providers import Classification, ValidatedGateway, classify
from .questions import (load_pack, noul, choice, screening, fitting_state,
                        state_for, prepared_question_batches, target_text, action_choice,
                        evidence_noul, LENS_KINDS, policy, _ordered_state,
                        using_state_layout, singleton_candidates, MAX_RANK_PAGE,
                        CONTROL_NAME, CONTROL_RESERVE_BYTES, CONTROL_SET,
                        CONTROL_MUST_TRUE_MIN, CONTROL_MUST_FALSE_MAX,
                        control_role, control_passed)
from . import injection_markers


MAX_PREPARED_WIRE_BYTES = 1024 * 1024
#: Gateway refusals that never reached the provider and end the run's dispatch.
_DISPATCH_REFUSALS = frozenset({"run_deadline_reserved", "provider_stopped",
                                "cost_budget_exhausted"})
#: Choice questions that only route the search (ADR-3(5)): a defect in one
#: of them is counted but does not by itself make the run incomplete.
_ROUTING_QUESTION = re.compile(r"(?:rank_[0-9]+|where|context_where|action)\Z")
#: Diagnostic-only questions (polarity twin): a defect is counted, never
#: a reason for incompleteness.
_DIAGNOSTIC_QUESTION = re.compile(r"twin_L[0-9]+-[0-9]+\Z")
#: Questions whose name ends in the target window they judge.
_WINDOW_QUESTION = re.compile(
    r"(?:screen|verify|twin|" + "|".join(LENS_KINDS) + r")_L([0-9]+)-([0-9]+)\Z")
#: Banner thresholds (ADR-4(2), (4)).
ARGMAX_BANNER_RATE = Fraction(2, 100)
ARGMAX_BANNER_MIN_ANSWERS = 50
IDENTITY_BANNER_VIOLATIONS = 3
#: The b1 report's calibration record (ADR-7(1)); no profile exists yet.
CALIBRATION = {"status": "uncalibrated", "profile_id": None}


def _binomial_cdf(k, n, p):
    """P(X <= k) for X ~ Binomial(n, p), summed in log space."""
    if k < 0:
        return 0.0
    if k >= n or p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    if k > n // 2:
        # Sum the shorter tail: P(X <= k) = 1 - P(n - X <= n - k - 1).
        return 1.0 - _binomial_cdf(n - k - 1, n, 1.0 - p)
    log_p, log_q, base = math.log(p), math.log1p(-p), math.lgamma(n + 1)
    total = sum(math.exp(base - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                         + i * log_p + (n - i) * log_q) for i in range(k + 1))
    return min(1.0, total)


def clopper_pearson(k, n, confidence=0.95):
    """The exact (Clopper-Pearson) two-sided interval for k successes in n.

    Returns ``None`` when ``n`` is 0. Bounds are found by bisection on the
    binomial tails and rounded outward to six decimal places.
    """
    if type(k) is not int or type(n) is not int or not 0 <= k <= n:
        raise ValueError("invalid_binomial_counts")
    if n == 0:
        return None
    tail = (1.0 - confidence) / 2.0

    def solve(predicate):
        lo, hi = 0.0, 1.0
        for _ in range(64):
            mid = (lo + hi) / 2.0
            if predicate(mid):
                hi = mid
            else:
                lo = mid
        return lo, hi

    lower = 0.0 if k == 0 else solve(lambda p: 1.0 - _binomial_cdf(k - 1, n, p) >= tail)[0]
    upper = 1.0 if k == n else solve(lambda p: _binomial_cdf(k, n, p) <= tail)[1]
    return [math.floor(lower * 1e6) / 1e6, math.ceil(upper * 1e6) / 1e6]


def _decimal_places(value):
    exponent = value.as_tuple().exponent if isinstance(value, Decimal) else 0
    return max(0, -exponent) if type(exponent) is int else 0


def confidence_identity_violation(answer, places):
    """Whether a choice breaks ``chance_normalized_p1`` beyond display rounding.

    The identity is c = (p1 - 1/k) / (1 - 1/k); with half a display quantum
    h, a violation is |c - (p1 - 1/k) / (1 - 1/k)| > h / (1 - 1/k) + h
    (ADR-4(4)). ``places`` is the display precision; ``None`` uses the
    places observed in this answer, a lower bound on the true precision.
    """
    probabilities = answer["probabilities"]
    k = len(probabilities)
    if places is None:
        places = max(_decimal_places(v) for v in (answer["confidence"],
                                                  *probabilities.values()))
    chance = Fraction(1, k)
    p1 = Fraction(max(probabilities.values()))
    half = Fraction(1, 2 * 10 ** places)
    expected = (p1 - chance) / (1 - chance)
    return abs(Fraction(answer["confidence"]) - expected) > half / (1 - chance) + half


def half_quantum(places):
    """Half a display quantum, h = 0.5 * 10**-places, as an exact fraction."""
    return Fraction(1, 2 * 10 ** places)


def answer_places(answer):
    """Decimal places displayed in one choice answer: a lower bound only."""
    return max(_decimal_places(v) for v in (answer["confidence"],
                                            *answer["probabilities"].values()))


def choice_option_cap(places):
    """Most options a choice may offer under rounding at *places*: k * h <= 1/8."""
    return int(Fraction(1, 8) / half_quantum(places))


def line_overlap_mass(answer, options, half):
    """M(line) = sum of max(0, v - h) over interval options containing it.

    *options* maps option ids to the Spans they name; sentinel options (none,
    unlocalized) carry no line. The lower bound L(i) = max(0, v - h) never
    credits a line with more mass than the displayed value guarantees.
    """
    mass = {}
    for key, span in options.items():
        lower = Fraction(answer["probabilities"].get(key, 0)) - half
        if lower <= 0:
            continue
        for line in range(span.start, span.end + 1):
            mass[line] = mass.get(line, 0) + lower
    return mass


def hidden_choice_mass(answer):
    """v(none) + v(unlocalized) plus any undisplayed mass 1 - sum(v)."""
    probabilities = answer["probabilities"]
    total = sum((Fraction(v) for v in probabilities.values()), Fraction(0))
    return (Fraction(probabilities.get("none", 0))
            + Fraction(probabilities.get("unlocalized", 0))
            + max(Fraction(0), 1 - total))


def mass_gate_runs(answer, options, threshold, half, limit):
    """The per-line overlap gate (ADR-4(5)); returns (runs, qualifying, hidden).

    Runs are the maximal contiguous line runs with M(line) >= *threshold*,
    ranked by peak M, then total M, then position; at most *limit* are kept.
    Nothing is selected while hidden mass (none, unlocalized and undisplayed
    mass) reaches one half. On a singleton menu this is v - h >= threshold.
    """
    hidden = hidden_choice_mass(answer)
    if hidden >= Fraction(1, 2):
        return [], 0, hidden
    threshold = Fraction(threshold)
    mass = line_overlap_mass(answer, options, half)
    runs: list[list[int]] = []
    current: list[int] = []
    for line in sorted(mass):
        if mass[line] < threshold:
            continue
        if current and line == current[-1] + 1:
            current.append(line)
        else:
            if current:
                runs.append(current)
            current = [line]
    if current:
        runs.append(current)
    runs.sort(key=lambda lines: (-max(mass[x] for x in lines),
                                 -sum(mass[x] for x in lines), lines[0]))
    return ([Span(lines[0], lines[-1]) for lines in runs[:max(0, limit)]],
            len(runs), hidden)


def choice_mass_diffuse(answer, places):
    """ADR-4(3): 1 - sum(v) > k0 * h + 4h * sqrt(k+ / 3) under rounding at *places*.

    k0 counts options displayed as 0 and k+ the others. Exact arithmetic:
    with d = 1 - sum(v) - k0 * h > 0, the test is 3 * d**2 > 16 * h**2 * k+.
    """
    half = half_quantum(places)
    values = [Fraction(v) for v in answer["probabilities"].values()]
    zero = sum(v == 0 for v in values)
    positive = len(values) - zero
    excess = 1 - sum(values, Fraction(0)) - zero * half
    return excess > 0 and 3 * excess * excess > 16 * half * half * positive


def _fraction_text(value):
    """A Fraction with a terminating decimal expansion, as decimal text."""
    return str(Decimal(value.numerator) / Decimal(value.denominator))


def _permanent(exc):
    """Whether a failed request would fail the same way if asked again (ADR-2(9))."""
    given = getattr(exc, "classification", None)
    if type(given) is Classification and given.code == exc.code:
        return given.permanent
    return classify(exc.code).permanent


def _count(value):
    return value if type(value) is int and value >= 0 else None


_SPEND_AMOUNTS = ("provider_reported_usd", "estimated_usd", "unknown_usage_upper_bound_usd",
                  "upper_bound_usd", "max_cost_usd")


def _spend(value):
    """A gateway's spend summary, copied only when well formed."""
    if type(value) is not dict:
        return None
    result = {}
    for name in _SPEND_AMOUNTS:
        amount = value.get(name)
        if amount is not None and not (type(amount) is str
                                       and re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,40})?", amount)):
            return None
        result[name] = amount
    date = value.get("price_table_date")
    result["price_table_date"] = (date if type(date) is str
                                  and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date) else None)
    attempts = value.get("attempts")
    result["attempts"] = ({k: v for k, v in attempts.items()
                           if type(k) is str and _count(v) is not None}
                          if type(attempts) is dict else {})
    return result


SECRET_SCAN_TARGETS = ("clean", "overridden")


def _secret_scan_record(value):
    """The caller's secret-scan record (ADR-10), exactly two known fields."""
    if value is None:
        return None
    if (type(value) is not dict or set(value) != {"target", "project_files_skipped"}
            or value["target"] not in SECRET_SCAN_TARGETS
            or _count(value["project_files_skipped"]) is None):
        raise ValueError("invalid_secret_scan")
    return {"target": value["target"],
            "project_files_skipped": value["project_files_skipped"]}


def digest(value):
    raw =json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _copy_validated_answers(answers):
    """Copy the closed answer schema; validated scalars are immutable."""
    result = {}
    for qid, answer in answers.items():
        copied = answer.copy()
        if answer["type"] == "choice":
            copied["probabilities"] = answer["probabilities"].copy()
        result[qid] = copied
    return result


class Search:
    def __init__(self, source, gateway, config, spec, project=None,
                 context_scope="declared_standalone", deadline_at=None,
                 secret_scan=None):
        if not isinstance(source, Source) or not isinstance(config, Config):
            raise ValueError("invalid_scan_arguments")
        self.secret_scan = _secret_scan_record(secret_scan)
        self.spec_source = spec if isinstance(spec, Source) else (
            Source.from_text(spec) if type(spec) is str else None)
        if isinstance(spec, Source):
            spec = "\n".join(spec.lines)
        if self.spec_source is not None and len(self.spec_source.lines) > 2000:
            raise ValueError("specification_too_many_lines")
        if spec is not None and (type(spec) is not str or not spec.strip()):
            raise ValueError("specification_must_be_nonempty_text")
        if spec is not None and len(spec.encode("utf-8")) > 8192:
            raise ValueError("specification_too_large")
        if hasattr(gateway, "check_sensitive"):
            gateway.check_sensitive(source.name, source.path,
                                    "\n".join(source.lines), spec,
                                    self.spec_source.path if self.spec_source else None)
        self.source, self.gw, self.cfg, self.spec = source, gateway, config, spec
        self.project = project
        self.context_scope = context_scope
        self.deadline_at = (time.monotonic() + config.run_deadline_seconds
                            if deadline_at is None else deadline_at)
        if hasattr(gateway, "set_run_deadline"):
            gateway.set_run_deadline(self.deadline_at)
        self.pack, self.pack_hash = load_pack()
        if hasattr(gateway, "check_sensitive"):
            gateway.check_sensitive(self.pack)
            if project is not None:
                for entry in project.entries:
                    gateway.check_sensitive(entry.relpath, entry.source.path,
                                            "\n".join(entry.source.lines))
        self.calls = self.questions = self.validated_questions = 0
        self.window_count = self.cache_hits = 0
        self.trace, self.observations, self.issues, self.events = [], [], [], []
        self._issue_candidates = {}
        self.cache, self.groups, self.support, self.verified = {}, [], {}, {}
        self.verify_outcomes = {}
        self.rechecks, self.existence_checks, self.handoff_evidence = [], [], []
        self.action_targets = set()
        self.relationship_promotions = []
        self.evidence_by_target = {}
        self.evidence_searches, self.relationships, self.action_trace = [], [], []
        self.action_requirement_evidence = {}
        self.action_requirement_stats = {}
        self.evidence_refs = {}
        self.context_reassessed_states = set()
        # failed_requests: key -> {"code", "permanent"}; a transient failure
        # may be asked once more (ADR-2(9)), recorded in ``reasked``.
        self.request_origins, self.failed_requests, self.reasked = {}, {}, set()
        self.dispatch_refused = None
        # Judgments and failures are keyed by (route, model, request hash):
        # request_sha256 hashes the local envelope, identical on every route.
        self.route_key = (getattr(gateway, "provider_id", "custom-unverified"),
                          getattr(gateway, "model_id", None))
        self.models_returned, self.answer_order_mismatch = set(), 0
        # Answer-level defects (ADR-3, ADR-4): counted on fresh responses
        # only; ``suppressed`` holds windows lost to refusal or moderation.
        self.answer_defects, self.routing_defects = {}, 0
        self.answers_received = self.choice_answers = 0
        self.identity_checked = self.identity_violations = 0
        self.diffuse_answers = 0
        self.suppressed = set()
        # Judge controls (revision-3 WP-14): requests that carried them, that
        # failed them (answers withheld) and that had no room for them.
        self.canaries = config.canaries == "on"
        self.control_stats = {"requests_checked": 0, "requests_failed": 0,
                              "requests_uncontrolled": 0}
        # Polarity-twin residuals |P(screen) + P(twin) - 1| (diagnostic only).
        self.twin_residuals = []
        # Injection markers annotate findings only (ADR-6(6)).
        self.injection_markers = injection_markers.scan_lines(source.lines)
        self.spec_injection_markers = (injection_markers.scan_lines(self.spec_source.lines)
                                       if self.spec_source is not None else [])
        self.search_memos = {}
        self._root_packets = None
        self.scoped = None
        if config.search_policy == "scoped-v2-beta":
            from .claim_search import ScopedClaims
            self.scoped = ScopedClaims(self)
        self.usage = {"input_tokens": 0, "output_tokens": 0,
                      "attempts_with_known_usage": 0, "attempts_with_unknown_usage": 0}
        if self.project is not None and self.project.limited and self.source.lines:
            self.issue("project_index_limited", Span(1, len(self.source.lines)),
                       "project-index")

    def issue(self, code, region, phase, affects=True):
        item = {"code": code, "range": [region.start, region.end],
                "phase": phase, "affects_completion": affects}
        # These generated key fields never change internally. Resolution may
        # change affects_completion, so compare the current records rather
        # than caching a fingerprint of the mutable dictionary. Scoped issues
        # have extra identity fields and cannot equal these simple records.
        candidates = self._issue_candidates.setdefault(
            (code, region.start, region.end, phase), [])
        if item not in candidates:
            self.issues.append(item)
            candidates.append(item)

    def stop_reason(self):
        reason = getattr(self.gw, "stop_reason", None)
        return reason if type(reason) is str else None

    def expired(self, region, phase):
        if self.stop_reason() is not None:
            # A blocked or breaker-stopped provider ends dispatch: one
            # whole-file limitation, no further calls, rows or usage. A spent
            # --max-cost budget names itself (ADR-9(4)).
            code = ("cost_budget_exhausted" if self.stop_reason() == "cost_budget_exhausted"
                    else "provider_stopped")
            self.issue(code, Span(1, max(1, len(self.source.lines))), "provider")
            return True
        if self.dispatch_refused is not None:
            self.issue(self.dispatch_refused, region, phase)
            return True
        if time.monotonic() < self.deadline_at:
            return False
        self.issue("run_deadline_exceeded", region, phase)
        return True

    def state_for(self, region, halo=0, extras=()):
        return state_for(self.source, region, halo, self.spec, extras,
                         context_scope=self.context_scope)

    def fitting_state(self, region, halo, probe, extras=()):
        return fitting_state(self.source, region, halo, self.spec, probe, extras,
                             context_scope=self.context_scope)

    def fitting_pair(self, target, ref, question):
        return fitting_pair_state(self.source, target, self.cfg.context_lines,
                                  self.spec, ref, question,
                                  context_scope=self.context_scope)

    def ask(self, state, questions, region, phase, *, origins=None):
        """Byte-bounded batches; dependent decisions require a later request."""
        # Every judge request carries the caller's declared scope (project-scope
        # fix); the judge sees the declaration, never an inference task.
        # Every request state is laid out by the one STATE_LAYOUT helper.
        state = _ordered_state({**state, "context_scope": self.context_scope})
        result = {}
        if self.expired(region, phase):
            if origins is not None:
                origins.extend(self.request_origins_for(state, questions))
            return result
        try:
            # Keep the packer's authoritative bytes. Re-encoding each batch
            # here, and again for scoped provenance, repeated the same work.
            # Large screens still receive atomic preflight, but repeated state
            # bytes cannot make retained wire storage grow without a bound.
            prepared, retained_bytes, overflow_state = [], 0, None
            wire_limit = min(MAX_PREPARED_WIRE_BYTES,
                             max(0, self.cfg.max_calls - self.calls)
                             * request_envelope().limits(True)[1])
            for batch, failed, wire in prepared_question_batches(
                    state, questions, controls=self.canaries):
                key = hashlib.sha256(wire).hexdigest() if wire is not None else None
                if wire is not None:
                    if retained_bytes + len(wire) <= wire_limit:
                        retained_bytes += len(wire)
                    else:
                        if overflow_state is None:
                            overflow_state = json.loads(wire)["state"]
                        wire = None
                prepared.append((batch, failed, wire, key))
        except ProviderError as exc:
            self.issue(exc.code, region, phase)
            if origins is not None:
                origins.extend(self.request_origins_for(state, questions))
            return result
        state_sha256 = None
        for batch, failed, wire, key in prepared:
            if self.expired(region, phase):
                break
            if failed is not None:
                self.issue("question_too_large", region, phase)
                continue
            ckey = (*self.route_key, key)
            if ckey in self.cache:
                # Never return cache-owned mutable dictionaries to a caller.
                cached, defects = self.cache[ckey]
                result.update(_copy_validated_answers(cached))
                self.cache_hits += 1
                self.events.append({"phase": "judgment_reuse", "request_sha256": key,
                                    "origin": self.request_origins[ckey]})
                # A defective answer is never asked again; its limitation is
                # issued again for this caller's region.
                self.issue_defects(defects, region, phase)
                continue
            if ckey in self.failed_requests:
                pin = self.failed_requests[ckey]
                if pin["permanent"] or ckey in self.reasked:
                    self.issue(pin["code"], region, phase)
                    self.events.append({"phase": "failed_request_not_retried",
                                        "request_sha256": key,
                                        "origin": self.request_origins[ckey]})
                    continue
                # A transient failure recurs while the provider still runs:
                # ask once more, then pin for the rest of the run.
                self.reasked.add(ckey)
                self.events.append({"phase": "failed_request_reasked", "request_sha256": key,
                                    "origin": self.request_origins[ckey]})
            error, permanent = None, False
            if self.calls >= self.cfg.max_calls:
                error = "call_budget_exhausted"
            elif self.questions + len(batch) > self.cfg.max_questions:
                error = "question_budget_exhausted"
            if error:
                self.issue(error, region, phase)
                continue
            if wire is None:
                wire = encode_request(overflow_state, batch)
            self.calls += 1
            self.questions += len(batch)
            row = {"sequence": self.calls, "phase": phase,
                   "range": [region.start, region.end], "request_sha256": key,
                   "state_sha256": None, "question_sha256": digest(batch),
                   "question_ids": list(batch), "question_count": len(batch),
                   "status": "failed", "answers": None, "error": None}
            try:
                sent = json.loads(wire)
                if state_sha256 is None:
                    # Fingerprint the owned wire snapshot, never a caller's
                    # mutable dictionaries after request preparation.
                    state_sha256 = digest(sent["state"])
                row["state_sha256"] = state_sha256
                answers = self.gw.evaluate(sent["state"], sent["questions"], metadata={
                    "sequence": self.calls, "phase": phase,
                    "window_id": region.id, "source_sha256": self.source.sha256})
                # A conforming Gateway validates types and values; the engine
                # re-checks the answers it kept. Only a ValidatedGateway may
                # report answer-scoped defects: custom gateways stay atomic.
                defects = self.gateway_defects(batch)
                kept = {qid: q for qid, q in batch.items() if qid not in defects}
                if kept:
                    answers = validate_answer_objects(answers, kept,
                                  getattr(self.gw, "rounding_places", DEFAULT_CHOICE_ROUNDING_PLACES))
                elif answers != {}:
                    raise ProviderError("response_schema")
                # Menu size controls maximum mass tolerance, not semantic
                # informativeness. Retain the actual numeric diagnostic only.
                places = getattr(self.gw, "rounding_places", DEFAULT_CHOICE_ROUNDING_PLACES)
                row["choice_mass_allowance"] = {
                    qid: str(Fraction(len(raw["probabilities"]), 2 * 10 ** places))
                    for qid, raw in answers.items()
                    if raw["type"] == "choice" and places is not None}
                if places is not None and self.option_cap() is not None:
                    # ADR-4(3) diagnostic, recorded under opt-in caps only.
                    diffuse = sorted(qid for qid, raw in answers.items()
                                     if raw["type"] == "choice"
                                     and choice_mass_diffuse(raw, places))
                    row["choice_mass_diffuse"] = diffuse
                    self.diffuse_answers += len(diffuse)
                own, answers, defects, passed = self.check_controls(
                    batch, answers, defects, row)
                if not passed:
                    # ADR-6(4): the judge visibly malfunctioned on this
                    # request. Withhold every answer it gave (no findings,
                    # no clean coverage) and never ask it again.
                    self.record_answers(own, answers, defects, region, phase)
                    error, permanent = "judge_control_failed", True
                    row["error"] = error
                    self.issue(error, region, phase)
                else:
                    self.cache[ckey] = (answers, defects)
                    result.update(_copy_validated_answers(answers))
                    # Passing controls were validated answers too.
                    self.validated_questions += len(answers) + len(batch) - len(own)
                    row.update(status="validated_partial" if defects else "validated",
                               answers=plain(answers))
                    if defects:
                        row["scoped"] = dict(defects)
                    self.record_answers(own, answers, defects, region, phase)
            except ProviderError as exc:
                # Only documented failure codes are recorded here; other
                # exceptions are real defects and must reach the CLI's
                # unexpected_error.
                error = exc.code
                if error in _DISPATCH_REFUSALS:
                    # Refused before any receipt or byte: not a call.
                    self.calls -= 1
                    self.questions -= len(batch)
                    self.dispatch_refused = error
                    self.issue(error, region, phase)
                    break
                permanent = _permanent(exc)
                row["error"] = error
                self.issue(error, region, phase)
                if error == "provider_moderated":
                    self.suppressed.add((region.start, region.end))
            stats = getattr(self.gw, "last_call_stats", None)
            usage = None
            if type(stats) is dict and stats.get("request_sha256") == key:
                if type(stats.get("model_returned")) is str:
                    self.models_returned.add(stats["model_returned"])
                if stats.get("answer_order_mismatch") is True:
                    self.answer_order_mismatch += 1
            # Retried requests report the usage summed over their attempts.
            known = None
            if type(stats) is dict and stats.get("request_sha256") == key:
                known = stats.get("logical_usage", stats.get("usage"))
            if known is not None:
                try:
                    usage = validate_usage(known)
                except ProviderError as exc:
                    row["usage_error"] = exc.code
                    self.issue(exc.code, region, phase + "-usage")
            row["usage"] = usage
            if usage is None:
                self.usage["attempts_with_unknown_usage"] += 1
            else:
                self.usage["attempts_with_known_usage"] += 1
                for name in ("input_tokens", "output_tokens"):
                    self.usage[name] += usage[name]
            self.trace.append(row)
            self.request_origins[ckey] = {"sequence": row["sequence"], "request_sha256": key,
                                          "question_ids": list(batch), "status": row["status"]}
            if error:
                self.failed_requests[ckey] = {"code": error, "permanent": permanent}
            if self.expired(region, phase):
                break
        if origins is not None:
            for batch, failed, _, key in prepared:
                if failed is not None:
                    origins.append({"request_sha256": None, "question_ids": [failed],
                                    "status": "preflight-failed", "sequence": None})
                elif (*self.route_key, key) in self.request_origins:
                    origins.append(deepcopy(self.request_origins[(*self.route_key, key)]))
                else:
                    origins.append({"request_sha256": key, "question_ids": list(batch),
                                    "status": "not-dispatched", "sequence": None})
        return result

    def check_controls(self, batch, answers, defects, row):
        """Split the judge controls off one fresh response (ADR-6).

        Returns (own batch, own answers, own defects, passed). A control
        that is missing, refused or outside its pre-registered threshold
        fails the request. A request without controls passes.
        """
        roles = ({qid: control_role(q) for qid, q in batch.items()
                  if CONTROL_NAME.fullmatch(qid)} if self.canaries else {})
        if not roles:
            if self.canaries:
                self.control_stats["requests_uncontrolled"] += 1
            return batch, answers, defects, True
        checked = {}
        for qid, role in roles.items():
            value = answers[qid]["noul"] if qid in answers else None
            checked[qid] = {"role": role, "noul": str(value) if value is not None else None,
                            "passed": control_passed(role, value)}
        row["controls"] = checked
        self.control_stats["requests_checked"] += 1
        passed = all(item["passed"] for item in checked.values())
        if not passed:
            self.control_stats["requests_failed"] += 1
        return ({qid: q for qid, q in batch.items() if qid not in roles},
                {qid: a for qid, a in answers.items() if qid not in roles},
                {qid: c for qid, c in defects.items() if qid not in roles}, passed)

    def twin_report(self):
        """Pairs and residuals of the polarity-twin diagnostic."""
        residuals = self.twin_residuals
        return {"pairs": len(residuals),
                "mean_residual": (str((sum(residuals) / len(residuals)).quantize(
                                      Decimal("0.000001"))) if residuals else None),
                "max_residual": str(max(residuals)) if residuals else None}

    def request_envelope(self):
        """Policy placement and caps for this scan (revision-3 WP-13).

        "instructions" is the b1 envelope. "state" moves the active layout's
        policy into state; requests that carry it use the gateway's declared
        caps for policy-in-state requests (OpenRouter 200 questions and
        48 KiB), and the b1 caps when the gateway declares none.
        """
        if self.cfg.policy_placement != "state":
            return RequestEnvelope()
        limits = getattr(self.gw, "request_limits", None)
        if not (type(limits) is tuple and len(limits) == 2
                and all(type(item) is int for item in limits)):
            limits = (MAX_QUESTIONS, MAX_REQUEST_BYTES)
        return RequestEnvelope(policy(self.pack), *limits)

    def geometry_report(self):
        """``request_geometry``, present only under "state" placement."""
        envelope = request_envelope()
        if envelope.policy is None:
            return {}
        questions, request_bytes, state_bytes = envelope.limits(True)
        return {"request_geometry": {"policy_placement": envelope.placement,
                                     "max_questions": questions,
                                     "max_request_bytes": request_bytes,
                                     "max_state_bytes": state_bytes,
                                     "max_evidence_state_bytes": MAX_STATE_BYTES}}

    def controls_report(self):
        """The report's ``controls`` record; absent when canaries are off."""
        if not self.canaries:
            return {}
        return {"controls": {"set": CONTROL_SET,
                             "must_true_min": str(CONTROL_MUST_TRUE_MIN),
                             "must_false_max": str(CONTROL_MUST_FALSE_MAX),
                             **self.control_stats}}

    def injection_report(self):
        """``injection_markers``, present only when the local scan found any."""
        if not self.injection_markers and not self.spec_injection_markers:
            return {}
        return {"injection_markers": {
            "file": injection_markers.report(self.injection_markers),
            "specification": (injection_markers.report(self.spec_injection_markers)
                              if self.spec_source is not None else None)}}

    def gateway_defects(self, batch):
        """The last call's answer-scoped defects, from a ValidatedGateway only."""
        if not isinstance(self.gw, ValidatedGateway):
            return {}
        defects = self.gw.last_defects
        if type(defects) is not dict or any(
                qid not in batch or code not in ANSWER_SCOPED_CODES
                for qid, code in defects.items()):
            raise ProviderError("response_schema")
        return defects

    def defect_span(self, qid, region):
        """The window a defective question judged, else the request region."""
        match = _WINDOW_QUESTION.fullmatch(qid)
        if match is not None:
            start, end = int(match.group(1)), int(match.group(2))
            if 1 <= start <= end <= len(self.source.lines):
                return Span(start, end)
        return region

    def issue_defects(self, defects, region, phase):
        """One limitation per defective answer (ADR-3(5))."""
        for qid, code in defects.items():
            span = self.defect_span(qid, region)
            self.issue(code, span, phase, affects=(_ROUTING_QUESTION.fullmatch(qid) is None
                                                   and _DIAGNOSTIC_QUESTION.fullmatch(qid) is None))
            if code == "question_refused":
                self.suppressed.add((span.start, span.end))

    def record_answers(self, batch, answers, defects, region, phase):
        """Count a fresh response's answers, defects and judge diagnostics."""
        self.answers_received += len(batch)
        for code in defects.values():
            self.answer_defects[code] = self.answer_defects.get(code, 0) + 1
        self.routing_defects += sum(_ROUTING_QUESTION.fullmatch(qid) is not None
                                    for qid in defects)
        self.choice_answers += sum(q["type"] == "choice" for q in batch.values())
        if getattr(self.gw, "confidence_identity", None) == "chance_normalized_p1":
            places = getattr(self.gw, "rounding_places", None)
            if places is None:
                places = getattr(self.gw, "display_places", None)
            for answer in answers.values():
                if answer["type"] == "choice":
                    self.identity_checked += 1
                    if confidence_identity_violation(answer, places):
                        self.identity_violations += 1
        self.issue_defects(defects, region, phase)

    def answer_quality(self):
        """Report fields for answer-level defects and judge diagnostics."""
        refused = self.answer_defects.get("question_refused", 0)
        mismatches = self.answer_defects.get("choice_argmax_mismatch", 0)
        banners = []
        if (self.choice_answers >= ARGMAX_BANNER_MIN_ANSWERS
                and Fraction(mismatches, self.choice_answers) > ARGMAX_BANNER_RATE):
            banners.append("judge_inconsistent")
        if self.identity_violations >= IDENTITY_BANNER_VIOLATIONS:
            banners.append("judge_semantics_changed")
        overlaps = any(lo <= span.end and span.start <= hi
                       for lo, hi in self.suppressed for span in self.support)
        return {
            "answer_defects": {"total": sum(self.answer_defects.values()),
                               "by_code": dict(sorted(self.answer_defects.items())),
                               "choice_routing": self.routing_defects},
            "refusals": {"refused": refused, "answers": self.answers_received,
                         "rate": (round(refused / self.answers_received, 6)
                                  if self.answers_received else None),
                         "interval_95": clopper_pearson(refused, self.answers_received),
                         "method": "clopper-pearson"},
            "possible_suppression": {
                "flagged": len(self.suppressed) >= 2 or overlaps,
                "windows": len(self.suppressed), "overlaps_support": overlaps},
            "judge_diagnostics": {
                "choice_answers": self.choice_answers, "argmax_mismatches": mismatches,
                "confidence_identity": getattr(self.gw, "confidence_identity", None),
                "confidence_identity_checked": self.identity_checked,
                "confidence_identity_violations": self.identity_violations,
                # Present only under opt-in rounding caps (ADR-4(3)).
                **({"choice_mass_diffuse": self.diffuse_answers}
                   if self.option_cap() is not None else {}),
                # Present only with Config.polarity_twin (ADR-6(6)).
                **({"polarity_twin": self.twin_report()}
                   if self.cfg.polarity_twin else {})},
            "banners": banners,
        }

    def option_cap(self):
        """The choice option cap of ADR-4(3), or None when no cap applies.

        Caps apply only with Config.choice_rounding_caps and a gateway
        rounding profile N; strict mass leaves every menu as before.
        """
        places = getattr(self.gw, "rounding_places", DEFAULT_CHOICE_ROUNDING_PLACES)
        if not self.cfg.choice_rounding_caps or type(places) is not int:
            return None
        return choice_option_cap(places)

    def gate_half_quantum(self, answer):
        """h for the mass gate: the rounding profile, else the declared display
        precision, else the places shown in *answer* (a lower bound on the
        true precision, so h is never understated)."""
        places = getattr(self.gw, "rounding_places", None)
        if type(places) is not int:
            places = getattr(self.gw, "display_places", None)
        if type(places) is not int:
            places = answer_places(answer)
        return half_quantum(places)

    def localization_menu(self, target):
        """(options, menu name) for one localization question.

        Under opt-in rounding caps an interval menu over the cap falls back
        to singletons (ADR-4(3)); that menu is named "singletons-capped".
        """
        if self.cfg.localization_menu == "intervals":
            intervals = contiguous_candidates(target)
            cap = self.option_cap()
            if cap is None or len(intervals) + 2 <= cap:
                return intervals, "intervals"
            return singleton_candidates(target), "singletons-capped"
        return singleton_candidates(target), "singletons"

    def mass_selection(self, where, candidates, limit):
        """Apply the mass gate to one localization answer: (spans, event fields)."""
        options = {s.id: s for s in candidates}
        runs, qualifying, hidden = mass_gate_runs(
            where, options, self.cfg.choice_mass, self.gate_half_quantum(where), limit)
        return runs, {"gate": "mass", "mass_selected": [s.id for s in runs],
                      "qualifying_runs": qualifying, "hidden_mass": _fraction_text(hidden)}

    def request_origins_for(self, state, questions):
        origins = []
        try:
            for batch, failed, wire in prepared_question_batches(
                    state, questions, controls=self.canaries):
                if failed:
                    origins.append({"request_sha256": None, "question_ids": [failed],
                                    "status": "preflight-failed", "sequence": None})
                    continue
                key = hashlib.sha256(wire).hexdigest()
                if (*self.route_key, key) in self.request_origins:
                    origins.append(deepcopy(self.request_origins[(*self.route_key, key)]))
                else:
                    origins.append({"request_sha256": key, "question_ids": list(batch),
                                    "status": "not-dispatched", "sequence": None})
        except ProviderError:
            origins.append({"request_sha256": None, "question_ids": list(questions),
                            "status": "preflight-failed", "sequence": None})
        return origins

    def add_support(self, span, score, origin, state, group_id, *, state_sha256=None):
        if score >= self.cfg.report_threshold:
            self.support.setdefault(span, []).append({
                "score": str(score), "origin": origin, "view_id": group_id,
                "state_sha256": digest(state) if state_sha256 is None else state_sha256})

    def view(self, region, targets, depths, state, phase):
        state = _ordered_state({**state, "context_scope": self.context_scope})
        remaining = self.cfg.max_windows - self.window_count
        if len(targets) > remaining:
            self.issue("window_budget_exhausted", region, phase)
            targets = targets[:remaining]
        if not targets:
            return None
        self.window_count += len(targets)
        group = {"id": f"V{len(self.groups) + 1}", "region": region,
                 "targets": targets, "depths": depths, "state": state,
                 "phase": phase, "scores": {}, "priority": [], "context_needed": None}
        self.groups.append(group)
        cap = self.option_cap()
        answers = self.ask(state, screening(self.pack, region, targets,
                                             bug_lenses=self.cfg.bug_lenses, state=state,
                                             max_page=(MAX_RANK_PAGE if cap is None
                                                       else min(MAX_RANK_PAGE, cap - 2)),
                                             reserve_bytes=(CONTROL_RESERVE_BYTES
                                                            if self.canaries else 0),
                                             polarity_twin=self.cfg.polarity_twin),
                           region, phase)
        context = [{"start_line": e["start_line"], "end_line": e["end_line"]}
                   for e in state["excerpts"]]
        # This state is fixed for the whole view; hashing it per target made
        # bookkeeping grow with source bytes times the number of intervals.
        state_sha256 = digest(state)
        for span in targets:
            judgments = {}
            answer = answers.get("screen_" + span.id)
            if answer is not None:
                judgments["screen"] = answer["noul"]
            if self.cfg.bug_lenses:
                for kind in LENS_KINDS:
                    answer = answers.get(f"{kind}_{span.id}")
                    if answer is not None:
                        judgments[kind] = answer["noul"]
            score = max(judgments.values()) if judgments else None
            mirror = answers.get("twin_" + span.id)
            if mirror is not None and "screen" in judgments:
                # Diagnostic only: never a judgment, score or support.
                self.twin_residuals.append(abs(judgments["screen"] + mirror["noul"] - 1))
            group["scores"][span] = score
            self.observations.append({
                "view_id": group["id"], "window_id": span.id,
                "start_line": span.start, "end_line": span.end,
                "depth": depths.get(span, 0), "phase": phase,
                "score": str(score) if score is not None else None,
                "judgments": {k: str(v) for k, v in judgments.items()},
                # Only the general screen reviews a window (ADR-3(6)); lens
                # answers alone still route drilling but leave it unreviewed.
                "status": "scored" if "screen" in judgments else "unreviewed",
                "context": context, "state_sha256": state_sha256})
            if score is not None:
                # Report support comes from the general screen only; lens
                # signals route investigation but never create support.
                general = judgments.get("screen")
                if general is not None:
                    self.add_support(span, general, "screen", state,
                                     group["id"], state_sha256=state_sha256)
                if score >= self.cfg.drill_threshold:
                    self.action_targets.add(span)
        if "need_context" in answers:
            group["context_needed"] = answers["need_context"]["noul"]
        for qid, answer in answers.items():
            # Gate: the weaker of stated confidence and
            # the chosen option's own displayed probability executes.
            if qid.startswith("rank_") and (self.scoped or min(
                    answer["confidence"],
                    answer["probabilities"][answer["choice"]],
            ) >= self.cfg.choice_confidence):
                selected = next((s for s in targets if s.id == answer["choice"]), None)
                if selected is not None:
                    group["priority"].extend(self.gated_candidates(
                        answer, targets, self.cfg.localization_beam_width))
        return group

    def gated_candidates(self, answer, candidates, limit):
        """Use the vector within one menu; every executed option keeps its gate."""
        if self.scoped:
            selected = select_exploration(answer, [s.id for s in candidates], limit)
            by_id = {s.id: s for s in candidates}
            return [by_id[key] for key in selected]
        if answer["choice"] not in {s.id for s in candidates}:
            return []
        eligible = [s for s in candidates if s.id in answer["probabilities"] and
                    min(answer["confidence"], answer["probabilities"][s.id])
                    >= self.cfg.choice_confidence]
        eligible.sort(key=lambda s: (-answer["probabilities"][s.id],
                                      s.id != answer["choice"], s.size, s.start))
        return eligible[:limit]

    def initial_scan(self):
        count = len(self.source.lines)
        if not count:
            return
        entire = Span(1, count)
        roots = self.root_packets()
        if self.cfg.whole_file and entire not in roots:
            state = self.fitting_state(entire, 0, noul(self.pack, "screen", entire))
            if state is None:
                self.issue("whole_file_not_submitted_size", entire, "whole", False)
            else:
                self.view(entire, [entire], {entire: -1}, state, "whole")
        pending, seen = deque(roots), set(roots)
        while pending:
            region = pending.popleft()
            if self.expired(region, "screen"):
                break
            if self.window_count >= self.cfg.max_windows:
                self.issue("window_budget_exhausted", region, "screen")
                # The union coverage below also exposes every unplanned tail line.
                break
            state = self.fitting_state(region, self.cfg.context_lines,
                                       noul(self.pack, "screen", region))
            if state is None:
                if region.size == 1:
                    self.issue("single_line_too_large", region, "screen")
                else:
                    self.issue("broad_view_split_for_size", region, "screen", False)
                    for part in windows(region, (region.size + 1) // 2):
                        if part not in seen:
                            seen.add(part)
                            pending.append(part)
                continue
            tree, capped = multiscale(
                region, self.cfg.min_width, self.cfg.max_depth,
                self.cfg.max_windows - self.window_count)
            if capped:
                self.issue("window_budget_exhausted", region, "screen")
            self.view(region, [s for s, _ in tree], dict(tree), state, "screen")

    def root_packets(self):
        """Immutable full-file geometry shared by screening and context pools."""
        key = (len(self.source.lines), self.cfg.width)
        if self._root_packets is None or self._root_packets[0] != key:
            packets = tuple(windows(Span(1, key[0]), key[1])) if key[0] else ()
            self._root_packets = key, packets
        return self._root_packets[1]

    def context_pool(self, group):
        region = group["region"]
        all_packets = self.root_packets()
        excerpts = group["state"]["excerpts"]
        pool = [p for p in all_packets if not any(
            e["start_line"] <= p.start and p.end <= e["end_line"] for e in excerpts)]
        cap = self.cfg.max_context_packets
        near = sorted(pool, key=lambda p: (min(abs(p.start - region.end),
                                                abs(p.end - region.start)), p.start))
        chosen = near[:cap // 2]
        slots = cap - len(chosen)
        for i in range(slots):
            if pool:
                candidate = pool[i * (len(pool) - 1) // max(1, slots - 1)]
                if candidate not in chosen:
                    chosen.append(candidate)
        for candidate in near:
            if len(chosen) >= cap:
                break
            if candidate not in chosen:
                chosen.append(candidate)
        return chosen, len(pool)

    def enrich(self, group):
        """One bounded retrieval round. Candidates are read, never hallucinated."""
        region = group["region"]
        pool, available = self.context_pool(group)
        relevant = []
        self.events.append({"phase": "context_pool", "view_id": group["id"],
                            "available_packets": available,
                            "examined_pool": [s.id for s in pool],
                            "pool_limited": len(pool) < available})
        # Fit several candidate packets into a shared state. The full text of
        # each option is visible. No candidate is represented only by a label.
        bins, current, current_state = [], [], None
        cap = self.option_cap()
        for packet in pool:
            if cap is not None and len(current) >= cap - 2:
                # ADR-4(3): the context picker offers its packets plus two
                # sentinels, so one bin holds at most cap - 2 packets.
                bins.append((current, current_state))
                current = []
            probe = noul(self.pack, "relevance", region, packet=target_text(packet))
            state = self.fitting_state(region, self.cfg.context_lines,
                                       probe, (*current, packet))
            if state is None and current:
                bins.append((current, current_state))
                current = []
                state = self.fitting_state(region, self.cfg.context_lines, probe, (packet,))
            if state is None:
                self.issue("context_packet_too_large", region, "context")
                continue
            current.append(packet)
            current_state = state
        if current:
            bins.append((current, current_state))
        for packets, state in bins:
            questions = {"relevance_" + p.id: noul(self.pack, "relevance", region,
                         packet=target_text(p)) for p in packets}
            picker = choice(self.pack, "context_pick", region, packets)
            picker["criteria"]["none"] = "No supplied packet provides needed context."
            picker["criteria"]["unlocalized"] = "The needed context is not identified."
            questions["context_where"] = picker
            answers = self.ask(state, questions, region, "context")
            pick = answers.get("context_where")
            preferred = (pick["choice"] if pick is not None and
                         min(pick["confidence"],
                             pick["probabilities"][pick["choice"]],
                             ) >= self.cfg.choice_confidence else None)
            for packet in packets:
                answer = answers.get("relevance_" + packet.id)
                if answer is not None and answer["noul"] >= self.cfg.context_threshold:
                    relevant.append((answer["noul"], packet, packet.id == preferred))
        # Independent Noul relevance orders packets across batches. Choice only
        # breaks equal-relevance ties; its menu-dependent probabilities are not
        # compared with probabilities from another menu.
        relevant.sort(key=lambda item: (-item[0], not item[2], item[1]))
        # A small fixed evidence capacity, not a semantic model replacing judge.
        selected = [p for _, p, _ in relevant[:2]]
        self.events.append({"phase": "context_selected", "view_id": group["id"],
                            "packets": [s.id for s in selected],
                            "additional_relevant_packets": max(0, len(relevant) - 2)})
        if not selected:
            self.issue("context_unresolved", region, "context")
            return
        state = self.fitting_state(region, self.cfg.context_lines,
                                   noul(self.pack, "screen", region), selected)
        if state is None:
            self.issue("selected_context_too_large", region, "context")
            return
        enriched = self.view(region, group["targets"], group["depths"], state, "enriched")
        if enriched is not None and (enriched["context_needed"] is None or
                enriched["context_needed"] >= self.cfg.context_threshold):
            self.issue("context_unresolved", region, "context")

    def verify(self, group, spans):
        if not spans:
            return
        if self.scoped:
            for span in spans:
                view = self.scoped_verification_view(group, span)
                row, _ = self.scoped.evaluate(span, view["state"], group_id=view["id"])
                view["state"] = self.scoped.states[row["id"]]
                self.scoped.eligible.add(row["claim_id"])
                value = row["roles"]["supports_failure"]
                self.rechecks.append({"target": [span.start, span.end],
                    "view_id": view["id"], "state_sha256": digest(view["state"]),
                    "score": value, "claim_id": row["claim_id"],
                    "evaluation_id": row["id"], "disposition": row["disposition"]})
                if value is not None and Decimal(value) >= self.cfg.drill_threshold:
                    self.action_targets.add(span)
            return
        questions = {"verify_" + span.id: noul(self.pack, "verify", span) for span in spans}
        answers = self.ask(group["state"], questions, group["region"], "verify")
        state_sha256 = digest(group["state"])
        for span in spans:
            answer = answers.get("verify_" + span.id)
            value = answer["noul"] if answer is not None else None
            self.verify_outcomes.setdefault(span, []).append(value)
            self.rechecks.append({"target": [span.start, span.end],
                                  "view_id": group["id"],
                                  "state_sha256": state_sha256,
                                  "score": str(value) if value is not None else None})
            if value is not None and value >= self.cfg.drill_threshold:
                self.action_targets.add(span)
            if value is not None and value >= self.cfg.report_threshold:
                self.verified[span] = group
                self.add_support(span, value, "direct_recheck", group["state"], group["id"],
                                 state_sha256=state_sha256)

    def scoped_verification_view(self, group, target):
        """Carry selected source passages into direct verification, without scores."""
        state = deepcopy(group["state"])
        records = {}
        for region, bucket in self.evidence_by_target.items():
            if region.start <= target.start and target.end <= region.end:
                for record in bucket.values():
                    records[record["ref"].id] = record
        records = sorted(records.values(), key=lambda r: (-r["score"], r["ref"].id))
        admitted = 0
        for record in records:
            ref = record["ref"]
            primary_visible = ref.source is self.source and any(
                p["start_line"] <= ref.span.start and ref.span.end <= p["end_line"]
                for p in state["excerpts"])
            external_visible = any(p["file"] == ref.label and p["source_sha256"] == ref.source.sha256
                and p["start_line"] <= ref.span.start and ref.span.end <= p["end_line"]
                for p in state.get("related_sources", []) + state.get("investigation_evidence", []))
            if primary_visible or external_visible:
                continue
            if admitted >= self.cfg.evidence_beam_width:
                self.issue("verification_evidence_limit", target, "verify")
                break
            state.setdefault("related_sources", []).append(excerpt(ref))
            try:
                encode_request(state, {"probe": noul(self.pack, "verify", target)})
            except ProviderError as exc:
                state["related_sources"].pop()
                self.issue(exc.code, target, "verify")
                continue
            admitted += 1
        state = _ordered_state(state)
        view = {**group, "id": f"SV{len(self.groups) + 1}", "state": state,
                "region": target, "targets": [target], "scores": {}, "priority": [],
                "phase": "claim-evidence"}
        self.groups.append(view)
        return view

    def localize(self, group, target):
        candidates, menu = self.localization_menu(target)
        # The mass gate replaces the legacy confidence gate; scoped-v2-beta
        # never used that gate and keeps its positive-mass exploration.
        mass = self.cfg.choice_gate == "mass" and not self.scoped
        examined = 0
        while examined < self.cfg.max_localizations:
            if self.expired(target, "localize"):
                return
            questions = {"exists": noul(self.pack, "screen", target),
                         "where": choice(self.pack, "localize", target, candidates)}
            answers = self.ask(group["state"], questions, target, "localize")
            if set(answers) != {"exists", "where"}:
                return
            where = answers["where"]
            event = {"phase": "localize", "target": target.id,
                     "view_id": group["id"], "choice": where["choice"],
                     "confidence": str(where["confidence"]),
                     "exists": str(answers["exists"]["noul"])}
            if menu != "intervals":
                event["menu"] = menu
            self.events.append(event)
            self.existence_checks.append({
                "target": [target.start, target.end], "view_id": group["id"],
                "score": str(answers["exists"]["noul"])})
            limit = min(self.cfg.localization_beam_width, self.cfg.max_localizations - examined)
            if mass:
                selected, fields = self.mass_selection(where, candidates, limit)
                event.update(fields)
            else:
                selected = self.gated_candidates(where, candidates, limit)
            if (answers["exists"]["noul"] < self.cfg.drill_threshold and
                    not (self.scoped and (where["choice"] == "unlocalized" or target in self.support))):
                if not (self.scoped and selected):
                    return
                # This target was already admitted for localization. A weak
                # broad existence answer cannot veto its bounded real-interval
                # beam; only independent verification may create support.
                event.update(routing_basis="positive-mass-interval-verification",
                             planned_verification_candidates=[s.id for s in selected])
            if (not self.scoped and not mass and min(where["confidence"],
                    where["probabilities"][where["choice"]]) < self.cfg.choice_confidence):
                return
            if not selected:  # Explicit none/unlocalized, not a clean verdict.
                if self.scoped:
                    # Preserve the parent and inspect a bounded deterministic
                    # subdivision. These are recovery candidates, not Choice picks.
                    recovery = [x for x in windows(target, max(1, (target.size + 1) // 2))
                                if x != target and (menu != "intervals" or x in candidates)]
                    recovery = recovery[:self.cfg.max_localizations - examined]
                    self.events.append({"phase": "localization_recovery", "target": target.id,
                        "sentinel": where["choice"], "candidates": [x.id for x in recovery],
                        "selection": "mechanical-subdivision-v1"})
                    if recovery:
                        self.verify(group, recovery)
                    self.issue("localization_unresolved", target, "localize")
                return
            first_recheck = len(self.rechecks)
            self.verify(group, selected)
            examined += len(selected)
            if self.scoped:
                # One fixed menu defines this optional beam. Removing selected
                # intervals does not remove their defects from the source, so
                # repeatedly asking existence against a shrinking menu is not
                # an independent search for another defect.
                planned = self.gated_candidates(where, candidates, self.cfg.localization_beam_width)
                # A planned recheck may never dispatch, or its triad may be
                # partial/invalid. Only this call's fully validated triads
                # count as verified, including exact compatible cache reuse.
                verified = [Span(*row["target"]).id for row in self.rechecks[first_recheck:]
                            if row["score"] is not None
                            and row["disposition"] != "unknown_evaluation"]
                self.events.append({"phase": "localization_policy_stop", "target": target.id,
                    "policy": "one-menu-ranked-positive-v1",
                    "planned_verification_candidates": [s.id for s in selected],
                    "verified_candidates": verified,
                    "positive_unselected": sum(where["probabilities"].get(s.id, 0) > 0
                                               for s in candidates if s not in selected)})
                if len(planned) > len(selected):
                    self.issue("localization_limit", target, "localize")
                return
            if mass:
                # One menu supplies every qualifying run (a run need not be
                # a menu option); shrinking the menu would re-count its lines.
                return
            for span in selected:
                candidates.remove(span)  # Exact options only; source unchanged.
        self.events.append({"phase": "localization_cap", "view_id": group["id"],
                            "target": target.id, "limit": self.cfg.max_localizations})
        if self.scoped:
            self.issue("localization_limit", target, "localize")

    def detailed_search(self):
        for group in list(self.groups):
            if self.expired(group["region"], "verify"):
                break
            scored = [s for s, score in group["scores"].items()
                      if score is not None and score >= self.cfg.drill_threshold]
            order = list(dict.fromkeys(group["priority"] + scored))
            # Every independently hot interval survives; Choice does not prune it.
            self.verify(group, order)
            for span in order:
                if span.size <= min(20, self.cfg.min_width) and self.cfg.max_localizations:
                    self.localize(group, span)


    @staticmethod
    def _spread(items, limit):
        if len(items) <= limit:
            return list(items)
        if limit == 1:
            return [items[0]]
        return [items[i * (len(items) - 1) // (limit - 1)]
                for i in range(limit)]

    def _same_file_evidence_roots(self, target):
        """Mechanical whole-file evidence candidates outside the target."""
        count = len(self.source.lines)
        width = max(self.cfg.evidence_min_width, self.cfg.width * 2)
        refs = []
        for lo, hi in ((1, target.start - 1), (target.end + 1, count)):
            if lo > hi:
                continue
            region = Span(lo, hi)
            for span in windows(region, min(width, region.size)):
                refs.append(EvidenceRef(self.source, self.source.name, span, "source"))
        return refs

    def _project_evidence_roots(self, target):
        if self.project is None:
            return []
        from .repository import ProjectEntry, ProjectIndex
        refs = []
        width = max(self.cfg.evidence_min_width, self.cfg.width * 2)
        entries = self.project.entries
        if (type(self.cfg) is Config and type(self.project) is ProjectIndex
                and type(entries) is tuple and all(
                    type(entry) is ProjectEntry and type(entry.relpath) is str
                    and type(entry.source) is Source and type(entry.source.lines) is tuple
                    and type(entry.source.sha256) is str for entry in entries)):
            # Count the exact global window sequence, then instantiate only
            # its spread-selected positions. No inventory cache: later calls
            # observe replaced entries and current line counts afresh.
            layout, total = [], 0
            for entry in entries:
                if not entry.source.lines:
                    continue
                entire = Span(1, len(entry.source.lines))
                local_width = min(width, entire.size)
                count = _window_count(entire, local_width)
                layout.append((entry, entire, local_width, count))
                total += count
            limit = self.cfg.max_project_candidates
            limited = total > limit
            if not limited:
                indices = range(total)
            elif limit == 1:
                indices = (0,)
            else:
                indices = (i * (total - 1) // (limit - 1) for i in range(limit))
            position = base = 0
            for index in indices:
                while index >= base + layout[position][3]:
                    base += layout[position][3]
                    position += 1
                entry, entire, local_width, _ = layout[position]
                span = _window_at(entire, local_width, index - base)
                refs.append(EvidenceRef(entry.source, entry.relpath, span, "project"))
        else:
            # Preserve the original behavior of custom/mutable library inputs.
            for entry in entries:
                if not entry.source.lines:
                    continue
                entire = Span(1, len(entry.source.lines))
                for span in windows(entire, min(width, entire.size)):
                    refs.append(EvidenceRef(entry.source, entry.relpath, span, "project"))
            total = len(refs)
            limited = total > self.cfg.max_project_candidates
            refs = self._spread(refs, self.cfg.max_project_candidates)
        if limited:
            self.issue("project_candidate_pool_limited", target, "evidence-project")
            self.events.append({"phase": "project_candidate_pool",
                                "available": total,
                                "examined": len(refs),
                                "limited": True})
        return refs

    def _evaluate_evidence(self, target, ref, phase):
        self.evidence_refs[ref.id] = ref
        label = evidence_label(ref)
        question = evidence_noul(self.pack, "relevance", target, label)
        state = self.fitting_pair(target, ref, question)
        if state is None:
            self.evidence_searches.append({"target": [target.start, target.end],
                "phase": phase, "candidate": ref.as_dict(), "score": None,
                "state_sha256": None, "status": "unsubmitted-payload-limit"})
            return None, None
        qid = "evidence_" + ref.id
        answer = self.ask(state, {qid: question}, target, phase).get(qid)
        score = answer["noul"] if answer is not None else None
        self.evidence_searches.append({
            "target": [target.start, target.end], "phase": phase,
            "candidate": ref.as_dict(),
            "score": str(score) if score is not None else None,
            "state_sha256": digest(state),
            "status": "assessed" if score is not None else "unknown"})
        return score, state

    def hierarchical_evidence_search(self, target, kind, group):
        if not self.scoped:
            return self._hierarchical_evidence_search(target, kind, group)
        key = identity({"scope": self.scoped.scope_id, "target": target.id, "kind": kind,
                        "configuration": self.cfg.as_dict(), "contract": CONTRACT_VERSION, "pack": self.pack_hash})
        if key in self.search_memos:
            records, incomplete = self.search_memos[key]
            self.events.append({"phase": "evidence_search_reuse", "search_id": key,
                                "target": target.id, "kind": kind, "incomplete": incomplete})
            return deepcopy(records)
        records = self._hierarchical_evidence_search(target, kind, group)
        incomplete = any(i["affects_completion"] and i["range"] == [target.start, target.end]
                         and i["phase"] == f"evidence-{kind}" for i in self.issues)
        self.search_memos[key] = deepcopy(records), incomplete
        return records

    def _hierarchical_evidence_search(self, target, kind, group):
        """judge-led broad-to-narrow evidence search over file or repository.

        Python supplies immutable passages and line coordinates. judge alone decides
        semantic relevance. Multiple branches survive through a bounded beam.
        """
        if kind == "source":
            current = self._same_file_evidence_roots(target)
        elif kind == "project":
            current = self._project_evidence_roots(target)
        else:
            raise ValueError("unknown_evidence_search_kind")
        if not current:
            return []
        found = {}
        examined = 0
        seen = set()
        for depth in range(self.cfg.evidence_max_depth + 1):
            if self.expired(target, f"evidence-{kind}"):
                break
            if not current:
                break
            unique = []
            for ref in current:
                key = (ref.label, ref.source.sha256, ref.span.start, ref.span.end, ref.kind)
                if key not in seen:
                    seen.add(key)
                    unique.append(ref)
            current = unique
            remaining = self.cfg.max_evidence_candidates - examined
            if remaining <= 0:
                self.issue("evidence_search_limited", target, f"evidence-{kind}")
                self.events.append({"phase": "evidence_search_limit",
                                    "target": target.id, "kind": kind})
                break
            if len(current) > remaining:
                current = self._spread(current, remaining)
                self.issue("evidence_search_limited", target, f"evidence-{kind}")
                self.events.append({"phase": "evidence_search_limit",
                                    "target": target.id, "kind": kind})
            scored = []
            oversize_children = []
            for ref in current:
                if self.expired(target, f"evidence-{kind}"):
                    break
                examined += 1
                score, state = self._evaluate_evidence(
                    target, ref, f"evidence-{kind}-d{depth}")
                if score is None:
                    if state is not None:
                        # A failed judgment is not a size failure or permission
                        # to retry it on several smaller versions of the input.
                        continue
                    # If a broad candidate cannot fit, smaller children can still fit.
                    if (ref.span.size > self.cfg.evidence_min_width
                            and depth < self.cfg.evidence_max_depth):
                        width = max(self.cfg.evidence_min_width,
                                    math.ceil(ref.span.size / 2))
                        for child in windows(ref.span, width):
                            oversize_children.append(EvidenceRef(
                                ref.source, ref.label, child, ref.kind))
                    else:
                        self.issue("evidence_payload_too_large", target,
                                   f"evidence-{kind}")
                    continue
                if score >= self.cfg.context_threshold:
                    record = {"ref": ref, "score": score, "state": state,
                              "depth": depth}
                    found[(ref.kind, ref.label, ref.source.sha256, ref.span.start, ref.span.end)] = record
                    scored.append(record)
            scored.sort(key=lambda r: (-r["score"], r["ref"].span.size,
                                       r["ref"].label, r["ref"].span.start))
            selected = scored[:self.cfg.evidence_beam_width]
            children = []
            for record in selected:
                ref = record["ref"]
                if (depth >= self.cfg.evidence_max_depth or
                        ref.span.size <= self.cfg.evidence_min_width):
                    continue
                width = max(self.cfg.evidence_min_width,
                            math.ceil(ref.span.size / 2))
                for child in windows(ref.span, width):
                    children.append(EvidenceRef(ref.source, ref.label, child, ref.kind))
            current = oversize_children + children
        records = list(found.values())
        records.sort(key=lambda r: (-r["depth"], -r["score"],
                                    r["ref"].span.size, r["ref"].label,
                                    r["ref"].span.start))
        bucket = self.evidence_by_target.setdefault(target, {})
        for record in records:
            ref = record["ref"]
            key = (ref.kind, ref.label, ref.source.sha256, ref.span.start, ref.span.end)
            previous = bucket.get(key)
            if previous is None or record["score"] > previous["score"]:
                bucket[key] = record
        self.events.append({"phase": "hierarchical_evidence_search",
                            "target": target.id, "kind": kind,
                            "examined": examined, "qualified": len(records),
                            "selected": [r["ref"].as_dict() for r in
                                         records[:self.cfg.evidence_beam_width]]})
        return records

    def _relationship_group(self, target, state, value, ref):
        group = {"id": f"XR{len(self.groups) + 1}", "region": target,
                 "targets": [target], "depths": {target: 0}, "state": state,
                 "phase": "relationship", "scores": {target: value},
                 "priority": [], "context_needed": None}
        self.groups.append(group)
        return group

    def _relationship_candidates(self, target):
        """Prefer semantically strong but spatially distinct evidence passages.

        Hierarchical search intentionally retains parents and descendants. Testing
        only the top-N raw scores can therefore spend every relationship call on
        nested versions of one passage. This deterministic selector first keeps
        non-overlapping passages within each source/file, then fills any remaining
        capacity from the original ranking. It does not judge semantic relevance.
        """
        if self.cfg.max_relationships <= 0:
            return []
        records = list(self.evidence_by_target.get(target, {}).values())
        records.sort(key=lambda r: (-r["score"], r["ref"].span.size,
                                    r["ref"].label, r["ref"].span.start))
        selected, deferred = [], []
        occupied = {}
        for record in records:
            ref = record["ref"]
            source_key = (ref.kind, ref.label, ref.source.sha256)
            spans = occupied.setdefault(source_key, [])
            if any(s.start <= ref.span.end and ref.span.start <= s.end for s in spans):
                deferred.append(record)
                continue
            if len(selected) >= self.cfg.max_relationships:
                return selected
            selected.append(record)
            spans.append(ref.span)
        for record in deferred:
            if len(selected) >= self.cfg.max_relationships:
                break
            selected.append(record)
        return selected

    def test_relationships(self, target):
        """Ask judge whether target/evidence relationships support a bug suspicion."""
        for record in self._relationship_candidates(target):
            if self.expired(target, "relationship"):
                break
            ref = record["ref"]
            self.evidence_refs[ref.id] = ref
            label = evidence_label(ref)
            relation_q = evidence_noul(self.pack, "relation", target, label)
            state = self.fitting_pair(target, ref, relation_q)
            if state is None:
                self.issue("relationship_payload_too_large", target, "relationship")
                continue
            qid = "relation_" + ref.id
            vqid = "verify_evidence_" + ref.id
            verify_q = evidence_noul(self.pack, "verify_with_evidence", target, label)
            if self.scoped:
                evaluation, answers = self.scoped.evaluate(target, state, ref=ref,
                    origin="relationship", extra_questions={qid: relation_q})
                relation = answers.get(qid)
                relation_value = relation["noul"] if relation is not None else None
                value = evaluation["roles"]["supports_failure"]
                if relation_value is not None and relation_value >= self.cfg.relation_threshold:
                    self.scoped.eligible.add(evaluation["claim_id"])
                    if value is not None and Decimal(value) >= self.cfg.drill_threshold:
                        self.action_targets.add(target)
                self.relationships.append({"target": [target.start, target.end],
                    "evidence": ref.as_dict(), "state_sha256": digest(state),
                    "relation_score": str(relation_value) if relation_value is not None else None,
                    "verify_score": value, "claim_id": evaluation["claim_id"],
                    "evaluation_id": evaluation["id"], "disposition": evaluation["disposition"]})
                continue
            # These propositions share fixed evidence; neither consumes the
            # other's answer. They are validated atomically when one batch fits.
            answers = self.ask(state, {qid: relation_q, vqid: verify_q}, target,
                               "relationship")
            relation = answers.get(qid)
            relation_value = relation["noul"] if relation is not None else None
            row = {"target": [target.start, target.end],
                   "evidence": ref.as_dict(),
                   "relation_score": (str(relation_value)
                                      if relation_value is not None else None),
                   "verify_score": None, "state_sha256": digest(state)}
            if (relation_value is not None and
                    relation_value >= self.cfg.relation_threshold):
                answer = answers.get(vqid)
                value = answer["noul"] if answer is not None else None
                row["verify_score"] = str(value) if value is not None else None
                # Relationship rechecks join the same-span history used by
                # direct rechecks; a failed check stays unknown, never a
                # negative.
                self.verify_outcomes.setdefault(target, []).append(value)
                self.rechecks.append({"target": [target.start, target.end],
                                      "view_id": "relationship:" + ref.id,
                                      "state_sha256": digest(state),
                                      "score": str(value) if value is not None else None,
                                      "evidence": ref.as_dict()})
                # Promotion is deferred (finalize_relationship_promotions):
                # order-independent, and only when no completed same-span
                # recheck contradicts the candidate.
                self.relationship_promotions.append((target, value, state, ref))
                # A newly supported relationship may ignite an initially cold
                # target. Route it now; report promotion still waits for every
                # same-span recheck and its contrary-evidence veto.
                if value is not None and value >= self.cfg.drill_threshold:
                    self.action_targets.add(target)
            self.relationships.append(row)

    def project_relationship_pass(self):
        """Project scope: related evidence may ignite a cold target.

        Cross-file defects are invisible in isolation (the smoke proved it:
        a contract mismatch screens cold until the sibling file is read).
        For maximal regions (warm or cold), one bounded project evidence
        search plus relationship testing runs before detailed_search; hot
        relation and verification create support through the normal
        promotion path. Cost is bounded by the existing evidence and
        relationship caps.
        """
        if (self.context_scope != "project" or self.project is None
                or not self.project.entries):
            return
        regions = {}
        for group in list(self.groups):
            if self.scoped and group["phase"] == "whole":
                continue
            region = group["region"]
            regions.setdefault((region.start, region.end), {
                "region": region, "group": group})
        for key, entry in regions.items():
            start, end = key
            if self.expired(entry["region"], "evidence-project"):
                break
            if not self.scoped and any(s <= start and end <= e and (e - s) > (end - start)
                   for s, e in regions):
                continue
            self.events.append({"phase": "project_relationship_pass",
                                "target": [start, end]})
            group = entry["group"]
            # Attach relationships to the region's hottest target so rows
            # key to the refined span; fall back to the region itself for
            # cold ignition. One span per maximal region bounds the cost.
            hot = [s for s, v in group.get("scores", {}).items()
                   if v is not None and v >= self.cfg.drill_threshold]
            span = (min(hot, key=lambda s: (-(group["scores"][s]), s.size))
                    if hot and not self.scoped else entry["region"])
            self.hierarchical_evidence_search(span, "project", group)
            self.test_relationships(span)

    def reassess_context_with_evidence(self):
        """Resolve a prior context limitation only with a fresh, validated Noul.

        Evidence can arrive after the same-file context phase. A relationship
        score does not itself establish that all missing context was supplied.
        Keep the original issue and an auditable resolution event; unrelated
        failures and contrary rechecks are never cleared here.
        """
        for issue in list(self.issues):
            if issue["code"] != "context_unresolved" or not issue["affects_completion"]:
                continue
            region = Span(*issue["range"])
            groups = [g for g in self.groups if g["region"] == region
                      and g["phase"] in {"whole", "screen", "enriched"}]
            if not groups:
                continue
            records = {}
            for target, bucket in self.evidence_by_target.items():
                if region.start <= target.start and target.end <= region.end:
                    for record in bucket.values():
                        ref = record["ref"]
                        if ref.id not in records or record["score"] > records[ref.id]["score"]:
                            records[ref.id] = record
            if not records:
                continue
            state = deepcopy(groups[-1]["state"])
            question = noul(self.pack, "need_context", region)
            state.setdefault("related_sources", [])
            supplied = []
            for record in sorted(records.values(), key=lambda r: (
                    -r["score"], r["ref"].span.size, r["ref"].id)):
                if len(supplied) >= self.cfg.evidence_beam_width:
                    break
                ref = record["ref"]
                if (ref.source is self.source and any(
                        e["start_line"] <= ref.span.start and ref.span.end <= e["end_line"]
                        for e in state["excerpts"])):
                    continue
                if any(e.get("id") == ref.id for e in state["related_sources"]):
                    continue
                state["related_sources"].append(excerpt(ref))
                try:
                    encode_request(state, {"need_context": question})
                except ProviderError as exc:
                    state["related_sources"].pop()
                    self.issue("context_packet_too_large" if exc.code == "request_too_large"
                               else exc.code, region, "context-reassessment")
                    continue
                supplied.append(ref.id)
            if not supplied:
                continue  # No new facts; do not ask for a different opinion.
            state = _ordered_state(state)
            state_hash = digest(state)
            identity = (region.id, state_hash)
            if identity in self.context_reassessed_states:
                continue  # Includes failed asks: no retry on unchanged input.
            self.context_reassessed_states.add(identity)
            answers = self.ask(state, {"need_context": question}, region, "context-reassessment")
            answer = answers.get("need_context")
            value = answer["noul"] if answer is not None else None
            resolved = value is not None and value < self.cfg.context_threshold
            self.events.append({"phase": "context_reassessed", "target": region.id,
                                "state_sha256": state_hash, "evidence_ids": supplied,
                                "score": str(value) if value is not None else None,
                                "resolved": resolved})
            if resolved:
                issue["affects_completion"] = False

    def requirement_action_search(self, target, group):
        """Optional judge-selected requirement search during the action loop."""
        if self.spec_source is None or not self.spec_source.lines:
            return []
        from .handoff import passages, capped
        pool = list(passages(
            self.spec_source.lines, Span(1, len(self.spec_source.lines))))
        candidates = capped(pool, self.cfg.max_handoff_candidates)
        limited = len(candidates) < len(pool)
        if limited:
            self.issue("reference_pool_limited", target, "action-requirement")
        selected = []
        answered = 0
        failed = limited
        questions = {}
        for candidate in candidates:
            # Untrusted spec text stays in structured state only; the
            # question references it by immutable coordinates.
            body = (f"SPEC:R{candidate.start}-R{candidate.end} (inclusive "
                    f"specification lines {candidate.start} through "
                    f"{candidate.end}) supplied in state")
            question = noul(self.pack, "requirement", target, passage=body)
            qid = f"action_requirement_R{candidate.start}-{candidate.end}"
            questions[qid] = question
        answers = self.ask(group["state"], questions, target, "action-requirement")
        for candidate in candidates:
            qid = f"action_requirement_R{candidate.start}-{candidate.end}"
            answer = answers.get(qid)
            if answer is None:
                failed = True
                continue
            answered += 1
            if answer["noul"] >= self.cfg.context_threshold:
                selected.append((answer["noul"], candidate))
        selected.sort(key=lambda x: (-x[0], x[1].size, x[1].start))
        self.action_requirement_evidence[target] = [s for _, s in selected]
        # Failed or unassessed asks must
        # not read as "no requirement". Counts are answered, not qualified.
        self.action_requirement_stats[target] = {
            "answered": answered, "assessed": answered, "attempted": len(candidates),
            "available": len(pool), "pool_limited": limited, "failed": failed}
        return selected

    def action_group(self, target):
        group = self.verified.get(target)
        if group is not None:
            return group
        for candidate in reversed(self.groups):
            if target in candidate.get("scores", {}):
                return candidate
        return None

    def action_options(self, target, performed):
        options = {
            "retain": "Retain the current suspicion at its present scope.",
            "finish": "Finish semantic investigation of this target for this run.",
        }
        if "search_file" not in performed and len(self.source.lines) > target.size:
            options["search_file"] = "Search elsewhere in this file for related evidence using hierarchical relevance checks."
        if ("test_relationship" not in performed and self.cfg.max_relationships
                and self.evidence_by_target.get(target)):
            options["test_relationship"] = "Test whether relationships between the target and selected evidence support a bug suspicion."
        if "search_requirement" not in performed and self.spec_source is not None:
            options["search_requirement"] = "Search supplied requirement passages for evidence relevant to this target."
        if "localize" not in performed and target.size <= 20 and self.cfg.max_localizations:
            options["localize"] = "Search exact smaller contiguous intervals inside this target."
        return options

    def investigation_group(self, target, base, performed, outcomes, options):
        """Supply new evidence and factual operations, never prior scores as proof."""
        state = deepcopy(base["state"])
        state["context_scope"] = self.context_scope
        state["investigation"] = {"completed_actions": sorted(performed),
            "outcomes": deepcopy(outcomes), "available_actions": list(options),
            "omitted_evidence_count": 0}
        records = list(self.evidence_by_target.get(target, {}).values())
        records.sort(key=lambda r: (-r["score"], r["ref"].span.size, r["ref"].id))
        state["investigation_evidence"] = []
        for record in records[:self.cfg.evidence_beam_width]:
            supplied = excerpt(record["ref"])
            state["investigation_evidence"].append(supplied)
            try:
                encode_request(state, {"probe": noul(self.pack, "continue_investigation", target)})
            except ProviderError as exc:
                if exc.code != "request_too_large":
                    raise
                state["investigation_evidence"].pop()
                state["investigation"]["omitted_evidence_count"] += 1
                self.issue("action_evidence_payload_limited", target, "action")
        state = _ordered_state(state)
        group = {**base, "id": f"A{len(self.groups) + 1}", "region": target,
                 "targets": [target], "state": state, "phase": "action"}
        self.groups.append(group)
        return group

    def decision_action_loop(self):
        """judge chooses bounded semantic investigation actions; Python executes them."""
        targets = sorted(self.action_targets, key=lambda s: (s.start, s.end))
        if not self.cfg.max_action_steps or not self.cfg.max_action_targets:
            self.events.append({"phase": "action_disabled", "available_targets": len(targets)})
            return
        if len(targets) > self.cfg.max_action_targets:
            self.events.append({"phase": "action_target_limit",
                                "available": len(targets),
                                "examined": self.cfg.max_action_targets})
            self.issue("action_target_limit",
                       Span(targets[0].start, targets[-1].end),
                       "action")
            targets = self._spread(targets, self.cfg.max_action_targets)
        for target in targets:
            if self.expired(target, "action"):
                break
            group = self.action_group(target)
            if group is None:
                continue
            # Project search is caller-declared scope, never a judge decision
            # (project-scope fix): judge cannot see the directory and must not
            # decide whether related files exist. One bounded search runs.
            if (self.context_scope == "project" and self.project is not None
                    and self.project.entries):
                self.hierarchical_evidence_search(target, "project", group)
            performed = set()
            outcomes = []
            terminal = "step-limit"
            for step in range(self.cfg.max_action_steps):
                options = self.action_options(target, performed)
                if set(options) == {"retain", "finish"}:
                    terminal = "available-actions-exhausted"
                    break
                action_group = self.investigation_group(target, group, performed, outcomes, options)
                continue_q = noul(self.pack, "continue_investigation", target)
                action_q = action_choice(self.pack, target, options)
                if self.scoped:
                    continue_q = {"type": "noul", "instructions": policy(self.pack) +
                        f" For {target_text(target)}, is at least one remaining nonterminal action "
                        "in investigation.available_actions expected to materially improve the supplied "
                        "evidence? Exclude retain and finish. Already completed work and a merely "
                        "possible additional bug do not by themselves warrant another step.",
                        "criteria": {"true": "A remaining nonterminal operation can materially improve evidence.",
                                     "false": "No remaining nonterminal operation is warranted by this evidence."}}
                    action_q["instructions"] = (policy(self.pack) + f" For {target_text(target)}, " +
                        "which listed action most usefully improves the supplied evidence? Choose " +
                        "retain or finish only when no remaining nonterminal action would materially improve it.")
                answers = self.ask(action_group["state"],
                                   {"continue": continue_q, "action": action_q},
                                   target, "action-select")
                if set(answers) != {"continue", "action"}:
                    terminal = "evaluation-failed"
                    break
                choice_answer = answers["action"]
                action = choice_answer["choice"]
                row = {"target": [target.start, target.end], "step": step + 1,
                       "continue": str(answers["continue"]["noul"]),
                       "action": action,
                       "confidence": str(choice_answer["confidence"]),
                       "executed": False, "outcome": None}
                self.action_trace.append(row)
                row["phase"] = "decision_action"
                self.events.append(row)
                if (answers["continue"]["noul"] < self.cfg.drill_threshold or
                        (not self.scoped and min(choice_answer["confidence"],
                            choice_answer["probabilities"][choice_answer["choice"]],
                            ) < self.cfg.choice_confidence)):
                    terminal = "judge-stopped" if answers["continue"]["noul"] < self.cfg.drill_threshold else "uncertain-choice"
                    break
                if action in ("retain", "finish"):
                    if self.scoped:
                        self.issue("action_continue_disagreement", target, "action")
                        terminal = "unresolved-sentinel"
                        break
                    row["executed"] = True
                    terminal = action
                    break
                performed.add(action)
                row["executed"] = True
                issue_count = len(self.issues)
                outcome = {"action": action, "status": "completed"}
                if action == "localize":
                    self.localize(action_group, target)
                elif action == "search_file":
                    records = self.hierarchical_evidence_search(target, "source", action_group)
                    outcome["evidence_candidates_found"] = len(records)
                elif action == "test_relationship":
                    previous = len(self.relationships)
                    self.test_relationships(target)
                    outcome["relationships_assessed"] = len(self.relationships) - previous
                elif action == "search_requirement":
                    self.requirement_action_search(target, action_group)
                    outcome["requirements_assessed"] = self.action_requirement_stats[target]["answered"]
                if any(i["affects_completion"] for i in self.issues[issue_count:]):
                    outcome["status"] = "incomplete"
                outcomes.append(outcome)
                row["outcome"] = outcome
            if terminal == "step-limit":
                remaining = set(self.action_options(target, performed)) - {"retain", "finish"}
                if remaining:
                    self.issue("action_step_limit", target, "action")
                else:
                    terminal = "available-actions-exhausted"
            self.events.append({"phase": "action_terminal", "target": target.id,
                                "reason": terminal, "completed_actions": sorted(performed)})

    def blocked(self, span):
        return any(item["affects_completion"] and
                   item["range"][0] <= span.end and span.start <= item["range"][1]
                   for item in self.issues)

    def reconcile(self):
        """Only judge may justify replacing a broad suspicion with smaller ones.

        This is a model-localization heuristic, never a proof of bug coverage.
        Disagreement, errors, or absent finer support retain the broader range.
        """
        selected = set(self.support)
        if self.scoped:
            # Provisional region propositions are not identical defect claims.
            # Do not erase a parent using an unrelated child's narrow location.
            return selected
        for parent in sorted(self.support, key=lambda s: (s.size, s.start)):
            if parent not in self.verified or self.blocked(parent):
                continue
            if any(v is None or v < self.cfg.report_threshold
                   for v in self.verify_outcomes.get(parent, [])):
                continue
            children = sorted(s for s in selected if s in self.verified
                              and parent.start <= s.start and s.end <= parent.end
                              and s != parent)
            if not children:
                continue
            if any(self.blocked(child) or any(
                    value is None or value < self.cfg.report_threshold
                    for value in self.verify_outcomes.get(child, [])) for child in children):
                continue
            if len(children) > 200:
                self.events.append({"phase": "reconcile_limit", "target": parent.id})
                continue
            group = self.verified[parent]
            question = noul(self.pack, "covered", parent,
                            candidates=", ".join(target_text(s) for s in children))
            # Very many intervals can exceed the application instruction limit.
            if len(question["instructions"].encode()) > 12000:
                self.issue("reconciliation_too_large", parent, "reconcile")
                continue
            answers = self.ask(group["state"], {"covered": question}, parent, "reconcile")
            if answers and answers["covered"]["noul"] >= self.cfg.report_threshold:
                selected.remove(parent)
                self.events.append({"phase": "reconciled", "target": parent.id,
                                    "represented_by": [s.id for s in children],
                                    "score": str(answers["covered"]["noul"])})
        return selected

    def finalize_relationship_promotions(self):
        """Order-independent relationship promotion (promotion invariant).

        A relationship candidate is promoted only when its own verification
        reaches the report threshold and no completed same-span recheck,
        direct or relationship, contradicts it. Failed rechecks remain
        unknown and never count as negatives.
        """
        if self.scoped:
            self.scoped.promote()
            return
        for target, value, state, ref in self.relationship_promotions:
            history = self.verify_outcomes.get(target, [])
            contrary = any(v is not None and v < self.cfg.report_threshold
                           for v in history)
            if (value is not None and value >= self.cfg.report_threshold
                    and not contrary):
                group = self._relationship_group(target, state, value, ref)
                self.verified[target] = group
                self.add_support(target, value, "relationship_recheck",
                                 state, group["id"])

    def run(self):
        # Every state and policy preamble of this scan uses the configured
        # layout (ADR-5(4)); the report's configuration records it, so the
        # question-pack hash plus the layout identify each request's bytes.
        # Policy placement and request caps (WP-13) are fixed for the scan
        # too; under "instructions" the envelope is the b1 one.
        with using_state_layout(self.cfg.state_layout):
            with using_request_envelope(self.request_envelope()):
                return self._run()

    def _run(self):
        ready = True
        if self.source.lines:
            probe = Span(1, 1)
            base = self.state_for(probe)
            base["excerpts"] = []
            try:
                encode_request(base, {"probe": noul(self.pack, "screen", probe)})
            except ProviderError as exc:
                self.issue(exc.code, Span(1, len(self.source.lines)), "preflight")
                ready = False
        if ready:
            self.initial_scan()
        # A bounded single context round; enriched views are not recursively
        # enriched. Whole-file views already contain all same-file context.
        for group in list(self.groups):
            if self.expired(group["region"], "context"):
                break
            need = group["context_needed"]
            if need is not None and need >= self.cfg.context_threshold:
                self.enrich(group)
        self.project_relationship_pass()
        self.reassess_context_with_evidence()
        self.detailed_search()
        self.decision_action_loop()
        self.reassess_context_with_evidence()
        self.finalize_relationship_promotions()
        selected = self.reconcile()
        assessed = [Span(o["start_line"], o["end_line"])
                    for o in self.observations if o["status"] == "scored"]
        coverage = _coverage(assessed, len(self.source.lines))
        complete = coverage["all_lines_assessed"] and not any(
            issue["affects_completion"] for issue in self.issues)
        scan_status = "complete" if complete else "incomplete"
        from .handoff import annotate_findings, compact_report
        annotations = annotate_findings(self, selected)
        complete = complete and not any(i["affects_completion"] for i in self.issues)
        findings = [{"window_id": s.id, "start_line": s.start, "end_line": s.end,
                     "resolution": ("directly_rechecked" if s in self.verified
                                    else "unresolved_initial_suspicion"),
                     "support": self.support[s],
                     "support_paths": sorted({row["origin"] for row in self.support[s]}),
                     **annotations[s]}
                    for s in sorted(selected)]
        # b1 report shape (WP-08): legacy 7, scoped 8; handoff 4 / 5.
        result = {"schema_version": 8 if self.scoped else 7, "tool_version": __version__, "contract": CONTRACT_VERSION,
                "provider": getattr(self.gw, "provider_id", "custom-unverified"),
                "model": getattr(self.gw, "model_id", None),
                "synthetic": getattr(self.gw, "synthetic", None),
                # Route provenance (ADR-1(6)): identifiers only, never ids of
                # individual generations, which stay in receipts.
                "provenance": {"route": self.route_key[0],
                               "model_requested": self.route_key[1],
                               "models_returned": sorted(self.models_returned),
                               "model_returned_changed": len(self.models_returned) > 1,
                               "answer_order_mismatch": self.answer_order_mismatch},
                "question_pack_sha256": self.pack_hash,
                "source": {"name": self.source.name,
                           "sha256": self.source.sha256,
                           "line_count": len(self.source.lines),
                           "encoding": self.source.encoding},
                "configuration": self.cfg.as_dict(),
                "choice_rounding_places": getattr(self.gw, "rounding_places", DEFAULT_CHOICE_ROUNDING_PLACES),
                "context_scope": self.context_scope,
                "specification_mode": "provided" if self.spec else "inferred",
                "specification_sha256": (hashlib.sha256(self.spec.encode()).hexdigest()
                                         if self.spec else None),
                "specification": ({"name": self.spec_source.name,
                    "sha256": self.spec_source.sha256,
                    "line_count": len(self.spec_source.lines),
                    "encoding": self.spec_source.encoding,
                    "hash_basis": ("original-bytes" if self.spec_source.path
                                   else "utf8-supplied-text")}
                    if self.spec_source else None),
                "scan_status": scan_status,
                "handoff_status": ("incomplete" if any(
                    a["handoff_incomplete"] for a in annotations.values()) else "complete"),
                "status": "complete" if complete else "incomplete",
                "calls_attempted": self.calls, "questions_attempted": self.questions,
                # Attempts and retries come from the gateway (ADR-2(10));
                # a custom gateway without them reports None.
                "attempts_transmitted": _count(getattr(self.gw, "attempts_transmitted", None)),
                "retries": _count(getattr(self.gw, "retries", None)),
                "stop_reason": self.stop_reason(),
                "stopped_at_sequence": (_count(getattr(self.gw, "stopped_at_sequence", None))
                                        if self.stop_reason() is not None else None),
                "usage": dict(self.usage),
                # Spend comes from the gateway's receipts (ADR-9(2)); a custom
                # gateway without accounting reports None.
                "spend": _spend(getattr(self.gw, "spend", None)),
                "questions_validated": self.validated_questions,
                **self.answer_quality(),
                **self.controls_report(),
                **self.injection_report(),
                **self.geometry_report(),
                "calibration": dict(CALIBRATION),
                "cache_hits": self.cache_hits, "windows_planned": self.window_count,
                "findings": findings, "coverage": coverage,
                "windows": self.observations, "requests": self.trace,
                "events": self.events, "issues": self.issues,
                "rechecks": self.rechecks, "existence_checks": self.existence_checks,
                "handoff_evidence": self.handoff_evidence,
                "evidence_searches": self.evidence_searches,
                "relationships": self.relationships,
                "decision_actions": self.action_trace,
                "secret_scan": (dict(self.secret_scan)
                                if self.secret_scan is not None else None),
                "project": ({"files_considered": self.project.files_considered,
                              "files_loaded": self.project.files_loaded,
                              "bytes_loaded": self.project.bytes_loaded,
                              "limited": self.project.limited,
                              "skipped_binary_or_invalid": self.project.skipped_binary_or_invalid,
                              "skipped_secret": self.project.skipped_secret,
                              "skipped_size": self.project.skipped_size,
                              "limited_file_count": self.project.limited_file_count,
                              "limited_total_bytes": self.project.limited_total_bytes,
                              "unreadable_files": self.project.unreadable_files,
                              "unreadable_directories": self.project.unreadable_directories,
                              "limited_line_count": self.project.limited_line_count,
                              "deadline_exceeded": self.project.deadline_exceeded,
                              "skipped_cache_dirs": self.project.skipped_cache_dirs,
                              "skipped_secret_content": self.project.skipped_secret_content}
                             if self.project is not None else None)}
        result["handoff"] = compact_report(result)
        if self.scoped:
            result["scoped_verification"] = self.scoped.report()
            result["policy_sha256"] = identity({"configuration": self.cfg.as_dict(),
                                               "contract": result["scoped_verification"]["contract_version"]})
            result["execution_status"] = "incomplete" if (not coverage["all_lines_assessed"] or
                any(i["affects_completion"] and not i["code"].startswith("claim_")
                    for i in self.issues)) else "complete"
            result["assessment_status"] = "unresolved" if any(
                i["affects_completion"] and (i["code"].startswith("claim_") or
                i["code"] == "context_unresolved") for i in self.issues) else "assessed"
        return result
