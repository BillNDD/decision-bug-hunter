"""Small local provider boundary. No endpoint or SDK assumptions live here."""
from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from decimal import (ROUND_CEILING, ROUND_HALF_EVEN, Context, Decimal, DivisionByZero,
                     InvalidOperation, Overflow)
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import sys
import tempfile
import threading
import time
from typing import Any, NamedTuple, Protocol, TextIO
import uuid

from .protocol import (ERROR_CODES, ProviderError, _metadata, encode_request,
                       plain, validate_answer_objects_scoped, validate_usage,
                       _rounding_profile)


@dataclass(frozen=True)
class ProviderIdentity:
    """Public provenance only; never put a credential or private path here."""

    name: str
    model: str | None = None
    synthetic: bool = False

    def __post_init__(self) -> None:
        if type(self.name) is not str or _NAME.fullmatch(self.name) is None:
            raise ProviderError("invalid_metadata")
        # Model ids may carry one vendor prefix, e.g. ``openai/gpt-6-luna-decisions``.
        if self.model is not None and (type(self.model) is not str
                                       or _MODEL.fullmatch(self.model) is None):
            raise ProviderError("invalid_metadata")
        if type(self.synthetic) is not bool:
            raise ProviderError("invalid_metadata")


_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_MODEL = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z")


@dataclass(frozen=True)
class ProviderRequest:
    """Owned immutable DBH JSON bytes and an effective cooperative timeout.

    Decode payload to obtain `state` and `questions`. This is a local envelope,
    not a service request. The adapter translates it into a documented API.
    """

    payload: bytes
    timeout_seconds: float


@dataclass(frozen=True)
class ProviderResponse:
    """Provider-normalized local answers. Unknown usage stays None.

    `error` carries a fixed failure code for a documented whole-batch
    rejection learned after usage; the gateway journals both.
    `cost_usd` is a provider-reported cost, when one was reported and valid.
    `scoped` maps a question name the adapter could not hand over to an
    answer-scoped defect code (``protocol.ADAPTER_SCOPED_CODES``: an explicit
    refusal or a choice without its vector); `answers` then holds exactly
    the other names (ADR-3).
    `provenance` holds receipt-only, charset-limited identifiers (see
    ``PROVENANCE_FIELDS``); anything else in it is dropped by the gateway.
    `order_mismatch` is 1 when answers arrived in a different order than
    the questions were asked (association is by name, so this is not fatal).
    """

    answers: dict[str, Any]
    usage: dict[str, int] | None = None
    complete: bool = True
    error: str | None = None
    cost_usd: Decimal | None = None
    scoped: Mapping[str, str] | None = None
    provenance: Mapping[str, Any] | None = None
    order_mismatch: int = 0


#: Submission classes of one attempt (ADR-2(2)). ``not_sent``: no complete
#: request left this process. ``rejected_unprocessed``: the service said it
#: did not process the request. ``terminal``: a deliberate refusal of this
#: request. ``possible``: the request may have been processed and billed.
SUBMISSION_CLASSES = frozenset({"not_sent", "possible", "rejected_unprocessed", "terminal"})


@dataclass(frozen=True)
class Classification:
    """What one failed attempt means for submission, retries and the run.

    ``scope`` is ``run`` for a failure that blocks the gateway and
    ``request`` otherwise. ``permanent`` failures repeat deterministically
    for the same request. ``retry_after`` is a validated Retry-After value
    in seconds, when the service sent one on a retryable status.
    ``stale_connection`` marks a reset or EOF with no response bytes on a
    reused keep-alive connection soon after the send (ADR-2(2)): the one
    failure a possible submission may be retried for, once and immediately.
    """

    code: str
    submission: str
    retry_after: float | None = None
    blocking: bool = False
    scope: str = "request"
    permanent: bool = False
    stale_connection: bool = False

    @property
    def submission_possible(self) -> bool:
        return self.submission not in {"not_sent", "rejected_unprocessed"}


# code -> (default submission class, blocks the run, permanent for this request)
_CLASSES: dict[str, tuple[str, bool, bool]] = {
    "connect_failed": ("not_sent", False, False),
    "transport_failed": ("possible", False, False),
    "deadline_exceeded": ("possible", False, False),
    "interrupted": ("possible", True, False),
    "internal_error": ("possible", True, False),
    "provider_error_in_body": ("possible", False, False),
    "http_redirect": ("terminal", True, False),
    "http_rejected": ("terminal", False, True),
    "http_unauthorized": ("terminal", True, False),
    "http_payment_required": ("terminal", True, False),
    "http_forbidden": ("terminal", True, False),
    "provider_moderated": ("terminal", False, True),
    "route_unavailable": ("terminal", True, False),
    "routing_no_endpoint": ("terminal", True, False),
    "http_request_timeout": ("not_sent", False, False),
    "request_too_large": ("terminal", False, True),
    "http_quota_exhausted": ("terminal", True, False),
    "http_rate_limited": ("rejected_unprocessed", False, False),
    "http_server_error": ("possible", False, False),
    "http_overloaded": ("rejected_unprocessed", False, False),
    "http_unavailable": ("rejected_unprocessed", False, False),
    "http_provider_timeout": ("possible", False, False),
    "response_refused": ("possible", False, True),
    "sensitive_input": ("not_sent", False, True),
    # Local refusals before any byte left this process.
    "run_deadline_exceeded": ("not_sent", False, False),
    "run_deadline_reserved": ("not_sent", False, False),
    "provider_stopped": ("not_sent", False, False),
    "cost_budget_exhausted": ("not_sent", False, False),
    "receipt_failed": ("not_sent", True, False),
}
#: Batch-level 200 defects: possible submission, deterministic for the request.
_RESPONSE_DEFECTS = frozenset({
    "response_too_large", "response_framing", "response_type", "response_invalid_json",
    "response_schema", "response_model", "response_truncated", "response_probability",
    "response_usage", "response_sensitive", "response_distribution",
    "choice_argmax_mismatch", "response_vector_missing"})
#: Failures worth another attempt, by the submission class they must carry
#: (ADR-2(2)). Everything else, including local refusals, is final.
RETRYABLE: dict[str, frozenset[str]] = {
    "not_sent": frozenset({"connect_failed", "http_request_timeout"}),
    "rejected_unprocessed": frozenset({"http_rate_limited", "http_overloaded",
                                       "http_unavailable"}),
    "possible": frozenset({"transport_failed", "deadline_exceeded", "http_server_error",
                           "http_provider_timeout", "provider_error_in_body"}),
}
#: Breaker categories (ADR-2(5)); each is judged on a logical request's final code.
RATE_LIMIT_CODES = frozenset({"http_rate_limited", "http_overloaded"})
DEGRADED_CODES = frozenset({"transport_failed", "deadline_exceeded", "http_server_error",
                            "http_provider_timeout", "http_unavailable",
                            "provider_error_in_body"})
NETWORK_CODES = RETRYABLE["not_sent"]
CONTRACT_CODES = frozenset({"response_schema", "response_model", "response_framing",
                            "response_type", "response_invalid_json", "response_truncated",
                            "http_rejected", "request_too_large"})
#: Consecutive logical requests that trip each streak reason.
BREAKER_LIMITS = {"rate_limit_sustained": 3, "provider_degraded": 3,
                  "network_unreachable": 3, "contract_mismatch": 2}
#: Moderation trips at this many moderated among the last ``MODERATION_WINDOW``.
MODERATION_LIMIT = 8
MODERATION_WINDOW = 10
#: Every stop reason the breaker can report, besides ``blocked:<code>``.
STOP_REASONS = frozenset({*BREAKER_LIMITS, "provider_moderation_sustained",
                          "cost_budget_exhausted"})


def classify(code: str, *, submission: str | None = None,
             retry_after: float | None = None) -> Classification:
    """The fixed classification of ``code``; ``submission`` overrides its class.

    Codes outside the table (local validation codes) default to a possible
    submission, the conservative reading when the provider was called.
    """
    default, blocking, permanent = _CLASSES.get(
        code, ("possible", False, code in _RESPONSE_DEFECTS))
    chosen = default if submission is None else submission
    if chosen not in SUBMISSION_CLASSES:
        raise ProviderError("internal_error")
    return Classification(code, chosen, retry_after, blocking,
                          "run" if blocking else "request", permanent)


@dataclass(frozen=True)
class RetryPolicy:
    """Retry budgets per submission class and the wait caps (ADR-2(3)).

    ``not_sent`` and ``rejected`` (rejected-unprocessed) failures are retried
    with full jitter, or after a validated Retry-After for rejected ones.
    ``possible`` submissions are not retried by default: a repeat may be
    billed twice. ``stale_connection`` is the single immediate retry, on a
    fresh connection, of a reused keep-alive socket the server had closed.
    """

    not_sent: int = 3
    rejected: int = 3
    possible: int = 0
    stale_connection: int = 1
    not_sent_cap: float = 8.0
    rejected_cap: float = 30.0
    retry_after_cap: float = 60.0

    def __post_init__(self) -> None:
        for count in (self.not_sent, self.rejected, self.possible, self.stale_connection):
            if type(count) is not int or not 0 <= count <= 10:
                raise ProviderError("invalid_request")
        for cap in (self.not_sent_cap, self.rejected_cap, self.retry_after_cap):
            if type(cap) not in (int, float) or not math.isfinite(cap) or not 0 <= cap <= 600:
                raise ProviderError("invalid_request")

    @classmethod
    def none(cls) -> RetryPolicy:
        """Exactly one attempt per logical request (``--no-retry``)."""
        return cls(not_sent=0, rejected=0, possible=0, stale_connection=0)

    def budget(self, kind: str) -> int:
        return {"not_sent": self.not_sent, "rejected": self.rejected,
                "possible": self.possible, "stale_connection": self.stale_connection}[kind]


def breaker_category(code: str | None, classification: Classification | None) -> str:
    """What one finished logical request means to the breaker.

    ``ok`` (validated) and ``other`` (a different failure that reached the
    service) end every streak; ``neutral`` (refused locally, never sent)
    changes nothing.
    """
    if code is None:
        return "ok"
    submission = classification.submission if classification is not None else "possible"
    if code == "provider_moderated":
        return "moderated"
    if code in RATE_LIMIT_CODES:
        return "rate_limit_sustained"
    if code in NETWORK_CODES and submission == "not_sent":
        return "network_unreachable"
    if submission == "not_sent":
        return "neutral"
    if code in CONTRACT_CODES:
        return "contract_mismatch"
    if code in DEGRADED_CODES:
        return "provider_degraded"
    return "other"


class Breaker:
    """Stops a run whose provider keeps failing the same way (ADR-2(5)).

    It sees one record per logical request, after that request's retries.
    Answer-scoped defects never reach it. The first stop reason sticks.
    """

    def __init__(self) -> None:
        self.streaks = dict.fromkeys(BREAKER_LIMITS, 0)
        self.moderation: deque[bool] = deque(maxlen=MODERATION_WINDOW)
        self.stop_reason: str | None = None

    def stop(self, reason: str) -> None:
        if self.stop_reason is None:
            self.stop_reason = reason

    def record(self, code: str | None, classification: Classification | None) -> str | None:
        """Account one finished logical request; returns the stop reason, if any."""
        if self.stop_reason is not None:
            return self.stop_reason
        if code is not None and classification is not None and classification.blocking:
            self.stop("blocked:" + code)
            return self.stop_reason
        category = breaker_category(code, classification)
        if category == "neutral":
            return None
        self.moderation.append(category == "moderated")
        for reason, limit in BREAKER_LIMITS.items():
            self.streaks[reason] = self.streaks[reason] + 1 if reason == category else 0
            if self.streaks[reason] >= limit:
                self.stop(reason)
        if sum(self.moderation) >= MODERATION_LIMIT:
            self.stop("provider_moderation_sustained")
        return self.stop_reason


def full_jitter(rng: random.Random, cap: float, base: float, retry: int) -> float:
    """``uniform(0, min(cap, base * 2**retry))`` for the ``retry``-th retry."""
    return rng.uniform(0.0, min(cap, base * 2.0 ** retry))


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_UPSTREAM = re.compile(r"[A-Za-z0-9 _.-]{1,64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
_PARAM = re.compile(r"[a-z_]{1,32}(?:\[[0-9]{1,3}\])?"
                    r"(?:\.[a-z_]{1,32}(?:\[[0-9]{1,3}\])?){0,3}\Z")
_ERROR_BODY_STATES = frozenset(
    {"unread", "absent", "ok", "oversized", "not_json", "withheld_sensitive"})


def _int_code(value: Any) -> bool:
    return type(value) is int and 100 <= value <= 599


def _token_or_int(value: Any) -> bool:
    return (type(value) is str and _TOKEN.fullmatch(value) is not None) or (
        type(value) is int and 0 <= value < 2**31)


def _matches(pattern: re.Pattern[str]) -> Any:
    return lambda value: type(value) is str and pattern.fullmatch(value) is not None


def _is_bool(value: Any) -> bool:
    return type(value) is bool


#: Receipt-only provenance fields and their validators (ADR-1(9)).
PROVENANCE_FIELDS: dict[str, Any] = {
    "model_returned": _matches(_MODEL),
    "upstream_provider": _matches(_UPSTREAM),
    "upstream_provider_unexpected": _is_bool,
    "generation_id": _matches(_ID),
    "request_id": _matches(_ID),
    "wire_sha256": _matches(_HEX64),
}
#: Receipt-only structural error fields (ADR-8); never messages or metadata text.
ERROR_FIELDS: dict[str, Any] = {
    "phase": lambda value: value in {"connect", "send", "receive"},
    "reused": _is_bool,
    "error_body": lambda value: value in _ERROR_BODY_STATES,
    "error_type": _matches(_TOKEN),
    "error_code": lambda value: _int_code(value) or _matches(_TOKEN)(value),
    "param": _matches(_PARAM),
    "param_withheld": _is_bool,
    "moderation": _is_bool,
    "routing_metadata": _is_bool,
    "provider_error_type": _token_or_int,
    "provider_code": _token_or_int,
    "provider_name": _matches(_UPSTREAM),
    "retry_after_seconds": lambda value: (type(value) in (int, float)
                                          and math.isfinite(value) and 0 <= value <= 60),
    "cost_error": lambda value: value == "invalid",
}


def _safe(check: Any, value: Any) -> bool:
    try:
        check(value)
    except ProviderError:
        return False
    return True


def _record_details(receipt: dict[str, Any], details: Any, check: Any) -> None:
    """Copy only validated, credential-free provenance and error fields."""
    if not isinstance(details, Mapping):
        return
    errors: dict[str, Any] = {}
    for name, value in details.items():
        if name in PROVENANCE_FIELDS:
            if PROVENANCE_FIELDS[name](value) and _safe(check, value):
                receipt[name] = value
        elif name in ERROR_FIELDS and ERROR_FIELDS[name](value) and _safe(check, value):
            errors[name] = value
    if errors:
        receipt["provider_error"] = {**(receipt.get("provider_error") or {}), **errors}


def _adapter_scoped(value: Any) -> dict[str, str]:
    """An adapter's answer-scoped defects as a plain dict; contents are checked later."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ProviderError("response_schema")
    return dict(value)


class DecisionProvider(Protocol):
    identity: ProviderIdentity

    def require_available(self) -> None: ...
    def decide(self, request: ProviderRequest) -> ProviderResponse: ...
    def check_sensitive(self, *values: Any) -> None: ...
    def close(self) -> None: ...


#: Upper bound on one hosted call's own deadline, in seconds.
MAX_CALL_DEADLINE_SECONDS = 300


def validate_call_deadline(deadline_seconds: Any) -> float:
    """The per-call deadline as a float, or ``invalid_deadline``.

    The CLI calls this before it creates any output directory, so an invalid
    value never leaves an empty run directory behind.
    """
    if (type(deadline_seconds) not in (int, float) or
            not math.isfinite(deadline_seconds) or
            not 0 < deadline_seconds <= MAX_CALL_DEADLINE_SECONDS):
        raise ProviderError("invalid_deadline")
    return float(deadline_seconds)


#: ``--provider`` selector -> route name.
ROUTES = {"openai": "openai-decisions", "openrouter": "openrouter-decisions"}


def make_provider(route: str, *, model: str | None = None, api_key: str | None = None,
                  environ: Mapping[str, str] | None = None, routing: str | None = None,
                  zdr: bool = False, exchange: Any = None,
                  policy_placement: str = "instructions",
                  max_connections: int = 1) -> DecisionProvider:
    """Library entry point: the hosted adapter for ``route``.

    ``route`` is a selector (``openai``, ``openrouter``) or a route name.
    ``model`` must be on the route's allow-list (default: its one model),
    otherwise ``invalid_request``; an unknown route is ``invalid_provider``.
    ``routing`` (``deny`` by default, or ``account-default``) and ``zdr``
    apply to OpenRouter only. ``policy_placement`` (``instructions`` or
    ``state``) sets the caps a policy-in-state request may use: OpenRouter
    raises them to 200 questions and 48 KiB, OpenAI direct keeps 64 and
    24 KiB. ``max_connections`` (1 to 8) is how many exchanges the provider
    may use at once, for a gateway built with ``max_in_flight`` above 1.
    Nothing is read from disk or the network.
    """
    name = ROUTES.get(route, route) if type(route) is str else None
    if name == "openai-decisions":
        if routing is not None or zdr:
            raise ProviderError("invalid_request")
        from .decisions import DecisionsProvider
        return DecisionsProvider(api_key, environ=environ, exchange=exchange, model=model,
                                 policy_placement=policy_placement,
                                 max_connections=max_connections)
    if name == "openrouter-decisions":
        from .openrouter import OpenRouterProvider
        return OpenRouterProvider(api_key, environ=environ, exchange=exchange, model=model,
                                  routing="deny" if routing is None else routing, zdr=zdr,
                                  policy_placement=policy_placement,
                                  max_connections=max_connections)
    raise ProviderError("invalid_provider")


#: Where an attempt's counted cost came from (ADR-9(1)).
COST_SOURCES = frozenset({"provider_reported", "list_price_estimate", "none"})
#: A reported cost must be a finite Decimal in [0, this) USD.
MAX_REPORTED_COST_USD = Decimal(10)
#: Largest accepted ``--max-cost``, in USD.
MAX_COST_LIMIT_USD = Decimal(1000)
#: Tokens allowed per question on top of the wire bytes for the input bound,
#: and as the output bound, of an attempt whose usage is unknown (ADR-9(3)).
QUESTION_TOKEN_ALLOWANCE = 64
_MILLION = Decimal(1_000_000)
_MICRO = Decimal("0.000001")
#: Cost arithmetic never depends on the caller's thread-local decimal context.
_COST = Context(prec=34, rounding=ROUND_HALF_EVEN,
                traps=[InvalidOperation, Overflow, DivisionByZero])


def usd(value: Decimal) -> str:
    """A USD amount as a plain decimal string (never exponent notation)."""
    return format(value, "f")


def validate_max_cost(value: Any) -> Decimal | None:
    """``--max-cost`` as a Decimal in (0, 1000] USD, None when unset.

    Anything else, including floats, is ``invalid_request``.
    """
    if value is None:
        return None
    if type(value) is int:
        value = Decimal(value)
    if (type(value) is not Decimal or not value.is_finite()
            or not 0 < value <= MAX_COST_LIMIT_USD):
        raise ProviderError("invalid_request")
    return value


#: A counted cost has at most this many decimal places and significant
#: digits, so sums stay exact in the 34-digit cost context and every amount
#: fits the report's decimal-string format.
MAX_REPORTED_COST_PLACES = 20
MAX_REPORTED_COST_DIGITS = 28


def reported_cost(value: Any) -> Decimal | None:
    """A provider-reported cost that may be counted, else None (ADR-9(1)).

    Negative zero counts as zero; an amount finer than
    ``MAX_REPORTED_COST_PLACES`` or longer than ``MAX_REPORTED_COST_DIGITS``
    is treated as invalid (unknown), never rounded.
    """
    if type(value) is not Decimal or not value.is_finite():
        return None
    if not 0 <= value < MAX_REPORTED_COST_USD:
        return None
    sign, digits, exponent = value.as_tuple()
    if (type(exponent) is not int or exponent < -MAX_REPORTED_COST_PLACES
            or len(digits) > MAX_REPORTED_COST_DIGITS):
        return None
    return value.copy_abs() if sign else value


def list_price(tokens_in: int, tokens_out: int, price_in: Decimal,
               price_out: Decimal) -> Decimal:
    """Tokens at USD-per-million list prices, exact in Decimal."""
    total = _COST.add(_COST.multiply(Decimal(tokens_in), price_in),
                      _COST.multiply(Decimal(tokens_out), price_out))
    return _COST.divide(total, _MILLION)


def attempt_cost_bound(wire_bytes: int, questions: int, price_in: Decimal,
                       price_out: Decimal) -> Decimal:
    """Upper bound on one possibly billed attempt whose usage is unknown.

    Input tokens <= wire bytes + 64 per question; output tokens <= 64 per
    question, priced at the model's output upper price (ADR-9(3)).
    """
    allowance = QUESTION_TOKEN_ALLOWANCE * questions
    return list_price(wire_bytes + allowance, allowance, price_in, price_out)


def _sync_directory(directory: Path) -> None:
    """fsync a directory so a completed rename survives a crash (POSIX only).

    Windows has no directory handle to fsync; there ``os.replace`` is the
    whole transition and this is a no-op.
    """
    if os.name != "posix":
        return
    handle = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _decimal_str(value: object) -> str:
    """JSON default for receipts: exact Decimal strings, as ``plain`` writes them."""
    if isinstance(value, Decimal):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _receipt_bytes(receipt: dict[str, Any]) -> bytes:
    """Receipt wire bytes; equal to ``_json(plain(receipt))`` for every receipt."""
    return json.dumps(receipt, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False, default=_decimal_str).encode("utf-8")


def _durable_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` through a fsynced temporary file and a rename."""
    temp: Path | None = None
    error = False
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temp = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        temp = None
    except Exception:
        error = True
    finally:
        # Control-flow interruption must also release the temporary file.
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                error = True
    if error:
        raise ProviderError("receipt_failed")


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Durable atomic journal transition; no request or raw response bodies.

    The file is fsynced before the rename. The directory is not: the gateway
    syncs it after each dispatching write and once at ``close()`` (ADR-9,
    F23), so a crash right after a settlement can at worst leave the
    dispatching receipt, which records a possible submission.
    """
    try:
        data = _receipt_bytes(receipt)
    except Exception:
        # Serialization fails before any file exists: nothing to clean up.
        raise ProviderError("receipt_failed") from None
    _durable_write(path, data)


#: Dispatch refusals that never become an attempt (the engine does not count
#: them as calls either).
_UNCOUNTED_REFUSALS = frozenset({"run_deadline_reserved", "cost_budget_exhausted"})

#: Leaves that ``_tree_copy`` shares: no operation changes them in place.
_IMMUTABLE_LEAVES: tuple[type, ...] = (str, int, float, bool, type(None), Decimal)
#: The receipt fields the engine's per-question bookkeeping reads.
_CALL_SUMMARY_FIELDS = ("request_sha256", "model_returned", "answer_order_mismatch",
                        "logical_usage", "usage")


def _tree_copy(value: Any) -> Any:
    """A copy of plain dict, list and tuple trees, without ``deepcopy``.

    Immutable leaves are shared. Any other type falls back to ``deepcopy``
    for its own subtree, so nothing new is ever aliased.
    """
    kind = type(value)
    if kind is dict:
        return {key: _tree_copy(item) for key, item in value.items()}
    if kind is list:
        return [_tree_copy(item) for item in value]
    if kind is tuple:
        return tuple(_tree_copy(item) for item in value)
    if kind in _IMMUTABLE_LEAVES:
        return value
    return deepcopy(value)


#: Most requests one gateway may have in flight (``max_in_flight``).
MAX_IN_FLIGHT = 8
#: Seconds a waiting thread sleeps between looks for an interrupt. A wake-up
#: by the event it waits on is immediate; only an interrupt waits out the
#: slice (a lock wait cannot be interrupted on Windows).
_WAIT_SLICE = 0.1
_ZERO = Decimal(0)


class CallResult(NamedTuple):
    """What a settled call hands back.

    ``answers`` is what ``_evaluate_prepared`` returns. ``summary`` holds the
    receipt fields the engine reads (``_CALL_SUMMARY_FIELDS``), ``defects``
    the answer-scoped defects by question name and ``receipts`` every attempt
    receipt path of the call, in order.
    """

    answers: dict[str, Any]
    summary: dict[str, Any]
    defects: dict[str, str]
    receipts: tuple[str, ...]


class CallHandle:
    """One submitted request: the state of its call and, once settled, its outcome.

    The gateway keeps a call's bookkeeping here (the receipt it wrote last, its
    receipt paths, its defects, the cost it holds in reserve), never in a
    field another call could overwrite, so calls in flight do not interfere.
    ``result()`` waits for the call and returns a ``CallResult``, or raises
    the ``ProviderError`` the call ended with. ``summary``, ``receipts`` and
    ``defects`` describe the call whether it succeeded or failed; a call
    refused before any receipt has none. The serial ``evaluate`` path uses a
    handle of its own for the same bookkeeping and never shows it.
    """

    __slots__ = ("_gateway", "_done", "_answers", "_error", "_stats", "_receipt",
                 "_receipts", "_defects", "_sequence", "_attempts", "_reserved",
                 "_honored", "_shared", "_place")

    def __init__(self, gateway: ValidatedGateway, *, shared: bool = False) -> None:
        self._gateway = gateway
        self._done = threading.Event()
        self._answers: dict[str, Any] | None = None
        self._error: BaseException | None = None
        self._stats: dict[str, Any] | None = None
        self._receipt: str | None = None
        self._receipts: tuple[str, ...] = ()
        self._defects: dict[str, str] = {}
        self._sequence: int | None = None
        #: Attempts this call began.
        self._attempts = 0
        #: Cost bound this call holds in the gateway's reservation.
        self._reserved = _ZERO
        #: The latest backoff-gate time this call has waited out or set itself.
        self._honored = -math.inf
        #: Whether other calls may run beside this one (``max_in_flight`` above 1).
        self._shared = shared
        #: Whether this call holds one of the gateway's in-flight places.
        self._place = False

    @property
    def summary(self) -> dict[str, Any] | None:
        """The receipt fields the engine reads, copied; None without a receipt.

        A key appears only when the receipt has it.
        """
        stats = self._stats
        if stats is None:
            return None
        return {name: _tree_copy(stats[name]) for name in _CALL_SUMMARY_FIELDS
                if name in stats}

    @property
    def receipts(self) -> tuple[str, ...]:
        """Every attempt receipt path of this call so far, in order."""
        return self._receipts

    @property
    def defects(self) -> dict[str, str]:
        """The answer-scoped defects of the call, by question name (a copy)."""
        return dict(self._defects)

    @property
    def sequence(self) -> int | None:
        """The call's sequence number, once it began."""
        return self._sequence

    def done(self) -> bool:
        """Whether the call has settled (its outcome is ready)."""
        return self._done.is_set()

    def result(self) -> CallResult:
        """Wait for the call; its answers and summary, or its error raised.

        An interrupt while waiting blocks the gateway with ``interrupted`` and
        stops new submissions; calls in flight still run to settlement.
        """
        done = self._done
        if not done.is_set():
            try:
                while not done.wait(_WAIT_SLICE):
                    pass
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    self._gateway._block("interrupted")
                raise
        if self._error is not None:
            raise self._error
        assert self._answers is not None
        return CallResult(self._answers, self.summary or {}, dict(self._defects),
                          self._receipts)

    def _finish(self, answers: dict[str, Any] | None = None,
                error: BaseException | None = None) -> None:
        self._answers, self._error = answers, error
        self._done.set()


class _Local(threading.local):
    """The call a thread is running (set by the serial path or by a worker)."""

    call: CallHandle | None = None


class ValidatedGateway:
    """Serial evaluation with exact validation, retries and local receipts.

    One logical request (one ``evaluate``) may take several attempts; each
    attempt has its own receipt (schema 2) carrying ``logical_id`` and
    ``attempt``, and the final one adds ``logical_status`` and the summed
    known usage. Retries follow ``retry_policy`` (ADR-2(3)): not-sent and
    rejected-unprocessed failures with full jitter or Retry-After, possible
    submissions never (except the one stale keep-alive retry). A wait that
    would cut into the run's reserve is abandoned.

    A dispatching receipt records possible submission; a call refused before
    the provider is reached records ``submission_possible: false``. Both
    receipts of an attempt carry the same ``deadline_seconds``, fixed before
    dispatch. A blocking failure, failed persistence or an interruption stops
    the gateway: later calls raise the original blocking code without a
    connection. The ``Breaker`` stops it after sustained failures; then
    ``stop_reason`` is set and later calls raise ``provider_stopped``.
    Undocumented adapter exceptions become ``internal_error``.

    Answer-scoped defects (ADR-3) cost their answers only: such an attempt
    is ``validated_partial`` with ``scoped: {name: code}`` in its receipt,
    ``evaluate`` returns the other answers and ``last_defects`` the defects.
    They never trigger a retry and never reach the breaker.

    ``clock`` (monotonic seconds), ``sleep`` and ``rng`` are injectable so
    tests never wait on the wall clock. ``progress`` is an optional text
    stream for the count-only progress line (ADR-9(5)).

    Cost (ADR-9): every attempt receipt carries ``cost_usd``, ``cost_source``
    (``provider_reported``, ``list_price_estimate`` or ``none``) and
    ``cost_bound_usd``, the amount it adds to the unknown-usage upper bound.
    ``spend`` sums them exactly in Decimal. With ``max_cost`` set, an attempt
    (first or retry) whose bound would take spent plus bounded cost above it
    is not dispatched: the gateway stops with ``cost_budget_exhausted``.
    Estimates and bounds need the provider's ``model_spec`` prices; without
    them they are None and ``max_cost`` is refused.

    Concurrency (``max_in_flight``, 1 to ``MAX_IN_FLIGHT``, default 1): the
    package-private ``_submit_prepared`` returns a ``CallHandle`` and, above
    1, runs up to ``max_in_flight`` requests at once, each on its own
    non-daemon worker thread. At 1 it runs the request in the calling thread,
    as ``_evaluate_prepared`` does. ``evaluate``, ``_evaluate_prepared`` and
    the ``last_*`` properties stay single-call and owned by one thread; a
    second concurrent ``evaluate`` is refused with ``transport_failed``.
    ``_state_lock`` guards every field the calls share: the counters, the
    cost totals and the reservations, the breaker and the block and stop
    state, the dispatch-write count, the backoff gate, the retry generator,
    the attempt history and the progress line. A request holds its attempt's
    cost bound in reserve from before the dispatching receipt until
    settlement, so ``max_cost`` counts calls in flight. A rate-limit wait
    (``rejected`` retries) closes a shared gate: no call starts a new
    attempt before it opens. A blocking failure, a stop (the breaker, the
    budget, a deadline) or an interrupt refuses every call that has not yet
    begun. A request that has begun runs to settlement, so a stop does not end
    its retries: only a blocking failure, a close or an interrupt abandons a
    retry that is waiting to be sent. Attempts already sent run to
    settlement. A call that has written its dispatching receipt looks at the
    gate and at these once more just before the send: it waits for a gate that
    closed meanwhile (its attempt deadline starts at the send). A first
    attempt is then refused by anything that refuses a new call, a retry by a
    blocking failure or a close, and the refused attempt settles as not sent.
    ``close`` waits for the workers up to the attempt deadline.
    """

    #: The p95 multiplier over recent attempts for the run reserve (ADR-2(7)).
    RESERVE_P95_FACTOR = 1.5
    RESERVE_HISTORY = 50
    #: Progress line cadence: every this many logical calls or seconds.
    PROGRESS_EVERY_CALLS = 100
    PROGRESS_EVERY_SECONDS = 30.0

    def __init__(self, provider: DecisionProvider, receipt_dir: Path | str, *,
                 deadline_seconds: float = 30.0,
                 rounding_places: int | None = None,
                 retry_policy: RetryPolicy | None = None,
                 clock: Callable[[], float] | None = None,
                 sleep: Callable[[float], None] | None = None,
                 rng: random.Random | None = None,
                 progress: TextIO | None = None,
                 reserve_floor_seconds: float = 3.0,
                 max_cost: Decimal | None = None,
                 max_in_flight: int = 1) -> None:
        deadline = validate_call_deadline(deadline_seconds)
        _rounding_profile(rounding_places)
        if type(provider.identity) is not ProviderIdentity:
            raise ProviderError("invalid_metadata")
        policy = RetryPolicy() if retry_policy is None else retry_policy
        if type(policy) is not RetryPolicy:
            raise ProviderError("invalid_request")
        if (type(reserve_floor_seconds) not in (int, float)
                or not math.isfinite(reserve_floor_seconds)
                or not 0 <= reserve_floor_seconds <= MAX_CALL_DEADLINE_SECONDS):
            raise ProviderError("invalid_deadline")
        if type(max_in_flight) is not int or not 1 <= max_in_flight <= MAX_IN_FLIGHT:
            raise ProviderError("invalid_request")
        self.max_cost = validate_max_cost(max_cost)
        spec = getattr(provider, "model_spec", None)
        price_in = getattr(spec, "price_in_per_mtok", None)
        price_out = getattr(spec, "price_out_upper_per_mtok", None)
        self._prices: tuple[Decimal, Decimal] | None = None
        if (isinstance(price_in, Decimal) and isinstance(price_out, Decimal)
                and price_in.is_finite() and price_out.is_finite()
                and price_in >= 0 and price_out >= 0):
            self._prices = (price_in, price_out)
        date = getattr(spec, "price_table_date", None)
        self.price_table_date = (date if self._prices is not None and type(date) is str
                                 and _TOKEN.fullmatch(date) else None)
        if self.max_cost is not None and self._prices is None:
            # A budget that cannot bound unknown usage would be a false promise.
            raise ProviderError("invalid_request")
        self.provider = provider
        self.provider_id = provider.identity.name
        self.model_id = provider.identity.model
        self.synthetic = provider.identity.synthetic
        self.receipt_dir = Path(receipt_dir)
        self._receipt_dir_ready = False
        self.deadline_seconds = deadline
        self.rounding_places = rounding_places
        self.retry_policy = policy
        self.reserve_floor_seconds = float(reserve_floor_seconds)
        self._clock = clock
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()
        self._progress = progress
        self._deadline: float | None = None
        #: The call the thread-owned ``last_*`` properties describe.
        self._last: CallHandle | None = None
        self._stats_owner: int | None = None
        self._busy = False
        self._block_code: str | None = None
        self._closed = False
        self._call_lock = threading.Lock()
        self.max_in_flight = max_in_flight
        # Without a semaphore (the default) no call runs beside another and
        # the call lock above is the only exclusion, as before.
        self._slots = (threading.BoundedSemaphore(max_in_flight)
                       if max_in_flight > 1 else None)
        self._state_lock = threading.RLock()
        self._local = _Local()
        self._workers: set[threading.Thread] = set()
        self._closing = False
        #: Set when the gateway blocks or closes, so a waiting worker wakes.
        self._wake = threading.Event()
        self._reserved = _ZERO
        self._gate_until = -math.inf
        self.breaker = Breaker()
        self.stopped_at_sequence: int | None = None
        self.logical_requests = 0
        self.attempts = 0
        self.attempts_transmitted = 0
        self.retries = 0
        self._sequence = 0
        self._elapsed: deque[float] = deque(maxlen=self.RESERVE_HISTORY)
        self._started = self._now()
        self._progress_calls = 0
        self._progress_at = self._started
        self._reported = Decimal(0)
        self._estimated = Decimal(0)
        self._unknown_bound = Decimal(0)
        self._cost_counts = dict.fromkeys(("provider_reported", "list_price_estimate",
                                           "unknown_bounded", "not_billable"), 0)
        self._dispatch_writes = 0

    # -- state -------------------------------------------------------------
    def _now(self) -> float:
        # Looked up at call time, so a patched ``time.monotonic`` applies.
        return self._clock() if self._clock is not None else time.monotonic()

    def _pause(self, seconds: float) -> None:
        if self._sleep is not None:
            self._sleep(seconds)
        elif self._slots is not None:
            # Ends early once the gateway blocks or closes. Short slices keep
            # an interrupt of the main thread from waiting out the whole pause
            # (a timed wait cannot be interrupted on Windows).
            end = time.monotonic() + seconds
            while True:
                left = end - time.monotonic()
                if left <= 0 or self._wake.wait(min(left, _WAIT_SLICE)):
                    return
        else:
            time.sleep(seconds)

    @property
    def stop_reason(self) -> str | None:
        """``blocked:<code>`` or a breaker reason once the gateway stopped."""
        return self.breaker.stop_reason

    @property
    def _blocked(self) -> bool:
        return self._block_code is not None

    def _block(self, code: str, call: CallHandle | None = None) -> None:
        with self._state_lock:
            if self._block_code is None:
                self._block_code = code
            self._stop("blocked:" + self._block_code, call)
        self._wake.set()

    def _stop(self, reason: str, call: CallHandle | None = None) -> None:
        """Latch the first stop reason; ``stopped_at_sequence`` is that of ``call``."""
        with self._state_lock:
            if self.breaker.stop_reason is None:
                self.breaker.stop(reason)
            if self.stopped_at_sequence is None:
                sequence = None if call is None else call._sequence
                self.stopped_at_sequence = self._sequence if sequence is None else sequence

    def _refusal(self) -> str | None:
        """The code a call that has not begun is refused with, else None.

        A blocking failure, a stop (the breaker, the budget, a deadline) or a
        closing gateway refuses it before any receipt. Call with the state
        lock held.
        """
        if self._block_code is not None:
            return self._block_code
        if self.breaker.stop_reason is not None:
            return "provider_stopped"
        if self._closed or self._closing:
            return "transport_failed"
        return None

    def stop(self, reason: str) -> None:
        """Stop further dispatch for ``reason`` (one of ``STOP_REASONS``)."""
        if reason not in STOP_REASONS:
            raise ProviderError("invalid_request")
        self._stop(reason)

    def reserve_seconds(self) -> float:
        """max(floor, 1.5 x p95 of the last 50 transmitted attempts' durations).

        The floor is ``reserve_floor_seconds`` (3 s by default).
        """
        with self._state_lock:
            if not self._elapsed:
                return self.reserve_floor_seconds
            ordered = sorted(self._elapsed)
        p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
        return max(self.reserve_floor_seconds, self.RESERVE_P95_FACTOR * p95)

    @property
    def spend(self) -> dict[str, Any]:
        """Spend so far as Decimal strings, reconciling exactly with receipts.

        ``provider_reported_usd`` sums reported costs; ``estimated_usd`` known
        usage at list price; ``unknown_usage_upper_bound_usd`` the bounds of
        possibly billed attempts without usage. Estimates and bounds are None
        without a price table.
        """
        priced = self._prices is not None
        with self._state_lock:
            return {
                "provider_reported_usd": usd(self._reported),
                "estimated_usd": usd(self._estimated) if priced else None,
                "unknown_usage_upper_bound_usd": usd(self._unknown_bound) if priced else None,
                "upper_bound_usd": usd(self._spent_upper()) if priced else None,
                "price_table_date": self.price_table_date,
                "max_cost_usd": usd(self.max_cost) if self.max_cost is not None else None,
                "attempts": dict(self._cost_counts),
            }

    def _spent_upper(self) -> Decimal:
        return _COST.add(_COST.add(self._reported, self._estimated), self._unknown_bound)

    def _over_budget(self, bound: Decimal | None) -> bool:
        """Whether one more attempt could take spend above ``max_cost``.

        The attempts in flight count: each holds its bound in ``_reserved``
        until it settles. Call with the state lock held.
        """
        if self.max_cost is None or bound is None:
            return False
        return _COST.add(_COST.add(self._spent_upper(), self._reserved),
                         bound) > self.max_cost

    def _reserve(self, call: CallHandle, bound: Decimal) -> None:
        """Hold ``bound`` for ``call``'s next attempt. Call with the state lock held."""
        self._reserved = _COST.add(self._reserved, bound)
        call._reserved = _COST.add(call._reserved, bound)

    def _release(self, call: CallHandle) -> None:
        """Give back what ``call`` holds. Call with the state lock held."""
        self._reserved = _COST.subtract(self._reserved, call._reserved)
        call._reserved = _ZERO

    def _wire_bytes(self, wire: bytes) -> int:
        """The adapter's wire size for this envelope, else the envelope size."""
        sizer = getattr(self.provider, "wire_size", None)
        if callable(sizer):
            try:
                size = sizer(wire)
            except Exception:
                size = None
            if type(size) is int and size >= 0:
                return max(size, len(wire))
        return len(wire)

    def _attempt_bound(self, wire: bytes, questions: int) -> Decimal | None:
        if self._prices is None:
            return None
        return attempt_cost_bound(self._wire_bytes(wire), questions, *self._prices)

    def _zero_bound(self) -> str | None:
        return usd(Decimal(0)) if self._prices is not None else None

    def _settle_cost(self, call: CallHandle, receipt: dict[str, Any],
                     bound: Decimal | None) -> None:
        """Fix an attempt's cost fields and add them to ``spend`` (once per attempt).

        A reported cost wins; otherwise known usage is priced at list price;
        otherwise a possibly billed attempt adds its bound. A cost flagged
        invalid counts as unknown, never as zero. Not-sent, rejected and
        terminal attempts add nothing. The attempt's reservation ends in the
        same step, so no other call sees its cost counted twice or not at all.
        """
        error = receipt.get("provider_error")
        invalid = isinstance(error, dict) and error.get("cost_error") == "invalid"
        usage = receipt.get("usage")
        estimate: Decimal | None = None
        if self._prices is not None and isinstance(usage, dict):
            estimate = list_price(usage["input_tokens"], usage["output_tokens"],
                                  *self._prices)
        with self._state_lock:
            if call._reserved:
                self._release(call)
            if receipt.get("cost_source") == "provider_reported":
                self._reported = _COST.add(self._reported, Decimal(receipt["cost_usd"]))
                self._cost_counts["provider_reported"] += 1
                receipt["cost_bound_usd"] = self._zero_bound()
                return
            receipt.update(cost_usd=None, cost_source="none")
            if estimate is not None and not invalid:
                receipt.update(cost_usd=usd(estimate), cost_source="list_price_estimate",
                               cost_bound_usd=self._zero_bound())
                self._estimated = _COST.add(self._estimated, estimate)
                self._cost_counts["list_price_estimate"] += 1
            elif receipt.get("submission") == "possible" and bound is not None:
                chosen = bound if estimate is None else max(bound, estimate)
                receipt["cost_bound_usd"] = usd(chosen)
                self._unknown_bound = _COST.add(self._unknown_bound, chosen)
                self._cost_counts["unknown_bounded"] += 1
            else:
                receipt["cost_bound_usd"] = self._zero_bound()
                self._cost_counts["not_billable"] += 1

    @property
    def last_call_stats(self) -> dict[str, Any] | None:
        call = self._last
        if self._stats_owner != threading.get_ident() or call is None:
            return None
        return _tree_copy(call._stats)

    @property
    def last_call_summary(self) -> dict[str, Any] | None:
        """The receipt fields the engine reads, copied; None without a call.

        A key appears only when the receipt has it, so ``get`` fallbacks see
        what they see in ``last_call_stats``.
        """
        call = self._last
        if self._stats_owner != threading.get_ident() or call is None:
            return None
        return call.summary

    @property
    def last_receipt(self) -> str | None:
        call = self._last
        if self._stats_owner != threading.get_ident() or call is None:
            return None
        return call._receipt

    @property
    def last_receipts(self) -> tuple[str, ...]:
        """Every attempt receipt of the last logical request, in order."""
        call = self._last
        if self._stats_owner != threading.get_ident() or call is None:
            return ()
        return call._receipts

    @property
    def last_defects(self) -> dict[str, str]:
        """The answer-scoped defects of the last logical request, by name."""
        call = self._last
        if self._stats_owner != threading.get_ident() or call is None:
            return {}
        return dict(call._defects)

    @property
    def confidence_identity(self) -> str | None:
        """The model's documented confidence identity, when one is known."""
        spec = getattr(self.provider, "model_spec", None)
        value = getattr(spec, "confidence_identity", None)
        return value if type(value) is str else None

    @property
    def display_places(self) -> int | None:
        """The model's declared display precision in decimal places, if known."""
        spec = getattr(self.provider, "model_spec", None)
        value = getattr(spec, "display_places", None)
        return value if type(value) is int and 0 <= value <= 8 else None

    @property
    def request_limits(self) -> tuple[int, int] | None:
        """The provider's (max questions, max envelope bytes) for a request
        whose policy sits in state, when it declares them (ADR-5(5))."""
        value = getattr(self.provider, "request_limits", None)
        if (type(value) is tuple and len(value) == 2
                and all(type(item) is int and item > 0 for item in value)):
            return value
        return None

    def require_available(self) -> None:
        if self._closed or self._busy:
            raise ProviderError("transport_failed")
        if self._block_code is not None:
            raise ProviderError(self._block_code)
        if self.breaker.stop_reason is not None:
            raise ProviderError("provider_stopped")
        self.provider.require_available()

    def set_run_deadline(self, deadline: float) -> None:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ProviderError("invalid_deadline")
        self._deadline = float(deadline)

    def check_sensitive(self, *values: Any) -> None:
        self.provider.check_sensitive(*values)

    def __enter__(self) -> ValidatedGateway:
        self.require_available()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, *_args: Any) -> None:
        self.close()

    def close(self) -> None:
        if not self._call_lock.acquire(blocking=False):
            raise ProviderError("transport_failed")
        try:
            if not self._closed:
                pending = sys.exc_info()[1]
                if (self._workers and pending is not None
                        and not isinstance(pending, Exception)):
                    # An interrupt unwinding past calls in flight (through a
                    # ``with`` block or a ``finally``) blocks the gateway
                    # first, so no further call begins and the join below
                    # waits for the calls in flight.
                    self._block("interrupted")
                error = self._join_workers() if self._workers else None
                if self._dispatch_writes:
                    # The one directory sync that makes every settlement
                    # rename durable (settlements skip it; ADR-9, F23).
                    try:
                        _sync_directory(self.receipt_dir)
                    except Exception:
                        error = "receipt_failed"
                try:
                    self.provider.close()
                except ProviderError as exc:
                    error = error or exc.code
                except Exception:
                    error = error or "transport_failed"
                if error:
                    self._block(error)
                    raise ProviderError(error)
                self._closed = True
        finally:
            self._call_lock.release()

    def evaluate(self, state: dict[str, Any], questions: dict[str, Any], *,
                 metadata: dict[str, Any]) -> dict[str, Any]:
        return self._locked(lambda: self._evaluate(state, questions, metadata=metadata))

    def _evaluate_prepared(self, wire: bytes, key: str, *,
                           metadata: dict[str, Any]) -> dict[str, Any]:
        """``evaluate`` for a wire the engine's packer already validated (A2).

        The packer checked every question, the count, the request limit and the
        state limit, so the wire is not encoded again. ``key`` must be
        ``sha256(wire)``: the engine computed it and it is not re-hashed here.
        """
        return self._locked(lambda: self._evaluate_wire(wire, key, metadata=metadata))

    def _submit_prepared(self, wire: bytes, key: str, *,
                         metadata: dict[str, Any]) -> CallHandle:
        """Start ``_evaluate_prepared``'s request and return its handle.

        At ``max_in_flight`` 1 the request runs here, in the calling thread,
        before this returns: the handle is settled and its receipts are those
        ``_evaluate_prepared`` writes. Above 1 it runs on a worker thread, and
        this waits for a free place when ``max_in_flight`` requests are in
        flight. Either way a request that fails, or is refused because the
        gateway stopped, is reported by the handle (``result()`` raises) and
        never by this call; a refused request writes no receipt. An interrupt
        propagates, after it blocked the gateway with ``interrupted``.
        """
        if self._slots is None:
            call = CallHandle(self)
            try:
                answers = self._locked(
                    lambda: self._evaluate_wire(wire, key, metadata=metadata), call)
            except Exception as exc:
                call._finish(error=exc)
            else:
                call._finish(answers)
            return call
        return self._submit_shared(wire, key, metadata)

    def _admission(self) -> str | None:
        """The code a new submission is refused with now, else None."""
        with self._state_lock:
            code = self._refusal()
        if code is None:
            try:
                self.provider.require_available()
            except ProviderError as exc:
                code = exc.code
        return code

    def _submit_shared(self, wire: bytes, key: str,
                       metadata: dict[str, Any]) -> CallHandle:
        call = CallHandle(self, shared=True)
        slots = self._slots
        assert slots is not None
        worker: threading.Thread | None = None
        try:
            while True:
                code = self._admission()
                if code is not None:
                    call._finish(error=ProviderError(code))
                    return call
                if slots.acquire(timeout=_WAIT_SLICE):
                    call._place = True
                    break
            # The place is held from here until the worker frees it, so
            # everything up to the worker's start answers for it.
            worker = threading.Thread(target=self._work,
                                      args=(call, wire, key, metadata),
                                      name="dbh-gateway-call", daemon=False)
            with self._state_lock:
                self._workers.add(worker)
            worker.start()
        except BaseException as exc:
            # A worker that did start frees its own place and registration;
            # freeing a place is once per call, so a worker that began to run
            # in spite of the interrupt does not free it a second time.
            held = call._place
            started = worker is not None and worker.is_alive()
            if not started:
                if worker is not None:
                    with self._state_lock:
                        self._workers.discard(worker)
                self._free_place(call)
            if not isinstance(exc, Exception):
                self._block("interrupted")
                raise
            if not held or started:
                # The admission check itself failed, or the worker is running.
                raise
            self._block("internal_error")
            call._finish(error=ProviderError("internal_error",
                                             classification=classify("internal_error")))
        return call

    def _free_place(self, call: CallHandle) -> None:
        """Give back the in-flight place ``call`` holds; a second call does nothing."""
        with self._state_lock:
            held, call._place = call._place, False
        if held:
            assert self._slots is not None
            self._slots.release()

    def _work(self, call: CallHandle, wire: bytes, key: str,
              metadata: dict[str, Any]) -> None:
        """One worker thread: run the request, settle the handle, free the place."""
        try:
            self._local.call = call
            try:
                answers = self._evaluate_wire(wire, key, metadata=metadata)
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    self._block("interrupted", call)
                call._finish(error=exc)
            else:
                call._finish(answers)
        finally:
            with self._state_lock:
                self._workers.discard(threading.current_thread())
            self._free_place(call)

    def _join_workers(self) -> str | None:
        """Stop new work and wait for the workers up to the attempt deadline.

        Returns ``transport_failed`` when some are still running after that.
        A retry that is waiting is abandoned; an attempt already sent is not.
        """
        with self._state_lock:
            self._closing = True
            pending = list(self._workers)
        self._wake.set()
        end = time.monotonic() + self.deadline_seconds
        for worker in pending:
            while worker.is_alive() and time.monotonic() < end:
                worker.join(_WAIT_SLICE)
        return "transport_failed" if any(worker.is_alive() for worker in pending) else None

    def _locked(self, run: Callable[[], dict[str, Any]],
                call: CallHandle | None = None) -> dict[str, Any]:
        """Run one request under the non-blocking call lock and owner bookkeeping.

        ``call`` is the handle that keeps the request's state (a fresh one
        when not given); it becomes what the ``last_*`` properties describe.
        Above ``max_in_flight`` 1 the request runs beside worker threads, so
        it obeys the same gate and stops they do.
        """
        if not self._call_lock.acquire(blocking=False):
            raise ProviderError("transport_failed")
        slot = False
        try:
            if self._slots is not None:
                # Counts against max_in_flight like a submitted request.
                if not self._slots.acquire(blocking=False):
                    raise ProviderError("transport_failed")
                slot = True
            if call is None:
                call = CallHandle(self, shared=self._slots is not None)
            self._stats_owner = threading.get_ident()
            self._last = call
            self._local.call = call
            self.require_available()
            self._busy = True
            return run()
        except BaseException as exc:
            if not isinstance(exc, Exception):
                self._block("interrupted", call)
            raise
        finally:
            self._busy = False
            if slot:
                assert self._slots is not None
                self._slots.release()
            self._call_lock.release()

    # -- one logical request -------------------------------------------------
    def _attempt_timeout(self, now: float) -> float:
        timeout = self.deadline_seconds
        if self._deadline is not None:
            timeout = min(timeout, self._deadline - now)
        return timeout

    def _evaluate(self, state: dict[str, Any], questions: dict[str, Any], *,
                  metadata: dict[str, Any]) -> dict[str, Any]:
        wire = encode_request(state, questions)
        meta = _metadata(metadata)
        self.check_sensitive(state, questions, metadata)
        # Own the expected question schema independently of caller/provider mutation.
        # encode_request has validated questions as plain JSON data by now.
        expected = _tree_copy(questions)
        return self._dispatch(wire, expected, hashlib.sha256(wire).hexdigest(), meta)

    def _evaluate_wire(self, wire: bytes, key: str, *,
                       metadata: dict[str, Any]) -> dict[str, Any]:
        meta = _metadata(metadata)
        # json.loads builds fresh objects that nothing else holds, so the
        # expected questions need no copy.
        sent = json.loads(wire)
        self.check_sensitive(sent["state"], sent["questions"], metadata)
        return self._dispatch(wire, sent["questions"], key, meta)

    def _dispatch(self, wire: bytes, expected: dict[str, Any], key: str,
                  meta: dict[str, Any]) -> dict[str, Any]:
        call = self._local.call
        assert call is not None
        if call._shared:
            # A call that waited for a place or for the backoff gate begins
            # only if the gateway has not stopped meanwhile.
            self._await_gate(call)
        with self._state_lock:
            if call._shared:
                code = self._refusal()
                if code is not None:
                    raise ProviderError(code)
            self.logical_requests += 1
            sequence = meta.get("sequence")
            self._sequence = call._sequence = (
                sequence if type(sequence) is int else self.logical_requests)
        try:
            now = self._now()
            if self._attempt_timeout(now) <= 0:
                raise ProviderError("run_deadline_exceeded",
                                    classification=classify("run_deadline_exceeded"))
            if (self._deadline is not None
                    and self._deadline - now < self.reserve_seconds()):
                # Too little run time is left for an attempt to finish:
                # refused before any receipt or byte, never a submission.
                raise ProviderError("run_deadline_reserved",
                                    classification=classify("run_deadline_reserved"))
            return self._logical(call, wire, expected, key, meta)
        except ProviderError as exc:
            if exc.code in _UNCOUNTED_REFUSALS and call._attempts == 0:
                # Refused before any receipt or byte: not a call, so the
                # progress line's calls= agrees with the report's count.
                with self._state_lock:
                    self.logical_requests -= 1
            raise
        finally:
            self._maybe_progress()

    def _base_receipt(self, meta: dict[str, Any], key: str, count: int, logical_id: str,
                      attempt: int, timeout: float) -> dict[str, Any]:
        # Receipt schema 2 adds route and model provenance (ADR-1(9)) and the
        # attempt fields (ADR-2(4)). ``request_sha256`` hashes the local
        # envelope, so it is the same on every route and every attempt.
        return {
            "schema_version": 2, "provider": self.provider_id, "model": self.model_id,
            "synthetic": self.synthetic, "metadata": meta, "request_sha256": key,
            "route": self.provider_id, "model_requested": self.model_id,
            "model_returned": None, "upstream_provider": None, "generation_id": None,
            "request_id": None, "wire_sha256": None, "answer_order_mismatch": False,
            "question_count": count, "rounding_places": self.rounding_places,
            "logical_id": logical_id, "attempt": attempt, "retry_reason": None,
            "waited_seconds": 0.0, "duplicate_billing_possible": False, "late": False,
            "deadline_seconds": max(0.0, timeout), "timeout_seconds": max(0.0, timeout),
            "status": "dispatching", "submission": "possible",
            "submission_possible": True, "usage": None, "answers": None, "error": None,
            "scoped": None, "provider_error": None,
            "cost_usd": None, "cost_source": "none", "cost_bound_usd": self._zero_bound(),
        }

    def _logical(self, call: CallHandle, wire: bytes, expected: dict[str, Any], key: str,
                 meta: dict[str, Any]) -> dict[str, Any]:
        logical_id = uuid.uuid4().hex
        used = {"not_sent": 0, "rejected": 0, "possible": 0, "stale_connection": 0}
        usage_total: dict[str, int] | None = None
        attempt, waited, reason, duplicate = 0, 0.0, None, False
        bound = self._attempt_bound(wire, len(expected))
        with self._state_lock:
            if self._over_budget(bound):
                # Refused before any receipt or byte, like the reserve refusal.
                self._stop("cost_budget_exhausted", call)
                raise ProviderError("cost_budget_exhausted",
                                    classification=classify("cost_budget_exhausted"))
            if self.max_cost is not None and bound is not None:
                self._reserve(call, bound)
        try:
            while True:
                attempt += 1
                call._attempts = attempt
                with self._state_lock:
                    self.attempts += 1
                    if attempt > 1:
                        self.retries += 1
                # Each attempt gets a fresh deadline, fixed before its receipt.
                started = self._now()
                timeout = self._attempt_timeout(started)
                receipt = self._base_receipt(meta, key, len(expected), logical_id, attempt,
                                             timeout)
                receipt.update(retry_reason=reason, waited_seconds=waited,
                               duplicate_billing_possible=duplicate)
                if bound is not None:
                    # The dispatching receipt carries the full bound: after a
                    # crash it alone says what this attempt may have cost.
                    receipt["cost_bound_usd"] = usd(bound)
                path = self.receipt_dir / (uuid.uuid4().hex + ".json")
                try:
                    answers, error, classification = self._journaled_attempt(
                        call, path, wire, expected, receipt, started + timeout)
                except BaseException as exc:
                    if not isinstance(exc, Exception):
                        # Block before another filesystem operation or propagation.
                        # The shared local receipt retains usage learned before.
                        self._settle_cost(call, receipt, bound)
                        self._fail_receipt(call, path, receipt, "interrupted", persist=True)
                    raise
                if receipt["usage"] is not None:
                    usage = receipt["usage"]
                    usage_total = {name: (0 if usage_total is None else usage_total[name])
                                   + usage[name] for name in ("input_tokens", "output_tokens")}
                plan: tuple[float, str, bool] | str | None = None
                with self._state_lock:
                    self._settle_cost(call, receipt, bound)
                    if receipt["submission"] != "not_sent":
                        self.attempts_transmitted += 1
                        self._elapsed.append(float(receipt.get("elapsed_seconds", 0.0)))
                    if (error is not None and classification is not None
                            and self._block_code is None):
                        plan = self._plan_retry(call, classification, used, bound)
                if isinstance(plan, tuple):
                    wait, next_reason, next_duplicate = plan
                    self._settle(call, path, receipt)
                    pause_error: BaseException | None = None
                    halted: str | None = None
                    try:
                        if wait > 0:
                            self._pause(wait)
                        if call._shared:
                            self._await_gate(call)
                            # Another call's blocking failure, or a close, ends
                            # a retry that has not been sent.
                            halted = self._block_code or (
                                "transport_failed" if self._closing else None)
                    except BaseException as exc:
                        pause_error = exc
                    if pause_error is not None:
                        # The next attempt was never sent. An interrupt (or a
                        # SystemExit) propagates as itself; a failing injected
                        # sleep is an internal defect that still settles the
                        # logical request and stops the gateway.
                        internal = isinstance(pause_error, Exception)
                        self._interrupted_backoff(call, meta, key, len(expected), logical_id,
                                                  attempt + 1, wait, next_reason, usage_total,
                                                  "internal_error" if internal else "interrupted")
                        if internal:
                            raise ProviderError("internal_error") from None
                        raise pause_error
                    if halted is not None:
                        self._interrupted_backoff(call, meta, key, len(expected), logical_id,
                                                  attempt + 1, wait, next_reason, usage_total,
                                                  halted)
                        raise ProviderError(halted)
                    waited, reason, duplicate = wait, next_reason, next_duplicate
                    continue
                receipt.update(logical_status="failed" if error else receipt["status"],
                               logical_attempts=attempt, logical_usage=usage_total)
                if plan in {"run_deadline", "cost_budget"}:
                    receipt["retry_abandoned"] = plan
                self._settle(call, path, receipt)
                with self._state_lock:
                    if plan == "cost_budget":
                        # The retry was not sent; nothing more is dispatched this run.
                        self._stop("cost_budget_exhausted", call)
                    if self._block_code is None and self.breaker.record(error, classification):
                        self._stop(self.breaker.stop_reason or "", call)
                if error:
                    raise ProviderError(error, classification=classification)
                assert answers is not None
                call._defects = dict(receipt["scoped"] or {})
                return answers
        finally:
            if call._reserved:
                # A failure between an attempt's reservation and its
                # settlement (a refused receipt, an interrupt) ends it too.
                with self._state_lock:
                    self._release(call)

    def _plan_retry(self, call: CallHandle, classification: Classification,
                    used: dict[str, int], bound: Decimal | None = None
                    ) -> tuple[float, str, bool] | str | None:
        """(wait, reason, duplicate billing possible), a refusal reason or None.

        The refusal reasons are ``"run_deadline"`` (the wait would cut into
        the reserve) and ``"cost_budget"`` (the retry could exceed
        ``max_cost``, counting the attempts in flight; ADR-9(4) checks retries
        too). A planned retry holds its bound in reserve from here until its
        attempt settles, and a rate-limit wait closes the backoff gate for
        every other call. Call with the state lock held.
        """
        policy = self.retry_policy
        code, submission = classification.code, classification.submission
        kind: str | None = None
        if (classification.stale_connection
                and used["stale_connection"] < policy.stale_connection):
            kind = "stale_connection"
        elif submission == "not_sent" and code in RETRYABLE["not_sent"]:
            kind = "not_sent"
        elif (submission == "rejected_unprocessed"
              and code in RETRYABLE["rejected_unprocessed"]):
            kind = "rejected"
        elif submission == "possible" and code in RETRYABLE["possible"]:
            kind = "possible"
        if kind is None or used[kind] >= policy.budget(kind):
            return None
        retry = used[kind] + 1
        if kind == "stale_connection":
            wait = 0.0
        elif kind == "rejected":
            if classification.retry_after is not None:
                wait = min(policy.retry_after_cap, max(0.0, classification.retry_after))
            else:
                wait = full_jitter(self._rng, policy.rejected_cap, 1.0, retry)
        else:
            wait = full_jitter(self._rng, policy.not_sent_cap, 0.5, retry)
        if (self._deadline is not None
                and self._now() + wait > self._deadline - self.reserve_seconds()):
            return "run_deadline"
        if self._over_budget(bound):
            return "cost_budget"
        used[kind] = retry
        if self.max_cost is not None and bound is not None:
            self._reserve(call, bound)
        if self._slots is not None and kind == "rejected" and wait > 0:
            until = self._now() + wait
            if until > self._gate_until:
                self._gate_until = until
            # This call waits out its own backoff; the gate holds the others.
            call._honored = max(call._honored, until)
        return (wait, "stale_connection" if kind == "stale_connection" else code,
                kind in {"stale_connection", "possible"})

    def _await_gate(self, call: CallHandle) -> None:
        """Wait until the backoff gate opens, once per gate time (shared calls).

        A rate-limit wait (``rejected`` retries) pauses every call that is
        about to send. The call that set the gate time has waited it out
        already. A block or a close ends the wait early.
        """
        while True:
            with self._state_lock:
                until = self._gate_until
                remaining = until - self._now()
                if (until <= call._honored or remaining <= 0
                        or self._block_code is not None or self._closing):
                    call._honored = max(call._honored, until)
                    return
            self._pause(remaining)
            call._honored = until

    def _hold_for_send(self, call: CallHandle, first: bool) -> tuple[str | None, float]:
        """Last look before the provider call of a shared call.

        Waits out the backoff gate (a rate-limit wait another call began while
        this one wrote its dispatching receipt) and then looks for a refusal.
        Returns (refusal code or None, seconds waited). A first attempt is
        refused by anything that refuses a new call; a retry, whose request
        began earlier, only by a blocking failure or a close, as before its
        wait. The dispatching receipt stays: it only says a send may follow,
        and the caller settles a refusal as not sent.
        """
        began = self._now()
        try:
            self._await_gate(call)
        except Exception:
            # An injected sleep failed: an internal defect that stops the run.
            self._block("internal_error", call)
            return "internal_error", 0.0
        waited = max(0.0, self._now() - began)
        with self._state_lock:
            if first:
                return self._refusal(), waited
            return (self._block_code or ("transport_failed" if self._closing else None),
                    waited)

    def _settle(self, call: CallHandle, path: Path, receipt: dict[str, Any]) -> None:
        """Write an attempt's terminal receipt; storage failure blocks."""
        # The settled receipt is never changed afterwards: the retry loop builds
        # a new one, and a failure reassigns the call's stats in _fail_receipt.
        call._stats = receipt
        try:
            _write_receipt(path, receipt)
        except Exception:
            self._fail_receipt(call, path, receipt, "receipt_failed", persist=False)
            raise ProviderError("receipt_failed") from None

    def _interrupted_backoff(self, call: CallHandle, meta: dict[str, Any], key: str,
                             count: int, logical_id: str, attempt: int, wait: float,
                             reason: str, usage_total: dict[str, int] | None,
                             code: str = "interrupted") -> None:
        """A backoff that did not finish: the next attempt was never sent."""
        receipt = self._base_receipt(meta, key, count, logical_id, attempt, 0.0)
        receipt.update(retry_reason=reason, waited_seconds=wait, submission="not_sent",
                       submission_possible=False, logical_status="failed",
                       logical_attempts=attempt, logical_usage=usage_total)
        path = self.receipt_dir / (uuid.uuid4().hex + ".json")
        self._fail_receipt(call, path, receipt, code, persist=True)

    def _fail_receipt(self, call: CallHandle, path: Path, receipt: dict[str, Any],
                      code: str, *, persist: bool) -> None:
        self._block(code, call)
        receipt.update(status="failed", error=code, answers=None)
        self._note_receipt(call, path)
        call._stats = deepcopy(receipt)
        if persist:
            try:
                _write_receipt(path, receipt)
            except BaseException:
                # Settlement is best effort; the gateway remains blocked even
                # when storage fails again or the operator interrupts again.
                pass

    def _note_receipt(self, call: CallHandle, path: Path) -> None:
        name = str(path)
        call._receipt = name
        if name not in call._receipts:
            call._receipts = (*call._receipts, name)

    def _journaled_attempt(self, call: CallHandle, path: Path, wire: bytes,
                           expected: dict[str, Any], receipt: dict[str, Any],
                           deadline_at: float
                           ) -> tuple[dict[str, Any] | None, str | None,
                                      Classification | None]:
        """Intent receipt, one provider call and validation.

        Returns (answers, error, classification) with ``receipt`` updated but
        its terminal state not yet written; the caller settles it.
        """
        # Whether this attempt's dispatching receipt is written: other calls
        # write theirs meanwhile, so the shared count cannot say.
        dispatched = False
        try:
            if not self._receipt_dir_ready:
                self.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                self._receipt_dir_ready = True
            self.check_sensitive(str(path), receipt)
            try:
                _write_receipt(path, receipt)
            except ProviderError:
                if self.receipt_dir.is_dir():
                    raise
                # The directory was removed after it was created: recreate it
                # once and retry this one write. A second failure takes the
                # receipt_failed path below.
                self.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                _write_receipt(path, receipt)
            # The dispatching receipt must survive a crash before dispatch:
            # its directory entry is made durable here, settlements skip it.
            dispatched = True
            with self._state_lock:
                self._dispatch_writes += 1
            _sync_directory(self.receipt_dir)
        except BaseException as exc:
            # The directory is created once. Before the dispatching write, a
            # removed directory is recreated best effort, so the failure receipt
            # lands as it did when every attempt created it (1a5f5be). A first
            # mkdir failure writes nothing, as before. A stat that fails counts
            # as missing. After the dispatching write the directory is left
            # alone, as 1a5f5be left it.
            if self._receipt_dir_ready and not dispatched:
                try:
                    present = self.receipt_dir.is_dir()
                except Exception:
                    present = False
                if not present:
                    try:
                        self.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                    except Exception:
                        pass
            if not isinstance(exc, Exception):
                # An interrupt is settled by the attempt loop, which writes its
                # interrupted receipt. Nothing is changed here.
                raise
            # The provider was never called: nothing can have been submitted.
            receipt.update(submission="not_sent", submission_possible=False,
                           cost_bound_usd=self._zero_bound())
            self._fail_receipt(call, path, receipt, "receipt_failed", persist=True)
            raise ProviderError("receipt_failed") from None
        self._note_receipt(call, path)
        # A top-level copy is enough: the only nested value present now is the
        # metadata dict, which no later step changes (every other nested value
        # is assigned whole, never edited in place).
        call._stats = dict(receipt)
        error: str | None = None
        answers: dict[str, Any] | None = None
        gated = 0.0
        refused: str | None = None
        if call._shared:
            # The checks made when the call began are stale by now: writing
            # the dispatching receipt took a while, and other calls kept going.
            refused, gated = self._hold_for_send(call, receipt["attempt"] == 1)
        started = self._now()
        # Intent persistence consumes the call budget. Recheck immediately
        # before the one provider call, including a reduced positive budget.
        # Time spent waiting for the backoff gate is not the attempt's: its
        # deadline starts at the send.
        timeout = deadline_at + gated - started
        refusal = "deadline_exceeded"
        if self._deadline is not None and self._deadline - started <= timeout:
            timeout = self._deadline - started
            refusal = "run_deadline_exceeded"
        receipt["timeout_seconds"] = max(0.0, timeout)
        if refused is not None:
            # The gateway blocked, stopped or closed after this call began:
            # nothing was handed to the provider, as in the refusal below.
            receipt.update(submission="not_sent", submission_possible=False,
                           status="failed", error=refused, answers=None,
                           elapsed_seconds=0.0, timeout_seconds=0.0)
            return None, refused, classify(refused, submission="not_sent")
        if timeout <= 0:
            # Refused before any byte was handed to the provider, so this
            # neither blocks the gateway nor counts as a possible submission.
            receipt.update(submission="not_sent", submission_possible=False,
                           status="failed", error=refusal, answers=None,
                           elapsed_seconds=0.0)
            return None, refusal, classify(refusal, submission="not_sent")
        classification: Classification | None = None
        try:
            response = self.provider.decide(ProviderRequest(wire, timeout))
            if type(response) is not ProviderResponse:
                raise ProviderError("response_schema")
            _record_details(receipt, response.provenance, self.check_sensitive)
            if response.cost_usd is not None:
                cost = reported_cost(response.cost_usd)
                if cost is None:
                    _record_details(receipt, {"cost_error": "invalid"}, self.check_sensitive)
                else:
                    receipt.update(cost_usd=usd(cost), cost_source="provider_reported")
            if type(response.order_mismatch) is int and response.order_mismatch > 0:
                receipt["answer_order_mismatch"] = True
            if response.usage is not None:
                receipt["usage"] = validate_usage(response.usage)
            if type(response.complete) is not bool:
                raise ProviderError("response_schema")
            if not response.complete:
                raise ProviderError("response_truncated")
            if response.error is not None:
                if type(response.error) is not str or response.error not in ERROR_CODES:
                    raise ProviderError("response_schema")
                raise ProviderError(response.error)
            # A complete 200 that arrived after the deadline is still the
            # answer that was paid for: kept, marked late, never blocking.
            receipt["late"] = self._now() - started >= timeout
            answers, defects = validate_answer_objects_scoped(
                response.answers, expected, self.rounding_places,
                _adapter_scoped(response.scoped))
            self.check_sensitive(answers, receipt["usage"])
            receipt["scoped"] = defects or None
        except ProviderError as exc:
            error = exc.code
            _record_details(receipt, getattr(exc, "info", None), self.check_sensitive)
            given = getattr(exc, "classification", None)
            classification = (given if type(given) is Classification and given.code == error
                              else classify(error))
            # A rejected credential or a refused route cannot succeed later
            # in this run either.
            if classification.blocking:
                self._block(error, call)
        except Exception:
            # Not a documented failure: an adapter defect, never a transport
            # verdict. The gateway still stops because its state is unknown.
            error = "internal_error"
            classification = classify(error)
            self._block(error, call)
        if classification is not None:
            receipt.update(submission=classification.submission,
                           submission_possible=classification.submission_possible)
            if classification.retry_after is not None:
                receipt["retry_after_seconds"] = classification.retry_after
        status = "failed" if error else (
            "validated_partial" if receipt["scoped"] else "validated")
        if error:
            receipt["scoped"] = None
        receipt.update(status=status, error=error,
                       answers=plain(answers) if error is None else None,
                       elapsed_seconds=max(0.0, self._now() - started))
        return answers, error, classification

    def _maybe_progress(self) -> None:
        """Count-only progress on the optional stream (ADR-9(5))."""
        if self._progress is None:
            return
        with self._state_lock:
            now = self._now()
            if (self.logical_requests - self._progress_calls < self.PROGRESS_EVERY_CALLS
                    and now - self._progress_at < self.PROGRESS_EVERY_SECONDS):
                return
            self._progress_calls, self._progress_at = self.logical_requests, now
            remaining = ("none" if self._deadline is None
                         else f"{max(0.0, self._deadline - now):.0f}s")
            spend = ("unknown" if self._prices is None
                     else "$" + usd(self._spent_upper().quantize(_MICRO,
                                                                 rounding=ROUND_CEILING)))
            try:
                self._progress.write(
                    f"progress: calls={self.logical_requests} attempts={self.attempts} "
                    f"elapsed={max(0.0, now - self._started):.0f}s remaining={remaining} "
                    f"spend<={spend}\n")
                self._progress.flush()
            except Exception:
                pass


#: The evaluate the engine's prepared path stands in for. It is captured as this
#: module loads, before any caller can patch the class, so a replacement made
#: later (a hook) is never this function.
VALIDATED_EVALUATE = ValidatedGateway.evaluate
