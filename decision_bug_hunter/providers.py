"""Small local provider boundary. No endpoint or SDK assumptions live here."""
from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import math
import os
from pathlib import Path
import random
import re
import tempfile
import threading
import time
from typing import Any, Protocol, TextIO
import uuid

from .protocol import (ERROR_CODES, ProviderError, _json, _metadata, encode_request,
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
                  zdr: bool = False, exchange: Any = None) -> DecisionProvider:
    """Library entry point: the hosted adapter for ``route``.

    ``route`` is a selector (``openai``, ``openrouter``) or a route name.
    ``model`` must be on the route's allow-list (default: its one model),
    otherwise ``invalid_request``; an unknown route is ``invalid_provider``.
    ``routing`` (``deny`` by default, or ``account-default``) and ``zdr``
    apply to OpenRouter only. Nothing is read from disk or the network.
    """
    name = ROUTES.get(route, route) if type(route) is str else None
    if name == "openai-decisions":
        if routing is not None or zdr:
            raise ProviderError("invalid_request")
        from .decisions import DecisionsProvider
        return DecisionsProvider(api_key, environ=environ, exchange=exchange, model=model)
    if name == "openrouter-decisions":
        from .openrouter import OpenRouterProvider
        return OpenRouterProvider(api_key, environ=environ, exchange=exchange, model=model,
                                  routing="deny" if routing is None else routing, zdr=zdr)
    raise ProviderError("invalid_provider")


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Durable atomic journal transition; no request or raw response bodies."""
    temp: Path | None = None
    error = False
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temp = Path(stream.name)
            stream.write(_json(plain(receipt)))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        temp = None
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
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
                 reserve_floor_seconds: float = 3.0) -> None:
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
        self.provider = provider
        self.provider_id = provider.identity.name
        self.model_id = provider.identity.model
        self.synthetic = provider.identity.synthetic
        self.receipt_dir = Path(receipt_dir)
        self.deadline_seconds = deadline
        self.rounding_places = rounding_places
        self.retry_policy = policy
        self.reserve_floor_seconds = float(reserve_floor_seconds)
        self._clock = clock
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()
        self._progress = progress
        self._deadline: float | None = None
        self._last_stats: dict[str, Any] | None = None
        self._last_receipt: str | None = None
        self._last_receipts: tuple[str, ...] = ()
        self._last_defects: dict[str, str] = {}
        self._stats_owner: int | None = None
        self._busy = False
        self._block_code: str | None = None
        self._closed = False
        self._call_lock = threading.Lock()
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

    # -- state -------------------------------------------------------------
    def _now(self) -> float:
        # Looked up at call time, so a patched ``time.monotonic`` applies.
        return self._clock() if self._clock is not None else time.monotonic()

    def _pause(self, seconds: float) -> None:
        if self._sleep is not None:
            self._sleep(seconds)
        else:
            time.sleep(seconds)

    @property
    def stop_reason(self) -> str | None:
        """``blocked:<code>`` or a breaker reason once the gateway stopped."""
        return self.breaker.stop_reason

    @property
    def _blocked(self) -> bool:
        return self._block_code is not None

    def _block(self, code: str) -> None:
        if self._block_code is None:
            self._block_code = code
        self._stop("blocked:" + self._block_code)

    def _stop(self, reason: str) -> None:
        if self.breaker.stop_reason is None:
            self.breaker.stop(reason)
        if self.stopped_at_sequence is None:
            self.stopped_at_sequence = self._sequence

    def stop(self, reason: str) -> None:
        """Stop further dispatch for ``reason`` (one of ``STOP_REASONS``)."""
        if reason not in STOP_REASONS:
            raise ProviderError("invalid_request")
        self._stop(reason)

    def reserve_seconds(self) -> float:
        """max(floor, 1.5 x p95 of the last 50 transmitted attempts' durations).

        The floor is ``reserve_floor_seconds`` (3 s by default).
        """
        if not self._elapsed:
            return self.reserve_floor_seconds
        ordered = sorted(self._elapsed)
        p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
        return max(self.reserve_floor_seconds, self.RESERVE_P95_FACTOR * p95)

    @property
    def last_call_stats(self) -> dict[str, Any] | None:
        if self._stats_owner != threading.get_ident():
            return None
        return deepcopy(self._last_stats)

    @property
    def last_receipt(self) -> str | None:
        if self._stats_owner != threading.get_ident():
            return None
        return self._last_receipt

    @property
    def last_receipts(self) -> tuple[str, ...]:
        """Every attempt receipt of the last logical request, in order."""
        if self._stats_owner != threading.get_ident():
            return ()
        return self._last_receipts

    @property
    def last_defects(self) -> dict[str, str]:
        """The answer-scoped defects of the last logical request, by name."""
        if self._stats_owner != threading.get_ident():
            return {}
        return dict(self._last_defects)

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

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def close(self) -> None:
        if not self._call_lock.acquire(blocking=False):
            raise ProviderError("transport_failed")
        try:
            if not self._closed:
                error = None
                try:
                    self.provider.close()
                except ProviderError as exc:
                    error = exc.code
                except Exception:
                    error = "transport_failed"
                if error:
                    self._block(error)
                    raise ProviderError(error)
                self._closed = True
        finally:
            self._call_lock.release()

    def evaluate(self, state: dict[str, Any], questions: dict[str, Any], *,
                 metadata: dict[str, Any]) -> dict[str, Any]:
        if not self._call_lock.acquire(blocking=False):
            raise ProviderError("transport_failed")
        try:
            self._stats_owner = threading.get_ident()
            self._last_stats = None
            self._last_receipt = None
            self._last_receipts = ()
            self._last_defects = {}
            self.require_available()
            self._busy = True
            return self._evaluate(state, questions, metadata=metadata)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                self._block("interrupted")
            raise
        finally:
            self._busy = False
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
        expected = deepcopy(questions)
        key = hashlib.sha256(wire).hexdigest()
        self.logical_requests += 1
        sequence = meta.get("sequence")
        self._sequence = sequence if type(sequence) is int else self.logical_requests
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
            return self._logical(wire, expected, key, meta)
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
        }

    def _logical(self, wire: bytes, expected: dict[str, Any], key: str,
                 meta: dict[str, Any]) -> dict[str, Any]:
        logical_id = uuid.uuid4().hex
        used = {"not_sent": 0, "rejected": 0, "possible": 0, "stale_connection": 0}
        usage_total: dict[str, int] | None = None
        attempt, waited, reason, duplicate = 0, 0.0, None, False
        while True:
            attempt += 1
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
            path = self.receipt_dir / (uuid.uuid4().hex + ".json")
            try:
                answers, error, classification = self._journaled_attempt(
                    path, wire, expected, receipt, started + timeout)
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    # Block before another filesystem operation or propagation.
                    # The shared local receipt retains usage learned before.
                    self._fail_receipt(path, receipt, "interrupted", persist=True)
                raise
            if receipt["submission"] != "not_sent":
                self.attempts_transmitted += 1
                self._elapsed.append(float(receipt.get("elapsed_seconds", 0.0)))
            if receipt["usage"] is not None:
                usage = receipt["usage"]
                usage_total = {name: (0 if usage_total is None else usage_total[name])
                               + usage[name] for name in ("input_tokens", "output_tokens")}
            plan: tuple[float, str, bool] | str | None = None
            if error is not None and classification is not None and self._block_code is None:
                plan = self._plan_retry(classification, used)
            if isinstance(plan, tuple):
                wait, next_reason, next_duplicate = plan
                self._settle(path, receipt)
                interrupted = False
                try:
                    if wait > 0:
                        self._pause(wait)
                except BaseException as exc:
                    if isinstance(exc, Exception):
                        raise
                    interrupted = True
                if interrupted:
                    self._interrupted_backoff(meta, key, len(expected), logical_id,
                                              attempt + 1, wait, next_reason, usage_total)
                    raise KeyboardInterrupt
                waited, reason, duplicate = wait, next_reason, next_duplicate
                continue
            receipt.update(logical_status="failed" if error else receipt["status"],
                           logical_attempts=attempt, logical_usage=usage_total)
            if plan == "run_deadline":
                receipt["retry_abandoned"] = "run_deadline"
            self._settle(path, receipt)
            if self._block_code is None and self.breaker.record(error, classification):
                self._stop(self.breaker.stop_reason or "")
            if error:
                raise ProviderError(error, classification=classification)
            assert answers is not None
            self._last_defects = dict(receipt["scoped"] or {})
            return answers

    def _plan_retry(self, classification: Classification,
                    used: dict[str, int]) -> tuple[float, str, bool] | str | None:
        """(wait, reason, duplicate billing possible), ``"run_deadline"`` or None."""
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
        used[kind] = retry
        return (wait, "stale_connection" if kind == "stale_connection" else code,
                kind in {"stale_connection", "possible"})

    def _settle(self, path: Path, receipt: dict[str, Any]) -> None:
        """Write an attempt's terminal receipt; storage failure blocks."""
        self._last_stats = deepcopy(receipt)
        try:
            _write_receipt(path, receipt)
        except Exception:
            self._fail_receipt(path, receipt, "receipt_failed", persist=False)
            raise ProviderError("receipt_failed") from None

    def _interrupted_backoff(self, meta: dict[str, Any], key: str, count: int,
                             logical_id: str, attempt: int, wait: float, reason: str,
                             usage_total: dict[str, int] | None) -> None:
        """An interrupt during a backoff: the next attempt was never sent."""
        receipt = self._base_receipt(meta, key, count, logical_id, attempt, 0.0)
        receipt.update(retry_reason=reason, waited_seconds=wait, submission="not_sent",
                       submission_possible=False, logical_status="failed",
                       logical_attempts=attempt, logical_usage=usage_total)
        path = self.receipt_dir / (uuid.uuid4().hex + ".json")
        self._fail_receipt(path, receipt, "interrupted", persist=True)

    def _fail_receipt(self, path: Path, receipt: dict[str, Any], code: str, *,
                      persist: bool) -> None:
        self._block(code)
        receipt.update(status="failed", error=code, answers=None)
        self._note_receipt(path)
        self._last_stats = deepcopy(receipt)
        if persist:
            try:
                _write_receipt(path, receipt)
            except BaseException:
                # Settlement is best effort; the gateway remains blocked even
                # when storage fails again or the operator interrupts again.
                pass

    def _note_receipt(self, path: Path) -> None:
        name = str(path)
        self._last_receipt = name
        if name not in self._last_receipts:
            self._last_receipts = (*self._last_receipts, name)

    def _journaled_attempt(self, path: Path, wire: bytes, expected: dict[str, Any],
                           receipt: dict[str, Any], deadline_at: float
                           ) -> tuple[dict[str, Any] | None, str | None,
                                      Classification | None]:
        """Intent receipt, one provider call and validation.

        Returns (answers, error, classification) with ``receipt`` updated but
        its terminal state not yet written; the caller settles it.
        """
        try:
            self.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.check_sensitive(str(path), receipt)
            _write_receipt(path, receipt)
        except Exception:
            # The provider was never called: nothing can have been submitted.
            receipt.update(submission="not_sent", submission_possible=False)
            self._fail_receipt(path, receipt, "receipt_failed", persist=True)
            raise ProviderError("receipt_failed") from None
        self._note_receipt(path)
        self._last_stats = deepcopy(receipt)
        error: str | None = None
        answers: dict[str, Any] | None = None
        started = self._now()
        # Intent persistence consumes the call budget. Recheck immediately
        # before the one provider call, including a reduced positive budget.
        timeout = deadline_at - started
        refusal = "deadline_exceeded"
        if self._deadline is not None and self._deadline - started <= timeout:
            timeout = self._deadline - started
            refusal = "run_deadline_exceeded"
        receipt["timeout_seconds"] = max(0.0, timeout)
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
                self._block(error)
        except Exception:
            # Not a documented failure: an adapter defect, never a transport
            # verdict. The gateway still stops because its state is unknown.
            error = "internal_error"
            classification = classify(error)
            self._block(error)
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
        now = self._now()
        if (self.logical_requests - self._progress_calls < self.PROGRESS_EVERY_CALLS
                and now - self._progress_at < self.PROGRESS_EVERY_SECONDS):
            return
        self._progress_calls, self._progress_at = self.logical_requests, now
        remaining = ("none" if self._deadline is None
                     else f"{max(0.0, self._deadline - now):.0f}s")
        try:
            self._progress.write(
                f"progress: calls={self.logical_requests} attempts={self.attempts} "
                f"elapsed={max(0.0, now - self._started):.0f}s remaining={remaining}\n")
            self._progress.flush()
        except Exception:
            pass
