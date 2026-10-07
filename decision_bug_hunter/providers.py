"""Small local provider boundary. No endpoint or SDK assumptions live here."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import math
import os
from pathlib import Path
import re
import tempfile
import threading
import time
from typing import Any, Protocol
import uuid

from .protocol import (ERROR_CODES, ProviderError, _json, _metadata, encode_request,
                       plain, validate_answer_objects, validate_usage,
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
    `scoped` maps a question name to an answer-scoped defect code; it is
    reserved for partial batches and adapters leave it empty today.
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
    """

    code: str
    submission: str
    retry_after: float | None = None
    blocking: bool = False
    scope: str = "request"
    permanent: bool = False

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
}
#: Batch-level 200 defects: possible submission, deterministic for the request.
_RESPONSE_DEFECTS = frozenset({
    "response_too_large", "response_framing", "response_type", "response_invalid_json",
    "response_schema", "response_model", "response_truncated", "response_probability",
    "response_usage", "response_sensitive", "response_distribution",
    "choice_argmax_mismatch", "response_vector_missing"})
#: Codes that still block the gateway although ADR-2(6) makes them transient:
#: without retries and the breaker (a later package) a failing route would
#: otherwise be asked again for every remaining request of the run.
INTERIM_BLOCKING = frozenset({"connect_failed", "transport_failed", "deadline_exceeded"})


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
    """Serial, one-attempt evaluation with exact validation and local receipts.

    A dispatching receipt records possible submission; a call refused before
    the provider is reached records ``submission_possible: false``. Both
    receipts carry the same ``deadline_seconds``, fixed before dispatch. Failed
    persistence or interrupted dispatch prevents further use of this gateway;
    there is no retry. Undocumented adapter exceptions become ``internal_error``.
    Provider timeouts are cooperative until an actual transport is implemented.
    """

    def __init__(self, provider: DecisionProvider, receipt_dir: Path | str, *,
                 deadline_seconds: float = 30.0,
                 rounding_places: int | None = None) -> None:
        deadline = validate_call_deadline(deadline_seconds)
        _rounding_profile(rounding_places)
        if type(provider.identity) is not ProviderIdentity:
            raise ProviderError("invalid_metadata")
        self.provider = provider
        self.provider_id = provider.identity.name
        self.model_id = provider.identity.model
        self.synthetic = provider.identity.synthetic
        self.receipt_dir = Path(receipt_dir)
        self.deadline_seconds = deadline
        self.rounding_places = rounding_places
        self._deadline: float | None = None
        self._last_stats: dict[str, Any] | None = None
        self._last_receipt: str | None = None
        self._stats_owner: int | None = None
        self._busy = False
        self._blocked = False
        self._closed = False
        self._call_lock = threading.Lock()

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

    def require_available(self) -> None:
        if self._closed or self._blocked or self._busy:
            raise ProviderError("transport_failed")
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
                    self._blocked = True
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
            self.require_available()
            self._busy = True
            return self._evaluate(state, questions, metadata=metadata)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                self._blocked = True
            raise
        finally:
            self._busy = False
            self._call_lock.release()

    def _evaluate(self, state: dict[str, Any], questions: dict[str, Any], *,
                  metadata: dict[str, Any]) -> dict[str, Any]:
        self._last_stats = None
        self._last_receipt = None
        wire = encode_request(state, questions)
        meta = _metadata(metadata)
        self.check_sensitive(state, questions, metadata)
        # Own the expected question schema independently of caller/provider mutation.
        expected = deepcopy(questions)
        # One absolute deadline per call, fixed before the dispatching receipt;
        # both receipts record the same ``deadline_seconds``.
        now = time.monotonic()
        timeout = self.deadline_seconds
        if self._deadline is not None:
            timeout = min(timeout, self._deadline - now)
        if timeout <= 0:
            raise ProviderError("run_deadline_exceeded")
        deadline_at = now + timeout
        key = hashlib.sha256(wire).hexdigest()
        # Receipt schema 2 adds route and model provenance (ADR-1(9)).
        # ``request_sha256`` hashes the local envelope, so it is the same on
        # every route; ``wire_sha256`` is the adapter's own request bytes.
        receipt: dict[str, Any] = {
            "schema_version": 2, "provider": self.provider_id, "model": self.model_id,
            "synthetic": self.synthetic, "metadata": meta, "request_sha256": key,
            "route": self.provider_id, "model_requested": self.model_id,
            "model_returned": None, "upstream_provider": None, "generation_id": None,
            "request_id": None, "wire_sha256": None, "answer_order_mismatch": False,
            "question_count": len(expected), "rounding_places": self.rounding_places,
            "deadline_seconds": timeout, "timeout_seconds": timeout,
            "status": "dispatching", "submission": "possible",
            "submission_possible": True, "usage": None, "answers": None, "error": None,
            "provider_error": None,
        }
        path = self.receipt_dir / (uuid.uuid4().hex + ".json")
        try:
            return self._journaled_attempt(path, wire, expected, receipt, deadline_at)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                # Block before another filesystem operation or propagation. The
                # shared local receipt retains usage learned before interruption.
                self._fail_receipt(path, receipt, "interrupted", persist=True)
            raise

    def _fail_receipt(self, path: Path, receipt: dict[str, Any], code: str, *,
                      persist: bool) -> None:
        self._blocked = True
        receipt.update(status="failed", error=code, answers=None)
        self._last_receipt = str(path)
        self._last_stats = deepcopy(receipt)
        if persist:
            try:
                _write_receipt(path, receipt)
            except BaseException:
                # Settlement is best effort; the gateway remains blocked even
                # when storage fails again or the operator interrupts again.
                pass

    def _journaled_attempt(self, path: Path, wire: bytes, expected: dict[str, Any],
                           receipt: dict[str, Any], deadline_at: float) -> dict[str, Any]:
        try:
            self.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.check_sensitive(str(path), receipt)
            _write_receipt(path, receipt)
        except Exception:
            # The provider was never called: nothing can have been submitted.
            receipt["submission_possible"] = False
            self._fail_receipt(path, receipt, "receipt_failed", persist=True)
            raise ProviderError("receipt_failed") from None
        self._last_receipt = str(path)
        self._last_stats = deepcopy(receipt)
        error: str | None = None
        answers: dict[str, Any] | None = None
        started = time.monotonic()
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
            receipt.update(submission_possible=False, status="failed",
                           error=refusal, answers=None, elapsed_seconds=0.0)
            self._last_stats = deepcopy(receipt)
            try:
                _write_receipt(path, receipt)
            except Exception:
                self._fail_receipt(path, receipt, "receipt_failed", persist=False)
                raise ProviderError("receipt_failed") from None
            raise ProviderError(refusal)
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
            if time.monotonic() - started >= timeout:
                raise ProviderError("deadline_exceeded")
            answers = validate_answer_objects(response.answers, expected, self.rounding_places)
            self.check_sensitive(answers, receipt["usage"])
        except ProviderError as exc:
            error = exc.code
            _record_details(receipt, getattr(exc, "info", None), self.check_sensitive)
            given = getattr(exc, "classification", None)
            classification = (given if type(given) is Classification and given.code == error
                              else classify(error))
            # A rejected credential or a refused route cannot succeed later
            # in this run either.
            if classification.blocking or error in INTERIM_BLOCKING:
                self._blocked = True
        except Exception:
            # Not a documented failure: an adapter defect, never a transport
            # verdict. The gateway still stops because its state is unknown.
            error = "internal_error"
            self._blocked = True
        if classification is not None:
            receipt.update(submission=classification.submission,
                           submission_possible=classification.submission_possible)
            if classification.retry_after is not None:
                receipt["retry_after_seconds"] = classification.retry_after
        receipt.update(status="failed" if error else "validated", error=error,
                       answers=plain(answers) if error is None else None,
                       elapsed_seconds=max(0.0, time.monotonic() - started))
        self._last_stats = deepcopy(receipt)
        try:
            _write_receipt(path, receipt)
        except Exception:
            self._fail_receipt(path, receipt, "receipt_failed", persist=False)
            raise ProviderError("receipt_failed") from None
        if error:
            raise ProviderError(error)
        assert answers is not None
        return answers
