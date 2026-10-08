"""Shared base for the two hosted Decisions routes (ADR-1).

A route is one fixed HTTPS origin, path and credential variable with an
allow-list of models. Both routes serve the same judge: the OpenAI Decisions
model, directly (``openai-decisions``) or through OpenRouter
(``openrouter-decisions``). ``HostedProvider`` owns what they share: reading
the credential once, the per-instance identity, credential checks over every
configured provider key, the deadline-bounded exchange, and the mapping of
transport failures to fixed codes and submission classes. Subclasses supply
the request encoding, the response decoding and the status table.

Nothing here prints, logs or journals a credential, a header value other
than the allow-listed identifiers, or any part of an error message.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import json
import math
import os
import re
import ssl
import threading
import time
from typing import Any, ClassVar

from .exchange import Clock, Deadline, ExchangeError, HttpsExchange, Outcome, _kind
from .protocol import (DEFAULT_POLICY_PLACEMENT, MAX_QUESTIONS, POLICY_PLACEMENTS,
                       POLICY_STATE_KEY, ProviderError, _REQUEST_PREFIX, _json, _pairs,
                       _secret_in)
from .providers import (Classification, ProviderIdentity, ProviderRequest,
                        ProviderResponse, classify)


#: Every provider credential DBH knows; all configured values are checked.
CREDENTIAL_VARIABLES = ("OPENAI_API_KEY", "OPENROUTER_API_KEY")
#: Credentials and routing identifiers are single-line printable ASCII tokens.
_HEADER_TOKEN = re.compile(r"[!-~]{1,4096}\Z")
#: An inactive key shorter than this is not treated as a credential, so a
#: stray placeholder cannot make ordinary source text "sensitive".
_INACTIVE_MIN_LENGTH = 8
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_UPSTREAM = re.compile(r"[A-Za-z0-9 _.-]{1,64}\Z")
_MODEL_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z")
_RETRY_SECONDS = re.compile(r"[0-9]{1,5}\Z")
#: Retry-After values above this are capped (ADR-2(3)).
MAX_RETRY_AFTER_SECONDS = 60.0
#: The date the list prices in the route model specs were read (ADR-9(2)).
PRICE_TABLE_DATE = "2026-10-06"
#: A local envelope whose state starts with the policy entry: a request sent
#: under "state" policy placement (ADR-5(1)), the only kind that may use a
#: model's raised caps.
_PLACED_PAYLOAD = _REQUEST_PREFIX + b"{" + _json(POLICY_STATE_KEY) + b":"
#: Most exchanges a provider may hold open at once (``max_connections``).
MAX_CONNECTIONS = 8


@dataclass(frozen=True)
class ModelSpec:
    """One allow-listed model of a route and its local bounds.

    Prices are USD per million tokens from the public model page on
    ``price_table_date``. ``price_out_upper_per_mtok`` prices the output
    allowance of an attempt whose usage is unknown (ADR-9(3)).
    ``max_questions`` and ``max_envelope_bytes`` bound every request; a
    request whose policy sits in state may instead use the
    ``state_placement_*`` caps when both are set (ADR-5(5)).
    """

    id: str
    price_in_per_mtok: Decimal
    price_out_upper_per_mtok: Decimal
    max_questions: int = 64
    max_envelope_bytes: int = 24576
    display_places: int = 2
    confidence_identity: str | None = None
    expected_upstream: str | None = None
    price_table_date: str = PRICE_TABLE_DATE
    state_placement_max_questions: int | None = None
    state_placement_max_envelope_bytes: int | None = None

    def limits(self, placement: str = DEFAULT_POLICY_PLACEMENT) -> tuple[int, int]:
        """(max questions, max local envelope bytes) under *placement*."""
        if (placement == "state" and self.state_placement_max_questions is not None
                and self.state_placement_max_envelope_bytes is not None):
            return self.state_placement_max_questions, self.state_placement_max_envelope_bytes
        return self.max_questions, self.max_envelope_bytes


@dataclass(frozen=True)
class RouteSpec:
    """A fixed origin, path and credential variable with a model allow-list."""

    name: str
    selector: str
    host: str
    path: str
    credential_variable: str
    models: tuple[ModelSpec, ...]
    default_model: str
    port: int = 443

    def model(self, model_id: str | None = None) -> ModelSpec:
        """The allow-listed model, or ``invalid_request`` for anything else."""
        wanted = self.default_model if model_id is None else model_id
        for spec in self.models:
            if spec.id == wanted:
                return spec
        raise ProviderError("invalid_request")


def token(value: Any) -> str | None:
    if type(value) is not str or not _HEADER_TOKEN.fullmatch(value):
        return None
    return value


def configured_credentials(environ: Mapping[str, str], active: str | None) -> tuple[str, ...]:
    """The active credential plus every set, token-valid provider key.

    Used only to refuse local data that contains any of them; a key for the
    route that was not selected must not leave this machine either.
    """
    found: list[str] = [] if active is None else [active]
    for variable in CREDENTIAL_VARIABLES:
        value = token(environ.get(variable, ""))
        if value is not None and len(value) >= _INACTIVE_MIN_LENGTH and value not in found:
            found.append(value)
    return tuple(found)


def model_echo_ok(returned: Any, requested: str, suffixes: Iterable[re.Pattern[str]]) -> bool:
    """Exactly the requested id, or the id plus one allowed dated suffix."""
    if type(returned) is not str:
        return False
    if returned == requested:
        return True
    if not returned.startswith(requested + "-"):
        return False
    rest = returned[len(requested):]
    return any(pattern.fullmatch(rest) for pattern in suffixes)


def model_returned(value: Any) -> str | None:
    """A charset-valid echoed model id for the receipt, never anything else."""
    if type(value) is str and _MODEL_ID.fullmatch(value):
        return value
    return None


def identifier(value: Any) -> str | None:
    if type(value) is str and _ID.fullmatch(value):
        return value
    return None


def upstream_name(value: Any) -> str | None:
    if type(value) is str and _UPSTREAM.fullmatch(value):
        return value
    return None


def parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    """Delta-seconds (``[0-9]{1,5}``) or an HTTP-date, capped at 60 s.

    Anything else, including a date in the past beyond rounding, is ignored.
    """
    if value is None:
        return None
    value = value.strip()
    if _RETRY_SECONDS.fullmatch(value):
        return min(MAX_RETRY_AFTER_SECONDS, float(int(value)))
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when is None or when.tzinfo is None:
        return None
    current = datetime.now(timezone.utc) if now is None else now
    seconds = (when - current).total_seconds()
    if not math.isfinite(seconds):
        return None
    return min(MAX_RETRY_AFTER_SECONDS, max(0.0, seconds))


def error_object(raw: bytes | None) -> dict[str, Any] | None:
    """The ``error`` object of an already credential-checked JSON body."""
    if raw is None:
        return None
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except Exception:
        return None
    if type(data) is not dict or type(data.get("error")) is not dict:
        return None
    error: dict[str, Any] = data["error"]
    return error


def transport_failure(exc: ExchangeError) -> Classification:
    """Fixed code and submission class of an exchange failure (ADR-2(2)).

    Connect (DNS, TCP, TLS) and a send failure on a fresh connection never
    delivered a complete request: ``connect_failed``, not sent. Anything
    after a complete send, or a send on a reused connection, may have been
    processed: ``deadline_exceeded`` on a timeout, else ``transport_failed``,
    flagged ``stale_connection`` when ``stale_connection(exc)`` holds.
    """
    if exc.phase == "connect" or (exc.phase == "send" and not exc.reused):
        return classify("connect_failed")
    if exc.kind == "timeout":
        return classify("deadline_exceeded")
    return replace(classify("transport_failed"), stale_connection=stale_connection(exc))


#: A reset on a reused connection counts as stale only this soon after the send.
STALE_WINDOW_SECONDS = 1.0


def stale_connection(exc: ExchangeError) -> bool:
    """A kept-alive socket the server had already closed (ADR-2(2)).

    True only on a reused connection, for a reset, broken pipe, abort or EOF
    (``kind == "reset"``) with zero response bytes, raised during the send or
    at most ``STALE_WINDOW_SECONDS`` after ``sendall`` completed. Timeouts
    never qualify: the request may still be in progress.
    """
    if not exc.reused or exc.kind != "reset" or exc.response_bytes != 0:
        return False
    if exc.phase == "send":
        return True
    return (exc.phase == "receive" and exc.since_send is not None
            and exc.since_send <= STALE_WINDOW_SECONDS)


def _unsent_deadline() -> ProviderError:
    """The caller's timeout ended before an exchange was free: nothing was sent."""
    return ProviderError("deadline_exceeded",
                         classification=classify("deadline_exceeded", submission="not_sent"))


class _Memo(threading.local):
    """The one-slot encode memo of one thread (see ``HostedProvider._encoded``)."""

    slot: tuple[bytes, int, bytes, dict[str, Any]] | None = None


class _ExchangePool:
    """Up to ``size`` exchanges, each used by one thread at a time.

    ``acquire(until)`` takes an idle exchange, builds one while fewer than
    ``size`` exist, and otherwise waits on the condition until ``release``
    returns one, but never past ``until`` on ``clock``: then it returns None
    and takes nothing. The first exchange builds the one TLS context (its
    ``contexts_built`` becomes 1); every later exchange is built over that
    same context, so the pool never builds a second one. A failure to build
    that context is raised as the ``ExchangeError`` a failed connect gives
    at ``max_connections=1``. The first grow builds that context while
    holding the condition: other acquires, release and close wait for it, and
    it is not bounded by ``until``. Every exchange keeps its own connection
    and idle bookkeeping.

    ``close`` closes the idle exchanges at once and does not wait for busy
    ones: a busy exchange's connection is closed when its current request
    returns to ``release``, so no connection stays open after ``close``.
    The pool stays usable after ``close``; the next acquire reconnects.
    """

    def __init__(self, make: Callable[[ssl.SSLContext | None], HttpsExchange],
                 size: int, clock: Clock = time.monotonic) -> None:
        self._make = make
        self._size = size
        self.clock = clock
        self._cond = threading.Condition()
        self._all: list[HttpsExchange] = []
        self._idle: list[HttpsExchange] = []
        self._busy: set[HttpsExchange] = set()
        self._retiring: set[HttpsExchange] = set()
        self._context: ssl.SSLContext | None = None

    def acquire(self, until: float) -> HttpsExchange | None:
        """An exchange now busy with the caller, or None once ``until`` passes.

        The first grow builds the shared TLS context while holding the
        condition: other acquires, release and close wait for it, and it is
        not bounded by ``until``.
        """
        with self._cond:
            self._restore_orphans()
            if not self._idle and len(self._all) < self._size:
                self._grow()
            while not self._idle:
                remaining = until - self.clock()
                if remaining <= 0:
                    return None
                # Clamped because threading rejects a wait above TIMEOUT_MAX;
                # the loop rechecks ``until``, so the bound is unchanged.
                self._cond.wait(min(remaining, threading.TIMEOUT_MAX))
            exchange = self._idle.pop()
            try:
                self._busy.add(exchange)
            except BaseException:
                # An interrupt inside the mark gives the exchange back at once.
                # One between the pop and this try leaves it in neither set, and
                # ``_restore_orphans`` returns it on the next acquire. One after
                # the mark, before the caller holds it, is the residual noted
                # in ``HostedProvider.decide``.
                self._idle.append(exchange)
                self._cond.notify()
                raise
            return exchange

    def release(self, exchange: HttpsExchange) -> None:
        with self._cond:
            try:
                self._busy.discard(exchange)
                if exchange in self._retiring:
                    self._retiring.discard(exchange)
                    exchange.close()
            finally:
                # Idle again however the steps above ended, so an interrupt
                # cannot leave the exchange in neither set (that would shrink
                # the pool for good). The discard and the retiring check repeat
                # because the first may be the step that was interrupted; both
                # are idempotent. A retiring exchange is closed here, not
                # returned to idle while still connected.
                self._busy.discard(exchange)
                if exchange in self._retiring:
                    self._retiring.discard(exchange)
                    exchange.close()
                if exchange not in self._idle:
                    self._idle.append(exchange)
                self._cond.notify()

    def _restore_orphans(self) -> None:
        # Called with the condition held. An interrupt in the few bytecodes
        # between taking an exchange out of one set and putting it in another
        # can leave it in neither; no caller holds such an exchange, so it
        # goes back to idle.
        for exchange in self._all:
            if exchange not in self._idle and exchange not in self._busy:
                self._idle.append(exchange)

    def close(self) -> None:
        with self._cond:
            for exchange in self._all:
                if exchange in self._busy:
                    self._retiring.add(exchange)
                else:
                    exchange.close()

    def _grow(self) -> None:
        # Called with the condition held, so two threads never build the context twice.
        if self._context is None:
            exchange = self._make(None)
            try:
                self._context = exchange.context
            except (OSError, http.client.HTTPException, ValueError) as exc:
                # post maps the same failure, met while connecting, to a connect
                # error; nothing was sent and no exception text is kept.
                raise ExchangeError("connect", _kind(exc), reused=False, bytes_sent=0,
                                    response_bytes=0) from None
        else:
            exchange = self._make(self._context)
        self._all.append(exchange)
        self._idle.append(exchange)


class HostedProvider:
    """One hosted route; construction reads the environment and nothing else.

    Without a usable credential for the route every operation raises
    ``provider_unavailable`` before any source read, output or network use.
    ``identity`` is per instance: the route name and the selected model.

    ``max_connections`` (1 to ``MAX_CONNECTIONS``, else ``invalid_request``)
    sets how many exchanges ``decide`` may use at once. At 1 there is one
    exchange and no locking, as before: the caller must not call ``decide``
    concurrently (the gateway's call lock enforces that). Above 1, ``decide``
    may be called from several threads; each call holds one exchange, and
    ``exchange`` (a single injected exchange) is then refused.

    Above 1 the call's ``timeout_seconds`` bounds only the wait for a free
    exchange: a wait that outlasts it raises ``deadline_exceeded`` with
    submission ``not_sent`` and nothing is sent. The send's own deadline starts
    when the exchange is taken and is the full timeout (plan invariant 7), so
    a call that waited may take up to the wait plus one timeout. At 1 there is
    no wait, so the timeout bounds the send alone, as before.

    Copying or pickling: a provider at 1 copies and pickles as before (its
    per-thread memo is dropped and recreated); one above 1 holds a lock and
    raises ``TypeError`` instead.
    """

    route: ClassVar[RouteSpec]

    def __init__(self, api_key: str | None = None, *,
                 environ: Mapping[str, str] | None = None,
                 exchange: HttpsExchange | None = None,
                 model: str | None = None,
                 policy_placement: str = DEFAULT_POLICY_PLACEMENT,
                 max_connections: int = 1) -> None:
        env: Mapping[str, str] = os.environ if environ is None else environ
        if type(policy_placement) is not str or policy_placement not in POLICY_PLACEMENTS:
            raise ProviderError("invalid_request")
        if type(max_connections) is not int or not 1 <= max_connections <= MAX_CONNECTIONS:
            raise ProviderError("invalid_request")
        if max_connections > 1 and exchange is not None:
            raise ProviderError("invalid_request")
        self.policy_placement = policy_placement
        self.model_spec = self.route.model(model)
        self.identity = ProviderIdentity(self.route.name, model=self.model_spec.id)
        # One exchange, hence one TLS context and connection, per provider at
        # the default. Nothing is built or opened until the first dispatch.
        self._exchange: HttpsExchange | None = None
        self._pool: _ExchangePool | None = None
        if max_connections == 1:
            self._exchange = exchange if exchange is not None else HttpsExchange(
                self.route.host, self.route.path, port=self.route.port)
        else:
            self._pool = _ExchangePool(self._new_exchange, max_connections)
        key = env.get(self.route.credential_variable, "") if api_key is None else api_key
        self._api_key = token(key)
        self._credentials = configured_credentials(env, self._api_key)
        # One slot per thread: the last wire_size encode, (payload, max
        # questions, body, questions), for the decide call that follows it on
        # the same thread. Only ever a hit when the payload and limits are
        # equal, so it cannot change bytes.
        self._memo = _Memo()

    @property
    def _encoded(self) -> tuple[bytes, int, bytes, dict[str, Any]] | None:
        """This thread's encode memo; another thread's never matches."""
        return self._memo.slot

    @_encoded.setter
    def _encoded(self, value: tuple[bytes, int, bytes, dict[str, Any]] | None) -> None:
        self._memo.slot = value

    def __getstate__(self) -> dict[str, Any]:
        # A thread-local memo and a pool's lock cannot be copied. The memo is a
        # per-call cache, so a copy starts with an empty one.
        if self._pool is not None:
            raise TypeError("a HostedProvider with max_connections above 1 cannot be copied or pickled")
        state = self.__dict__.copy()
        del state["_memo"]
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._memo = _Memo()

    def _new_exchange(self, context: ssl.SSLContext | None) -> HttpsExchange:
        """A pooled exchange over *context* (None: the exchange builds its own)."""
        return HttpsExchange(self.route.host, self.route.path, port=self.route.port,
                             context=context)

    def _checkout(self, timeout: float) -> tuple[HttpsExchange, Deadline]:
        """The exchange for one call and the deadline of its send.

        At 1 the exchange is the provider's own and its deadline starts now,
        as before. Pooled, ``timeout`` bounds only the wait for a free
        exchange (a wait that ends at the limit raises ``deadline_exceeded``,
        nothing sent). The send's deadline starts when the exchange is taken
        and is the full ``timeout``, as plan invariant 7 has it. An exchange
        taken is given back if the deadline cannot be taken.
        """
        if self._pool is None:
            assert self._exchange is not None
            return self._exchange, self._exchange.deadline(timeout)
        exchange = self._pool.acquire(self._pool.clock() + timeout)
        if exchange is None:
            raise _unsent_deadline()
        try:
            return exchange, exchange.deadline(timeout)
        except BaseException:
            self._pool.release(exchange)
            raise

    def _checkin(self, exchange: HttpsExchange) -> None:
        if self._pool is not None:
            self._pool.release(exchange)

    @property
    def request_limits(self) -> tuple[int, int]:
        """(max questions, max envelope bytes) for a request whose policy
        sits in state; the model's ordinary caps unless this provider was
        built with ``policy_placement="state"`` (ADR-5(5))."""
        return self.model_spec.limits(self.policy_placement)

    def payload_limits(self, payload: bytes) -> tuple[int, int]:
        """The caps that apply to one local envelope."""
        if type(payload) is bytes and payload.startswith(_PLACED_PAYLOAD):
            return self.request_limits
        return self.model_spec.limits()

    # -- subclass hooks ----------------------------------------------------
    def encode(self, payload: bytes,
               max_questions: int = MAX_QUESTIONS) -> tuple[bytes, dict[str, Any]]:
        """Local envelope bytes -> (wire body, expected questions)."""
        raise NotImplementedError

    def extra_headers(self) -> dict[str, str]:
        return {}

    def decode(self, raw: bytes, questions: Mapping[str, Any],
               outcome: Outcome) -> ProviderResponse:
        raise NotImplementedError

    def status_error(self, status: int, error: dict[str, Any] | None,
                     outcome: Outcome) -> tuple[str, dict[str, Any]]:
        """Fixed code and receipt-only error fields of a non-200 status."""
        raise NotImplementedError

    def header_ids(self, outcome: Outcome) -> dict[str, Any]:
        return {}

    # -- DecisionProvider --------------------------------------------------
    def require_available(self) -> None:
        if self._api_key is None:
            raise ProviderError("provider_unavailable")

    def check_sensitive(self, *values: Any) -> None:
        """Reject any configured provider credential anywhere in local data."""
        for credential in self._credentials:
            if _secret_in(credential, values):
                raise ProviderError("sensitive_input")

    def decide(self, request: ProviderRequest) -> ProviderResponse:
        refused: str | None = None
        try:
            body, questions, headers, timeout = self._prepare(request)
        except ProviderError as exc:
            # Refused before any byte left this process.
            refused = exc.code
        if refused is not None:
            raise ProviderError(refused, classification=classify(refused, submission="not_sent"))
        wire_sha256 = hashlib.sha256(body).hexdigest()
        failure: ExchangeError | None = None
        rejected: ProviderError | None = None
        outcome: Outcome | None = None
        # Taken only after every local refusal above, so the wait for an idle
        # exchange (pooled use) is never spent on a request that cannot go out.
        # The checkout is inside the try: a shared TLS context that cannot be
        # built is then classified like any connect failure, and an exchange
        # taken is given back by the finally. Residual: a KeyboardInterrupt in
        # the few bytecodes between _checkout returning and the store below
        # leaves that one exchange busy with no owner, and the pool serves one
        # fewer call at a time for good. Closing that window needs owner
        # tracking, which is not worth its cost here.
        exchange: HttpsExchange | None = None
        try:
            exchange, deadline = self._checkout(timeout)
            try:
                outcome = exchange.post(body, headers, deadline, read_errors=True,
                                        credentials=self._credentials)
            except ExchangeError as exc:
                failure = exc
            except ProviderError as exc:
                rejected = exc
        except ExchangeError as exc:
            failure = exc
        finally:
            if exchange is not None:
                self._checkin(exchange)
        if failure is not None:
            # Raised outside the handler: no exception text or context is attached.
            classification = transport_failure(failure)
            raise ProviderError(classification.code, classification=classification,
                                info={"wire_sha256": wire_sha256, "phase": failure.phase,
                                      "reused": failure.reused})
        if rejected is not None:
            # A 200 whose framing, type or size failed: the request may have
            # been billed, so its identifiers are journaled like any other.
            partial = getattr(rejected, "outcome", None)
            ids = self.header_ids(partial) if isinstance(partial, Outcome) else {}
            raise ProviderError(rejected.code, classification=rejected.classification,
                                info={**(rejected.info or {}), "wire_sha256": wire_sha256,
                                      **ids})
        assert outcome is not None
        details: dict[str, Any] = {"wire_sha256": wire_sha256, **self.header_ids(outcome)}
        if outcome.status != 200:
            code, fields = self.status_error(outcome.status, error_object(outcome.error_raw),
                                             outcome)
            base = classify(code)
            retry_after = None
            if base.submission in {"rejected_unprocessed", "not_sent"}:
                retry_after = parse_retry_after(outcome.header("retry-after"))
            classification = classify(code, retry_after=retry_after)
            info = {**details, **fields, "error_body": outcome.error_body_state}
            if retry_after is not None:
                info["retry_after_seconds"] = retry_after
            raise ProviderError(code, classification=classification, info=info)
        undecodable: ProviderError | None = None
        try:
            response = self.decode(outcome.body, questions, outcome)
        except ProviderError as exc:
            undecodable = exc
        if undecodable is not None:
            # The decoder raises only when it learned nothing else (invalid
            # JSON, a sensitive or non-object body); the attempt's
            # identifiers still belong in its receipt.
            raise ProviderError(undecodable.code, classification=undecodable.classification,
                                info={**(undecodable.info or {}), **details})
        return replace(response, provenance={**details, **(response.provenance or {})})

    def _prepare(self, request: ProviderRequest
                 ) -> tuple[bytes, dict[str, Any], dict[str, str], float]:
        # Taken before anything can refuse, so no refusal leaves a memo behind.
        memo, self._encoded = self._encoded, None
        self.require_available()
        assert self._api_key is not None
        if type(request) is not ProviderRequest:
            raise ProviderError("invalid_request")
        timeout = request.timeout_seconds
        if type(timeout) not in (int, float) or not math.isfinite(timeout):
            raise ProviderError("invalid_deadline")
        if timeout <= 0:
            raise ProviderError("deadline_exceeded")
        if type(request.payload) is not bytes:
            raise ProviderError("invalid_request")
        max_questions, max_bytes = self.payload_limits(request.payload)
        if len(request.payload) > max_bytes:
            raise ProviderError("request_too_large")
        if (memo is not None and memo[1] == max_questions
                and memo[0] == request.payload):
            # The same payload under the same limits encodes to the same bytes.
            body, questions = memo[2], memo[3]
        else:
            body, questions = self.encode(request.payload, max_questions)
        if len(questions) > max_questions:
            raise ProviderError("request_too_large")
        if any(_secret_in(credential, [body]) for credential in self._credentials):
            raise ProviderError("sensitive_input")
        headers = {"Authorization": "Bearer " + self._api_key,
                   "Content-Type": "application/json", "Accept": "application/json",
                   "Accept-Encoding": "identity", **self.extra_headers()}
        return body, questions, headers, float(timeout)

    def wire_size(self, payload: bytes) -> int | None:
        """Bytes of the wire body ``payload`` would be sent as, or None.

        Used only to bound the cost of an attempt before it is dispatched
        (ADR-9(3)); nothing is sent and no credential is involved. The encode
        is kept in the one-slot memo for the ``decide`` call that follows.
        """
        self._encoded = None
        if type(payload) is not bytes:
            return None
        max_questions = self.payload_limits(payload)[0]
        try:
            body, questions = self.encode(payload, max_questions)
        except ProviderError:
            return None
        self._encoded = (payload, max_questions, body, questions)
        return len(body)

    def close(self) -> None:
        """Close the kept-alive connection, if any; the provider stays usable.

        Pooled: every idle connection closes now, and a connection in use
        closes when its request returns (see ``_ExchangePool.close``). It
        never waits for a request, but may wait for the one-time build of the
        shared TLS context if a first ``decide`` is building it, so it may run
        while ``decide`` calls are in flight. A call still waiting for an
        exchange is not woken by it: that call ends at its own timeout, or when
        an exchange is released. Idempotent in both modes.
        """
        if self._pool is not None:
            self._pool.close()
            return
        assert self._exchange is not None
        self._exchange.close()
