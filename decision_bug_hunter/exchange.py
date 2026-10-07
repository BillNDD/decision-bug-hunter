"""Route-agnostic HTTPS exchange with an absolute deadline and safe reuse.

One ``HttpsExchange`` serves one fixed origin and path. It owns at most one
connection and one TLS context, built on first use and reused for the life of
the exchange. The context is explicit (``PROTOCOL_TLS_CLIENT``, system trust
store, TLS 1.2 minimum) and never reads ``SSLKEYLOGFILE``.

Every phase runs under one absolute ``Deadline``: connect and the TLS
handshake, ``sendall``, and every single receive (status line, headers,
chunk-size lines and body), so a trickling peer cannot extend a call beyond
it. Name resolution is bounded only by the operating system's resolver.
There is no watchdog thread, no proxy support (proxy environment variables
are ignored by design), no redirect following and no content decoding.

A connection is kept only after a complete, framing-valid 200 that did not
announce ``Connection: close`` and left no unread byte, and it is reused only
when it has been idle at most ``idle_reuse_seconds``, is not readable and has
no TLS bytes pending. Any error, non-200 or framing failure drops it.

Requests are written as bytes; ``http.client.HTTPConnection`` is never used,
so its process-wide ``debuglevel`` cannot print request headers. Responses
are parsed by ``http.client.HTTPResponse`` with ``debuglevel`` 0 over a
deadline-bounded reader. Exceptions carry structural fields only, never
exception text, header values or body bytes.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import http.client
import io
import json
import re
import select
import socket
import ssl
import sys
import time
from typing import Any

from .protocol import MAX_RESPONSE_BYTES, ProviderError, _pairs, _secret_in


Clock = Callable[[], float]
Connector = Callable[..., Any]
TlsWrap = Callable[[Any, ssl.SSLContext, str], Any]
Readable = Callable[[Any], bool]

#: Error bodies larger than this are never read (ADR-8).
ERROR_BODY_CAP = 16 * 1024
#: States of a non-200 body. ``unread`` means the caller did not ask for it.
ERROR_BODY_STATES = frozenset(
    {"unread", "absent", "ok", "oversized", "not_json", "withheld_sensitive"})
#: Response headers an ``Outcome`` may carry; every other header is dropped.
KEPT_HEADERS = frozenset({"content-type", "content-length", "transfer-encoding",
                          "content-encoding", "connection", "retry-after",
                          "x-request-id", "x-generation-id"})
_KEPT_PREFIX = "x-ratelimit-"
#: Never named, not even in ``Outcome.dropped_header_names``: the suffix of
#: Cloudflare's ``cf-ray`` value is the edge's airport code, i.e. the caller's
#: region (ADR-11(2)).
UNNAMED_HEADERS = frozenset({"cf-ray"})
_KEPT_VALUE = re.compile(r"[ -~]{0,256}")
_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
_HEADER_VALUE = re.compile(r"[ -~]{0,8192}")
_CONTENT_TYPE = re.compile(r'application/json(?:;\s*charset=(?:utf-8|"utf-8"))?')
_MASKED_KEY = re.compile(rb"sk-[A-Za-z0-9_-]*\*{3,}")
_CRITICAL = ("content-type", "content-length", "content-encoding", "transfer-encoding")
_MIN_RECV_TIMEOUT = 0.001
_READ_SIZE = 65536


class Deadline:
    """An absolute point on a monotonic clock; never extended."""

    __slots__ = ("at", "clock")

    def __init__(self, at: float, clock: Clock = time.monotonic) -> None:
        self.at = float(at)
        self.clock = clock

    @classmethod
    def after(cls, seconds: float, clock: Clock = time.monotonic) -> Deadline:
        return cls(clock() + float(seconds), clock)

    def remaining(self) -> float:
        return self.at - self.clock()

    def expired(self) -> bool:
        return self.remaining() <= 0


def make_tls_context() -> ssl.SSLContext:
    """Verified client context: system trust store, TLS 1.2+, no key log.

    Unlike ``ssl.create_default_context`` this never reads ``SSLKEYLOGFILE``.
    On Python 3.13+ it applies the same strict X.509 flags that function does.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if sys.version_info >= (3, 13):
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


@dataclass(frozen=True)
class Outcome:
    """One HTTP exchange that produced a status line and headers.

    ``body`` is the framing-checked 200 body (empty otherwise). ``error_raw``
    holds a non-200 body only in state ``ok``: JSON, within the cap, read
    within the deadline and free of every configured credential.
    """

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    error_raw: bytes | None
    error_body_state: str
    reused: bool
    elapsed: float
    late: bool = False
    bytes_sent: int = 0
    response_bytes: int = 0
    #: Lower-case names of the headers that were dropped, sorted and distinct;
    #: never their values, never ``UNNAMED_HEADERS``. Diagnostic only (the
    #: smoke runner reports them); receipts do not carry it.
    dropped_header_names: tuple[str, ...] = ()

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key == name:
                return value
        return None


class ExchangeError(Exception):
    """A transport failure with structural fields only.

    ``phase`` is ``connect`` (TCP and TLS), ``send`` or ``receive``. ``kind``
    is ``timeout``, ``reset``, ``tls``, ``protocol`` or ``os``. ``since_send``
    is the time from the end of ``sendall`` to the failure, when known.
    """

    def __init__(self, phase: str, kind: str, *, reused: bool, bytes_sent: int,
                 response_bytes: int, since_send: float | None = None) -> None:
        super().__init__(f"exchange_failed:{phase}:{kind}")
        self.phase = phase
        self.kind = kind
        self.reused = reused
        self.bytes_sent = bytes_sent
        self.response_bytes = response_bytes
        self.since_send = since_send


def _kind(error: BaseException) -> str:
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(error, (ConnectionResetError, BrokenPipeError,
                          ConnectionAbortedError, http.client.RemoteDisconnected)):
        return "reset"
    if isinstance(error, ssl.SSLError):
        return "tls"
    if isinstance(error, (http.client.HTTPException, ValueError)):
        return "protocol"
    return "os"


class _DeadlineRaw(io.RawIOBase):
    """Every receive re-arms the socket timeout to the remaining deadline."""

    def __init__(self, sock: Any, deadline: Deadline) -> None:
        self._sock = sock
        self._deadline = deadline
        self.count = 0
        self.sealed = False

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int | None:
        if self.sealed:
            # Probe only: report "no data" instead of blocking (see _close_conn).
            return None
        remaining = self._deadline.remaining()
        if remaining <= 0:
            raise TimeoutError("deadline reached")
        self._sock.settimeout(max(_MIN_RECV_TIMEOUT, remaining))
        count: int = self._sock.recv_into(buffer)
        self.count += count
        return count

    def close(self) -> None:
        # The exchange owns the socket; closing the reader never closes it.
        super().close()


class _ReaderSource:
    """What ``HTTPResponse.__init__`` calls ``makefile`` on."""

    def __init__(self, reader: io.BufferedReader) -> None:
        self._reader = reader

    def makefile(self, mode: str = "rb", *args: Any, **kwargs: Any) -> io.BufferedReader:
        return self._reader


class _Response(http.client.HTTPResponse):
    """``HTTPResponse`` that notes whether bytes were left unread at the end."""

    leftover = False

    def _close_conn(self) -> None:
        reader = self.fp
        if isinstance(reader, io.BufferedReader) and not reader.closed:
            raw = reader.raw
            if isinstance(raw, _DeadlineRaw):
                raw.sealed = True
                try:
                    self.leftover = bool(reader.peek(1))
                except (OSError, ValueError):
                    self.leftover = True
        super()._close_conn()  # type: ignore[misc]


def _default_readable(sock: Any) -> bool:
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError, TypeError):
        return True
    return bool(readable)


def _default_wrap(sock: Any, context: ssl.SSLContext, server_hostname: str) -> Any:
    return context.wrap_socket(sock, server_hostname=server_hostname)


def read_success_body(response: http.client.HTTPResponse) -> bytes:
    """Strict 200 framing: JSON only, identity encoding, bounded, exact length."""
    headers: dict[str, str] = {}
    for name, value in response.getheaders():
        name = name.lower()
        if name in _CRITICAL:
            if name in headers or "\r" in value or "\n" in value:
                raise ProviderError("response_framing")
            headers[name] = value.strip().lower()
    if not _CONTENT_TYPE.fullmatch(headers.get("content-type", "")):
        raise ProviderError("response_type")
    if headers.get("content-encoding", "identity") != "identity":
        raise ProviderError("response_type")
    length = headers.get("content-length")
    transfer = headers.get("transfer-encoding")
    if transfer is not None and (length is not None or transfer != "chunked"):
        raise ProviderError("response_framing")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,10}", length):
            raise ProviderError("response_framing")
        if int(length) > MAX_RESPONSE_BYTES:
            raise ProviderError("response_too_large")
    chunks: list[bytes] = []
    count = 0
    while True:
        chunk = response.read(min(_READ_SIZE, MAX_RESPONSE_BYTES + 1 - count))
        if not chunk:
            break
        count += len(chunk)
        if count > MAX_RESPONSE_BYTES:
            raise ProviderError("response_too_large")
        chunks.append(chunk)
    if length is not None and count != int(length):
        raise ProviderError("response_framing")
    return b"".join(chunks)


def _sensitive(raw: bytes, credentials: Iterable[str]) -> bool:
    if _MASKED_KEY.search(raw):
        return True
    return any(credential and _secret_in(credential, [raw]) for credential in credentials)


def read_error_body(response: http.client.HTTPResponse, deadline: Deadline,
                    cap: int = ERROR_BODY_CAP,
                    credentials: Iterable[str] = ()) -> tuple[bytes | None, str]:
    """A bounded, credential-checked JSON error body and its state.

    Reads only a JSON, identity-encoded body whose declared or streamed size
    stays within ``cap`` and whose bytes all arrive before ``deadline``.
    A failure while reading leaves the state ``absent``. The returned bytes
    are present only in state ``ok``.
    """
    credentials = tuple(credentials)
    content_type = (response.getheader("content-type") or "").strip().lower()
    encoding = (response.getheader("content-encoding") or "identity").strip().lower()
    if not _CONTENT_TYPE.fullmatch(content_type) or encoding != "identity":
        return None, "not_json"
    declared = (response.getheader("content-length") or "").strip()
    if declared:
        if not re.fullmatch(r"[0-9]{1,10}", declared):
            return None, "absent"
        if int(declared) > cap:
            return None, "oversized"
    chunks: list[bytes] = []
    count = 0
    try:
        while True:
            if deadline.expired():
                return None, "absent"
            chunk = response.read(min(_READ_SIZE, cap + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > cap:
                return None, "oversized"
            chunks.append(chunk)
    except (OSError, http.client.HTTPException, ValueError):
        return None, "absent"
    raw = b"".join(chunks)
    if not raw:
        return None, "absent"
    if _sensitive(raw, credentials):
        return None, "withheld_sensitive"
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except Exception:
        return None, "not_json"
    if any(credential and _secret_in(credential, [data]) for credential in credentials):
        return None, "withheld_sensitive"
    return raw, "ok"


def _kept_headers(response: http.client.HTTPResponse
                  ) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    """Allow-listed (name, value) pairs, and the sorted names of the rest."""
    kept: list[tuple[str, str]] = []
    dropped: set[str] = set()
    for name, value in response.getheaders():
        lower = name.lower()
        if ((lower in KEPT_HEADERS or lower.startswith(_KEPT_PREFIX))
                and _KEPT_VALUE.fullmatch(value)):
            kept.append((lower, value.strip()))
        elif lower not in UNNAMED_HEADERS and _HEADER_NAME.fullmatch(lower):
            dropped.add(lower)
    return tuple(kept), tuple(sorted(dropped))


class HttpsExchange:
    """POSTs to one fixed HTTPS origin and path under an absolute deadline.

    ``connect`` has the ``socket.create_connection(address, timeout)``
    signature; ``wrap(sock, context, server_hostname)`` performs the TLS
    handshake; ``readable(sock)`` reports whether an idle socket has data or
    EOF waiting. All three, and ``clock``, exist so tests can replace them.
    """

    def __init__(self, host: str, path: str, *, port: int = 443,
                 context: ssl.SSLContext | None = None,
                 connect: Connector | None = None, wrap: TlsWrap | None = None,
                 readable: Readable | None = None, clock: Clock = time.monotonic,
                 idle_reuse_seconds: float = 10.0) -> None:
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host) or not path.startswith("/"):
            raise ValueError("invalid origin")
        self.host = host
        self.path = path
        self.port = int(port)
        self.clock = clock
        self.idle_reuse_seconds = float(idle_reuse_seconds)
        self._context = context
        self._connect = connect
        self._wrap = wrap if wrap is not None else _default_wrap
        self._readable = readable if readable is not None else _default_readable
        self._sock: Any = None
        self._idle_since: float | None = None
        self.contexts_built = 0

    # -- public ------------------------------------------------------------
    @property
    def context(self) -> ssl.SSLContext:
        """The single TLS context of this exchange, built on first use."""
        if self._context is None:
            self._context = make_tls_context()
            self.contexts_built += 1
        return self._context

    def deadline(self, seconds: float) -> Deadline:
        return Deadline.after(seconds, self.clock)

    def post(self, body: bytes, headers: Mapping[str, str], deadline: Deadline, *,
             read_errors: bool = False,
             credentials: Iterable[str] = ()) -> Outcome:
        """One POST; returns an ``Outcome`` or raises ``ExchangeError``.

        200 bodies go through ``read_success_body`` (whose ``ProviderError``
        propagates unchanged). Non-200 bodies are read, through
        ``read_error_body``, only when ``read_errors`` is true. Nothing is
        retried.
        """
        request = self._request_bytes(body, headers)
        started = self.clock()
        if deadline.expired():
            raise ExchangeError("connect", "timeout", reused=False, bytes_sent=0,
                                response_bytes=0)
        sock, reused = self._take_connection()
        failure: ExchangeError | None = None
        phase = "connect"
        bytes_sent = 0
        raw: _DeadlineRaw | None = None
        sent_at: float | None = None
        response: _Response | None = None
        keep = False
        try:
            try:
                if sock is None:
                    sock = self._open(deadline)
                phase = "send"
                remaining = deadline.remaining()
                if remaining <= 0:
                    raise TimeoutError("deadline reached")
                sock.settimeout(remaining)
                sock.sendall(request)
                bytes_sent = len(request)
                sent_at = self.clock()
                phase = "receive"
                raw = _DeadlineRaw(sock, deadline)
                response = _Response(_ReaderSource(io.BufferedReader(raw)),  # type: ignore[arg-type]
                                     0, "POST")
                response.begin()
                kept, dropped = _kept_headers(response)
                if response.status == 200:
                    content = read_success_body(response)
                    error_raw: bytes | None = None
                    state = "unread"
                    keep = (response.isclosed() and not response.will_close
                            and not response.leftover)
                elif read_errors:
                    content = b""
                    error_raw, state = read_error_body(
                        response, deadline, ERROR_BODY_CAP, credentials)
                else:
                    content = b""
                    error_raw, state = None, "unread"
                now = self.clock()
                return Outcome(response.status, kept, content, error_raw, state, reused,
                               max(0.0, now - started), late=now >= deadline.at,
                               bytes_sent=bytes_sent, response_bytes=raw.count,
                               dropped_header_names=dropped)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                since = None if sent_at is None else max(0.0, self.clock() - sent_at)
                failure = ExchangeError(phase, _kind(exc), reused=reused,
                                        bytes_sent=bytes_sent,
                                        response_bytes=0 if raw is None else raw.count,
                                        since_send=since)
        finally:
            if response is not None:
                # Release the reader now rather than in a finalizer, which on
                # some versions flushes a reader already closed by the GC.
                try:
                    response.close()
                except Exception:
                    pass
            if keep and sock is not None:
                self._sock = sock
                self._idle_since = self.clock()
            elif sock is not None:
                _close_quietly(sock)
        # Raised outside the handler: no exception text or context is attached.
        assert failure is not None
        raise failure

    def close(self) -> None:
        sock, self._sock, self._idle_since = self._sock, None, None
        if sock is not None:
            _close_quietly(sock)

    # -- internals ---------------------------------------------------------
    def _request_bytes(self, body: bytes, headers: Mapping[str, str]) -> bytes:
        if type(body) is not bytes:
            raise ProviderError("invalid_request")
        lines = [f"POST {self.path} HTTP/1.1",
                 "Host: " + (self.host if self.port == 443 else f"{self.host}:{self.port}")]
        seen = {"host", "content-length"}
        for name, value in headers.items():
            lower = name.lower()
            if (not _HEADER_NAME.fullmatch(name) or type(value) is not str
                    or not _HEADER_VALUE.fullmatch(value) or lower in seen):
                raise ProviderError("invalid_request")
            seen.add(lower)
            lines.append(f"{name}: {value}")
        lines.append(f"Content-Length: {len(body)}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body

    def _take_connection(self) -> tuple[Any, bool]:
        sock, idle_since = self._sock, self._idle_since
        self._sock, self._idle_since = None, None
        if sock is None:
            return None, False
        usable = (idle_since is not None
                  and self.clock() - idle_since <= self.idle_reuse_seconds)
        if usable:
            pending = getattr(sock, "pending", None)
            try:
                usable = not self._readable(sock) and (pending is None or pending() == 0)
            except (OSError, ValueError):
                usable = False
        if not usable:
            _close_quietly(sock)
            return None, False
        return sock, True

    def _open(self, deadline: Deadline) -> Any:
        remaining = deadline.remaining()
        if remaining <= 0:
            raise TimeoutError("deadline reached")
        connect = self._connect if self._connect is not None else socket.create_connection
        raw = connect((self.host, self.port), remaining)
        try:
            remaining = deadline.remaining()
            if remaining <= 0:
                raise TimeoutError("deadline reached")
            raw.settimeout(remaining)
            return self._wrap(raw, self.context, self.host)
        except BaseException:
            _close_quietly(raw)
            raise


def _close_quietly(sock: Any) -> None:
    try:
        sock.close()
    except Exception:
        pass
