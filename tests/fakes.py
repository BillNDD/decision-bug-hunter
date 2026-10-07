"""Scripted transport, clock, sleep and rng fakes for the offline suite.

Nothing here opens a socket. ``ScriptedHTTPS`` is an injected connector with
the ``socket.create_connection(address, timeout, source_address)`` signature
that hands out ``FakeSocket`` objects. Each socket parses the HTTP requests
written to it and replays the next scripted step: response bytes, fake-clock
delays, mid-body exceptions, connect and send failures, or silence. The real
``http.client`` parser runs over the scripted bytes, either through a future
exchange that accepts ``connect=`` or through ``ScriptedHTTPS.https_connection``,
a drop-in for ``http.client.HTTPSConnection`` that skips TLS.

Delays only advance the ``FakeClock``; no test sleeps on the wall clock. A
delay longer than the socket's current timeout raises ``TimeoutError`` after
advancing the clock by that timeout, as a blocking socket would, and the rest
of the delay remains, so a trickling body defeats per-operation timeouts
exactly as it does on a real connection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import io
import random
from typing import Any, Iterable, Sequence, Union


class FakeClock:
    """A monotonic clock that moves only when told to."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise AssertionError("a monotonic clock cannot move backwards")
        self.now += seconds


class FakeSleep:
    """Records each requested wait and advances the clock instead of sleeping."""

    def __init__(self, clock: FakeClock | None = None) -> None:
        self.clock = clock if clock is not None else FakeClock()
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("sleep length must be non-negative")
        self.calls.append(seconds)
        self.clock.advance(seconds)

    @property
    def total(self) -> float:
        return sum(self.calls)


def seeded_rng(seed: int = 0) -> random.Random:
    """A private, reproducible generator; never the shared module state."""
    return random.Random(seed)


@dataclass(frozen=True)
class Delay:
    """Advance the fake clock before the next byte is available."""
    seconds: float


@dataclass(frozen=True)
class Raise:
    """Raise this exception from the read that reaches this point."""
    error: BaseException


Event = Union[bytes, Delay, Raise]


@dataclass
class Reply:
    """One scripted HTTP response.

    ``headers=None`` sends ``Content-Type: application/json`` with an exact
    ``Content-Length`` (or ``Transfer-Encoding: chunked`` when ``chunked``).
    ``chunk_size`` splits the delivered body into reads of that size, with
    ``delay_between`` seconds before each later piece. ``fail_after`` raises
    ``fail_with`` once that many body bytes have been delivered.
    ``events`` replaces all generated wire events for full control.
    ``close_after`` makes the peer close once the reply is drained; otherwise
    the connection stays open and a further read blocks until it times out.
    """
    status: int = 200
    body: bytes = b"{}"
    headers: Sequence[tuple[str, str]] | None = None
    reason: str = "Scripted"
    chunked: bool = False
    chunk_size: int | None = None
    delay_before: float = 0.0
    delay_between: float = 0.0
    fail_after: int | None = None
    fail_with: BaseException | None = None
    close_after: bool = False
    events: Sequence[Event] | None = None

    def wire_events(self) -> list[Event]:
        if self.events is not None:
            return list(self.events)
        if self.headers is None:
            headers: list[tuple[str, str]] = [("Content-Type", "application/json")]
            if self.chunked:
                headers.append(("Transfer-Encoding", "chunked"))
            else:
                headers.append(("Content-Length", str(len(self.body))))
        else:
            headers = list(self.headers)
        head = f"HTTP/1.1 {self.status} {self.reason}\r\n".encode("latin-1")
        head += b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in headers) + b"\r\n"
        size = self.chunk_size or max(1, len(self.body))
        pieces = [self.body[i:i + size] for i in range(0, len(self.body), size)]
        events: list[Event] = []
        if self.delay_before:
            events.append(Delay(self.delay_before))
        events.append(head)
        delivered = 0
        for index, piece in enumerate(pieces):
            if index and self.delay_between:
                events.append(Delay(self.delay_between))
            if self.fail_after is not None and delivered + len(piece) > self.fail_after:
                cut = self.fail_after - delivered
                events.append(_frame(piece[:cut], self.chunked))
                events.append(Raise(self.fail_with or ConnectionResetError("scripted reset")))
                return events
            events.append(_frame(piece, self.chunked))
            delivered += len(piece)
        if self.fail_after is not None:
            events.append(Raise(self.fail_with or ConnectionResetError("scripted reset")))
            return events
        if self.chunked:
            events.append(b"0\r\n\r\n")
        return events


def _frame(piece: bytes, chunked: bool) -> bytes:
    if not chunked or not piece:
        return piece
    return f"{len(piece):x}\r\n".encode("ascii") + piece + b"\r\n"


@dataclass
class ConnectFailure:
    """Consumed by the next connect attempt, which raises ``error``."""
    error: BaseException = field(default_factory=lambda: ConnectionRefusedError("scripted"))
    delay: float = 0.0


@dataclass
class SendFailure:
    """Consumed by the next complete request, whose final send raises ``error``."""
    error: BaseException = field(default_factory=lambda: BrokenPipeError("scripted"))


@dataclass
class Silence:
    """The request is received and no byte ever comes back."""


Step = Union[Reply, ConnectFailure, SendFailure, Silence]


@dataclass
class RecordedRequest:
    connection: int
    method: str
    target: str
    headers: list[tuple[str, str]]
    body: bytes
    sent_at: float

    def header(self, name: str) -> str | None:
        values = [v for k, v in self.headers if k.lower() == name.lower()]
        if len(values) > 1:
            raise AssertionError(f"header {name} sent more than once")
        return values[0] if values else None


class _Raw(io.RawIOBase):
    def __init__(self, sock: FakeSocket) -> None:
        self._sock = sock

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        return self._sock.recv_into(buffer)


class FakeSocket:
    """A connected socket whose peer is the script. Never touches the OS."""

    def __init__(self, script: ScriptedHTTPS, index: int, address: tuple[str, int],
                 timeout: float | None) -> None:
        self.script = script
        self.index = index
        self.address = address
        self.timeout = timeout
        self.timeouts: list[float | None] = []
        self.sent = bytearray()
        self.closed = False
        self.peer_closed = False
        self._pending = bytearray()
        self._events: list[Event] = []
        self._requests_served = 0

    # -- socket surface used by http.client and an exchange ------------------
    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)
        self.script.settimeout_calls.append((self.index, value))
        self.timeout = value

    def gettimeout(self) -> float | None:
        return self.timeout

    def setsockopt(self, *args: Any) -> None:
        return None

    def fileno(self) -> int:
        return -1

    def pending(self) -> int:
        """``ssl.SSLSocket.pending``: decrypted bytes buffered locally."""
        return 0

    def readable_idle(self) -> bool:
        """What ``select([fd], [], [], 0)`` would say about an idle socket."""
        return bool(self._events) or self.peer_closed

    def sendall(self, data: bytes) -> None:
        self._check_open()
        self.sent += data
        self._pending += data
        self._dispatch_complete_requests()

    def send(self, data: bytes) -> int:
        self.sendall(data)
        return len(data)

    def makefile(self, mode: str = "rb", buffering: int | None = None) -> io.BufferedReader:
        if "b" not in mode or "r" not in mode:
            raise AssertionError(f"unsupported makefile mode {mode!r}")
        return io.BufferedReader(_Raw(self))

    def recv(self, size: int) -> bytes:
        buffer = bytearray(size)
        count = self.recv_into(buffer)
        return bytes(buffer[:count])

    def recv_into(self, buffer: Any, nbytes: int = 0) -> int:
        self._check_open()
        view = memoryview(buffer)
        limit = nbytes or len(view)
        while True:
            if not self._events:
                if self.peer_closed:
                    return 0
                self._block_forever()
            event = self._events[0]
            if isinstance(event, Delay):
                self._wait(event)
                continue
            if isinstance(event, Raise):
                self._events.pop(0)
                self.script.raised.append((self.index, event.error))
                raise event.error
            if not event:
                self._events.pop(0)
                continue
            piece = event[:limit]
            rest = event[limit:]
            if rest:
                self._events[0] = rest
            else:
                self._events.pop(0)
            view[:len(piece)] = piece
            return len(piece)

    def shutdown(self, how: int) -> None:
        return None

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.script.closed.append(self.index)

    # -- internals -----------------------------------------------------------
    def _check_open(self) -> None:
        if self.closed:
            raise OSError("scripted socket is closed")

    def _wait(self, delay: Delay) -> None:
        if self.timeout is not None and delay.seconds > self.timeout:
            self.script.clock.advance(self.timeout)
            self._events[0] = Delay(delay.seconds - self.timeout)
            raise TimeoutError("timed out")
        self.script.clock.advance(delay.seconds)
        self._events.pop(0)

    def _block_forever(self) -> None:
        if self.timeout is None:
            raise AssertionError("scripted peer is silent and the read has no timeout")
        self.script.clock.advance(self.timeout)
        raise TimeoutError("timed out")

    def _dispatch_complete_requests(self) -> None:
        while True:
            end = self._pending.find(b"\r\n\r\n")
            if end < 0:
                return
            head = bytes(self._pending[:end]).decode("latin-1").split("\r\n")
            method, target, _version = head[0].split(" ", 2)
            headers: list[tuple[str, str]] = []
            for line in head[1:]:
                name, _, value = line.partition(":")
                headers.append((name.strip(), value.strip()))
            lengths = [v for k, v in headers if k.lower() == "content-length"]
            length = int(lengths[0]) if lengths else 0
            if len(self._pending) < end + 4 + length:
                return
            body = bytes(self._pending[end + 4:end + 4 + length])
            del self._pending[:end + 4 + length]
            self.script.requests.append(RecordedRequest(
                self.index, method, target, headers, body, self.script.clock.now))
            self._requests_served += 1
            step = self.script._next_step("request")
            if isinstance(step, SendFailure):
                raise step.error
            if isinstance(step, Silence):
                continue
            if not isinstance(step, Reply):
                raise AssertionError(f"script expected a connect, got a request: {step!r}")
            if self._events:
                raise AssertionError("a new request arrived before the last reply was read")
            self._events = step.wire_events()
            if step.close_after:
                self.peer_closed = True


class ScriptedHTTPS:
    """Injected connector replaying ``steps`` in order across all connections.

    Records every connect (``connects``), complete request (``requests``),
    ``settimeout`` call (``settimeout_calls``), raised scripted exception and
    closed socket. ``reuse_count`` is the number of requests that travelled
    on an already-used connection.
    """

    def __init__(self, steps: Iterable[Step], *, clock: FakeClock | None = None,
                 host: str | None = None, port: int = 443) -> None:
        self.steps: list[Step] = list(steps)
        self.clock = clock if clock is not None else FakeClock()
        self.expected_address = None if host is None else (host, port)
        self.connects: list[tuple[tuple[str, int], float | None]] = []
        self.sockets: list[FakeSocket] = []
        self.requests: list[RecordedRequest] = []
        self.settimeout_calls: list[tuple[int, float | None]] = []
        self.raised: list[tuple[int, BaseException]] = []
        self.closed: list[int] = []
        self.contexts: list[Any] = []

    def __call__(self, address: tuple[str, int], timeout: float | None = None,
                 source_address: Any = None) -> FakeSocket:
        return self.connect(address, timeout, source_address)

    def connect(self, address: tuple[str, int], timeout: float | None = None,
                source_address: Any = None) -> FakeSocket:
        address = (address[0], int(address[1]))
        if self.expected_address is not None and address != self.expected_address:
            raise AssertionError(f"unexpected origin {address!r}")
        self.connects.append((address, timeout))
        if self.steps and isinstance(self.steps[0], ConnectFailure):
            failure = self.steps.pop(0)
            assert isinstance(failure, ConnectFailure)
            if timeout is not None and failure.delay > timeout:
                self.clock.advance(timeout)
                raise TimeoutError("timed out")
            self.clock.advance(failure.delay)
            raise failure.error
        sock = FakeSocket(self, len(self.sockets), address, timeout)
        self.sockets.append(sock)
        return sock

    def https_connection(self, host: str, port: int | None = None, *,
                         timeout: Any = None, context: Any = None,
                         **kwargs: Any) -> http.client.HTTPConnection:
        """Drop-in for ``http.client.HTTPSConnection``: same parser, no TLS."""
        self.contexts.append(context)
        if timeout is None:
            return _ScriptedConnection(self, host, port)
        return _ScriptedConnection(self, host, port, timeout=timeout)

    @property
    def reuse_count(self) -> int:
        return len(self.requests) - len({r.connection for r in self.requests})

    @property
    def exhausted(self) -> bool:
        return not self.steps

    def _next_step(self, kind: str) -> Step:
        if not self.steps:
            raise AssertionError(f"unscripted {kind}")
        return self.steps.pop(0)


class _ScriptedConnection(http.client.HTTPConnection):
    default_port = 443

    def __init__(self, script: ScriptedHTTPS, host: str, port: int | None = None,
                 **kwargs: Any) -> None:
        super().__init__(host, port, **kwargs)
        self._create_connection = script.connect
