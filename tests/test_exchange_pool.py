"""The exchange pool behind ``HostedProvider(max_connections=N)``.

No socket is opened. ``hosted.HttpsExchange`` is replaced either by a
thread-safe fake that records every use, or by the real class with a fake
connector and a no-op TLS wrap. The tests check what the pool does: how many
exchanges exist, whether two threads ever share one, which response reaches
which caller, how many TLS contexts are built, how a caller's timeout bounds
the wait for an exchange, what a failure looks like at each pool size, and
what happens to connections on ``close``. The bytes the N=1 provider sends
are checked against literal digests recorded from commit f6be9b8, before the
pool existed, not against the encoder under test.
"""
from __future__ import annotations

import copy
import hashlib
import pickle
import re
import ssl
import threading
import time
import unittest
from unittest.mock import patch

from decision_bug_hunter import exchange as exchange_module
from decision_bug_hunter import hosted
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.exchange import ExchangeError, HttpsExchange as RealExchange, Outcome
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import QUESTION, ProviderError, encode_request
from decision_bug_hunter.providers import ProviderRequest, ProviderResponse, classify


KEY = "offline-sentinel-credential-7c2e"
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
MARKER = re.compile(r"t\d+-\d+\.txt")

#: The OpenAI route's wire body for STATE and QUESTIONS, and the full request
#: bytes for the fixed header set below; recorded from the base checkout.
BODY_LENGTH = 1249
BODY_SHA256 = "7429c1ddb51323b1a1f84075fa59536f7b6be10caa6ada3b2d2ace43ca29dc9e"
REQUEST_LENGTH = 1465
REQUEST_SHA256 = "a729b0cf68f7ca28334efa5067cefde2a33fe0b87e25403d05ec896947a9ecab"
ROUTE_HOST = "api.openai.com"
ROUTE_PATH = "/v1/decisions"
EXPECTED_HEADERS = {"Authorization": "Bearer " + KEY, "Content-Type": "application/json",
                    "Accept": "application/json", "Accept-Encoding": "identity"}


class Ledger:
    """Shared, lock-protected record of everything the fake exchanges did."""

    def __init__(self, *, latency: float = 0.002, first_wave: int = 0) -> None:
        self.lock = threading.Lock()
        self.exchanges: list[FakeExchange] = []
        self.contexts_made = 0
        self.posts = 0
        self.in_flight = 0
        self.max_in_flight = 0
        self.violations: list[int] = []
        self.bodies: list[bytes] = []
        self.headers: list[dict[str, str]] = []
        self.deadlines: list[float] = []
        self.raise_next: list[BaseException] = []
        self.deadline_raise: list[BaseException] = []
        self.latency = latency
        self.arrivals = 0
        self.first_wave = first_wave
        self.gate = threading.Barrier(first_wave, timeout=10) if first_wave else None

    def build_context(self) -> object:
        """Stands in for one ``ssl.SSLContext``; counted, never used."""
        with self.lock:
            self.contexts_made += 1
            return object()

    def factory(self, host: str, path: str, *, port: int = 443,
                context: object = None) -> FakeExchange:
        """Replaces ``hosted.HttpsExchange``; same keyword arguments."""
        exchange = FakeExchange(self, host, path, port=port, context=context)
        with self.lock:
            self.exchanges.append(exchange)
        return exchange


class FakeExchange:
    """One pooled exchange: echoes the request body as the response body."""

    def __init__(self, ledger: Ledger, host: str, path: str, *, port: int,
                 context: object) -> None:
        self.ledger = ledger
        self.host = host
        self.path = path
        self.port = port
        self._context = context
        self.contexts_built = 0
        self.connected = False
        self.close_calls = 0
        self._busy = False

    @property
    def context(self) -> object:
        if self._context is None:
            self._context = self.ledger.build_context()
            self.contexts_built += 1
        return self._context

    def deadline(self, seconds: float) -> float:
        with self.ledger.lock:
            self.ledger.deadlines.append(float(seconds))
            failing = self.ledger.deadline_raise.pop(0) if self.ledger.deadline_raise else None
        if failing is not None:
            raise failing
        return float(seconds)

    def post(self, body: bytes, headers: object, deadline: object, *,
             read_errors: bool = False, credentials: object = ()) -> Outcome:
        ledger = self.ledger
        with ledger.lock:
            if self._busy:
                ledger.violations.append(id(self))
            self._busy = True
            ledger.posts += 1
            ledger.in_flight += 1
            ledger.max_in_flight = max(ledger.max_in_flight, ledger.in_flight)
            ledger.bodies.append(body)
            ledger.headers.append(dict(headers))  # type: ignore[call-overload]
            ledger.arrivals += 1
            held = ledger.gate is not None and ledger.arrivals <= ledger.first_wave
            failing = ledger.raise_next.pop(0) if ledger.raise_next else None
        try:
            if failing is not None:
                raise failing
            if held:
                ledger.gate.wait()
            time.sleep(ledger.latency)
        finally:
            with ledger.lock:
                self._busy = False
                ledger.in_flight -= 1
                self.connected = True
        return Outcome(200, (), body, None, "unread", False, 0.0)

    def close(self) -> None:
        with self.ledger.lock:
            self.close_calls += 1
            self.connected = False


class DummySocket:
    """Accepts the socket calls the exchange makes before the TLS wrap."""

    def setsockopt(self, *args: object) -> None:
        pass

    def settimeout(self, value: float) -> None:
        pass

    def close(self) -> None:
        pass


def dummy_connect(address: object, timeout: float) -> DummySocket:
    return DummySocket()


def dummy_wrap(sock: object, context: object, server_hostname: str) -> object:
    return sock


def real_factory(host: str, path: str, *, port: int = 443,
                 context: object = None) -> RealExchange:
    """The real ``HttpsExchange`` with a fake connector: no socket is opened."""
    return RealExchange(host, path, port=port, context=context,
                        connect=dummy_connect, wrap=dummy_wrap)  # type: ignore[arg-type]


class EchoDecisions(DecisionsProvider):
    """The OpenAI route with the response decoded as its own raw text."""

    def decode(self, raw: bytes, questions: object, outcome: Outcome) -> ProviderResponse:
        return ProviderResponse({"echo": raw.decode("utf-8")}, None)


class InterruptOnce(set):  # type: ignore[type-arg]
    """A busy set whose first ``add`` is interrupted, as a Ctrl-C would be."""

    armed = True

    def add(self, item: object) -> None:
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt
        super().add(item)  # type: ignore[arg-type]


class InterruptOnDiscard(set):  # type: ignore[type-arg]
    """A busy set whose first ``discard`` is interrupted before it removes anything."""

    armed = True

    def discard(self, item: object) -> None:
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt
        super().discard(item)  # type: ignore[arg-type]


class InterruptOnPop(list):  # type: ignore[type-arg]
    """An idle list whose first ``pop`` removes the item and then is interrupted."""

    armed = True

    def pop(self, index: int = -1) -> object:
        item = super().pop(index)
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt
        return item


class InterruptOnContains(set):  # type: ignore[type-arg]
    """A retiring set whose first membership test is interrupted, as a Ctrl-C would be."""

    armed = True

    def __contains__(self, item: object) -> bool:
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt
        return super().__contains__(item)


def request_for(name: str, timeout: float = 30.0) -> ProviderRequest:
    state = dict(STATE, file=name)
    return ProviderRequest(encode_request(state, QUESTIONS), timeout)


def take(pool: hosted._ExchangePool) -> object:
    exchange = pool.acquire(time.monotonic() + 30)
    assert exchange is not None
    return exchange


def single_pool(ledger: Ledger) -> hosted._ExchangePool:
    """A pool of one exchange built by the ledger's fake factory."""
    return hosted._ExchangePool(
        lambda context: ledger.factory(ROUTE_HOST, ROUTE_PATH, context=context), 1)


class PoolTests(unittest.TestCase):
    def test_eight_threads_share_four_exchanges_and_one_context(self):
        ledger = Ledger(latency=0.002, first_wave=4)
        provider = EchoDecisions(KEY, environ={}, max_connections=4)
        results: dict[tuple[int, int], str] = {}
        errors: list[BaseException] = []
        barrier = threading.Barrier(8, timeout=10)

        def worker(index: int) -> None:
            try:
                barrier.wait()
                for call in range(5):
                    response = provider.decide(request_for(f"t{index}-{call}.txt"))
                    results[(index, call)] = response.answers["echo"]
            except BaseException as exc:  # reported by the assertions below
                errors.append(exc)

        with patch.object(hosted, "HttpsExchange", ledger.factory):
            threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(60)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(ledger.posts, 40)
        self.assertEqual(len(ledger.exchanges), 4)
        self.assertEqual(ledger.max_in_flight, 4)
        self.assertEqual(ledger.violations, [])
        self.assertEqual(ledger.contexts_made, 1)
        self.assertEqual(sum(exchange.contexts_built for exchange in ledger.exchanges), 1)
        self.assertEqual(len({id(exchange.context) for exchange in ledger.exchanges}), 1)
        self.assertEqual(len(results), 40)
        for (index, call), echo in results.items():
            with self.subTest(thread=index, call=call):
                self.assertEqual(MARKER.findall(echo), [f"t{index}-{call}.txt"])

    def test_single_connection_sends_the_pristine_bytes(self):
        ledger = Ledger(latency=0.0)
        payload = encode_request(STATE, QUESTIONS)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            default = EchoDecisions(KEY, environ={})
            explicit = EchoDecisions(KEY, environ={}, max_connections=1)
            self.assertIsNone(default._pool)
            self.assertIsNone(explicit._pool)
            for provider in (default, explicit):
                with self.subTest(provider=provider is explicit):
                    for _ in range(2):
                        provider.decide(ProviderRequest(payload, 30.0))
        exchanges = ledger.exchanges
        self.assertEqual(len(exchanges), 2)
        self.assertIsNot(exchanges[0], exchanges[1])
        self.assertEqual(ledger.posts, 4)
        self.assertEqual(ledger.violations, [])
        self.assertIs(default._exchange, exchanges[0])
        self.assertIs(explicit._exchange, exchanges[1])
        for body, headers in zip(ledger.bodies, ledger.headers):
            self.assertEqual(len(body), BODY_LENGTH)
            self.assertEqual(hashlib.sha256(body).hexdigest(), BODY_SHA256)
            self.assertEqual(headers, EXPECTED_HEADERS)
            request = RealExchange(ROUTE_HOST, ROUTE_PATH)._request_bytes(body, headers)
            self.assertEqual(len(request), REQUEST_LENGTH)
            self.assertEqual(hashlib.sha256(request).hexdigest(), REQUEST_SHA256)

    def test_memo_is_per_thread(self):
        provider = EchoDecisions(KEY, environ={})
        payload = encode_request(STATE, QUESTIONS)
        encodes: list[int] = []
        original = provider.encode

        def counting(payload_bytes: bytes, max_questions: int = 64) -> object:
            encodes.append(1)
            return original(payload_bytes, max_questions)

        provider.encode = counting
        expected = original(payload, provider.payload_limits(payload)[0])[0]
        planted = threading.Event()
        b_done = threading.Event()
        results: dict[str, bytes] = {}

        def thread_a() -> None:
            provider.wire_size(payload)
            stored = provider._encoded
            assert stored is not None
            provider._encoded = (stored[0], stored[1], b"POISON", stored[3], stored[4])
            planted.set()
            b_done.wait(10)
            results["a"] = provider._prepare(ProviderRequest(payload, 30.0))[0]

        def thread_b() -> None:
            planted.wait(10)
            results["b"] = provider._prepare(ProviderRequest(payload, 30.0))[0]
            b_done.set()

        threads = [threading.Thread(target=thread_a), threading.Thread(target=thread_b)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(results["b"], expected)
        self.assertEqual(results["a"], b"POISON")
        self.assertEqual(len(encodes), 2)
        self.assertIsNone(provider._encoded)

    def test_close_closes_idle_and_retires_busy_exchanges(self):
        ledger = Ledger(latency=0.0)
        provider = EchoDecisions(KEY, environ={}, max_connections=2)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            pool = provider._pool
            assert pool is not None
            busy = take(pool)
            idle = take(pool)
            pool.release(idle)
            busy.connected = idle.connected = True
            provider.close()
            self.assertEqual((idle.close_calls, busy.close_calls), (1, 0))
            pool.release(busy)
            self.assertEqual(busy.close_calls, 1)
            self.assertFalse(busy.connected)
            provider.close()
            provider.close()
            self.assertFalse(idle.connected)
            response = provider.decide(request_for("t0-0.txt"))
            self.assertEqual(MARKER.findall(response.answers["echo"]), ["t0-0.txt"])
            self.assertEqual(len(ledger.exchanges), 2)

    def test_close_during_a_call_retires_the_busy_exchange(self):
        ledger = Ledger(latency=0.3)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            result: dict[str, ProviderResponse] = {}
            thread = threading.Thread(
                target=lambda: result.update(response=provider.decide(request_for("t0-0.txt"))))
            thread.start()
            stop = time.monotonic() + 10
            while ledger.in_flight == 0 and time.monotonic() < stop:
                time.sleep(0.005)
            self.assertEqual(ledger.in_flight, 1)
            provider.close()
            busy = ledger.exchanges[0]
            self.assertEqual(busy.close_calls, 0)
            thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(busy.close_calls, 1)
            self.assertFalse(busy.connected)
            self.assertEqual(MARKER.findall(result["response"].answers["echo"]), ["t0-0.txt"])
            provider.close()

    def test_close_on_a_provider_that_never_dispatched_is_quiet(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=3)
            provider.close()
            provider.close()
        self.assertEqual(ledger.exchanges, [])
        self.assertEqual(ledger.contexts_made, 0)

    def test_invalid_max_connections_is_refused(self):
        for route in (DecisionsProvider, OpenRouterProvider):
            for value in (0, 9, -1, True, False, 2.0, "4", None, 1.0):
                with self.subTest(route=route.__name__, value=value):
                    with self.assertRaises(ProviderError) as caught:
                        route(KEY, environ={}, max_connections=value)
                    self.assertEqual(caught.exception.code, "invalid_request")

    def test_valid_bounds_and_injected_exchange_rule(self):
        for value in (1, 2, 8):
            with self.subTest(value=value):
                provider = DecisionsProvider(KEY, environ={}, max_connections=value)
                self.assertEqual(provider._pool is None, value == 1)
        with self.assertRaises(ProviderError) as caught:
            DecisionsProvider(KEY, environ={}, exchange=object(), max_connections=2)
        self.assertEqual(caught.exception.code, "invalid_request")


class TimeoutTests(unittest.TestCase):
    def test_saturated_pool_bounds_the_wait_by_the_timeout(self):
        ledger = Ledger(latency=0.0)
        outcome: dict[str, BaseException] = {}
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            held = [take(pool), take(pool)]

            def caller() -> None:
                try:
                    provider.decide(request_for("t0-0.txt", timeout=0.2))
                except BaseException as exc:  # asserted below
                    outcome["error"] = exc

            # On a daemon thread with a bounded join: a wait that lost its bound
            # fails this test instead of hanging the module.
            thread = threading.Thread(target=caller, daemon=True)
            started = time.monotonic()
            thread.start()
            thread.join(5)
            finished = not thread.is_alive()
            elapsed = time.monotonic() - started
            for exchange in held:
                pool.release(exchange)
            thread.join(5)
            self.assertTrue(finished)
            error = outcome.get("error")
            assert isinstance(error, ProviderError)
            self.assertEqual(error.code, "deadline_exceeded")
            self.assertEqual(error.classification,
                             classify("deadline_exceeded", submission="not_sent"))
            self.assertGreaterEqual(elapsed, 0.15)
            self.assertLess(elapsed, 2.0)
            self.assertEqual(ledger.posts, 0)
            self.assertEqual(len(ledger.exchanges), 2)
            response = provider.decide(request_for("t0-0.txt"))
            self.assertEqual(MARKER.findall(response.answers["echo"]), ["t0-0.txt"])
            self.assertEqual(pool._busy, set())

    def test_send_gets_the_full_timeout_after_a_wait(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            both_held = threading.Event()

            def holder() -> None:
                held = [take(pool), take(pool)]
                both_held.set()
                time.sleep(0.3)
                for exchange in held:
                    pool.release(exchange)

            thread = threading.Thread(target=holder)
            thread.start()
            self.assertTrue(both_held.wait(10))
            response = provider.decide(request_for("t0-0.txt", timeout=1.0))
            thread.join(10)
            self.assertEqual(MARKER.findall(response.answers["echo"]), ["t0-0.txt"])
        # The wait ate about 0.3 s of the caller's 1.0 s; the send's deadline
        # still starts at checkout with the full timeout (plan invariant 7).
        self.assertEqual(ledger.deadlines, [1.0])

    def test_refusal_takes_no_exchange_while_the_pool_is_full(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            held = [take(pool), take(pool)]
            started = time.monotonic()
            with self.assertRaises(ProviderError) as caught:
                provider.decide(ProviderRequest(b"x" * 40000, 5.0))
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertEqual(caught.exception.code, "request_too_large")
            self.assertEqual(ledger.posts, 0)
            self.assertEqual(len(pool._busy), 2)
            for exchange in held:
                pool.release(exchange)

    def test_release_wakes_a_waiting_acquire(self):
        ledger = Ledger(latency=0.0)
        pool = single_pool(ledger)
        held = take(pool)
        outcome: dict[str, object] = {}

        def waiter() -> None:
            started = time.monotonic()
            outcome["exchange"] = pool.acquire(time.monotonic() + 10)
            outcome["elapsed"] = time.monotonic() - started

        # Daemon with a bounded join: a release that wakes nothing fails this
        # test after about 5 s instead of hanging the module for 10 s.
        thread = threading.Thread(target=waiter, daemon=True)
        thread.start()
        time.sleep(0.1)
        pool.release(held)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIs(outcome.get("exchange"), held)
        self.assertLess(float(outcome["elapsed"]), 5.0)  # type: ignore[arg-type]

    def test_huge_timeout_waits_without_overflow(self):
        ledger = Ledger(latency=0.0)
        pool = single_pool(ledger)
        held = take(pool)
        outcome: dict[str, object] = {}

        def waiter() -> None:
            try:
                outcome["exchange"] = pool.acquire(time.monotonic() + 5_000_000.0)
            except BaseException as exc:  # asserted below
                outcome["error"] = exc

        thread = threading.Thread(target=waiter, daemon=True)
        thread.start()
        time.sleep(0.2)
        pool.release(held)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", outcome)
        self.assertIs(outcome.get("exchange"), held)


class FailurePathTests(unittest.TestCase):
    def test_failed_posts_give_the_exchange_back(self):
        cases = [
            (RuntimeError("offline failure"), RuntimeError),
            (KeyboardInterrupt(), KeyboardInterrupt),
            (ExchangeError("send", "reset", reused=True, bytes_sent=10, response_bytes=0),
             ProviderError),
            (ProviderError("invalid_request"), ProviderError),
        ]
        for max_connections in (2, 4):
            for exc, expected in cases:
                with self.subTest(max_connections=max_connections, error=type(exc).__name__):
                    ledger = Ledger(latency=0.0)
                    with patch.object(hosted, "HttpsExchange", ledger.factory):
                        provider = EchoDecisions(KEY, environ={},
                                                 max_connections=max_connections)
                        pool = provider._pool
                        assert pool is not None
                        ledger.raise_next.append(exc)
                        with self.assertRaises(expected):
                            provider.decide(request_for("t0-0.txt"))
                        self.assertEqual(pool._busy, set())
                        self.assertEqual(len(pool._all), 1)
                        self.assertEqual(len(pool._idle), 1)
                        response = provider.decide(request_for("t0-0.txt"))
                        self.assertEqual(MARKER.findall(response.answers["echo"]),
                                         ["t0-0.txt"])
                        self.assertEqual(pool._busy, set())

    def test_interrupt_between_pop_and_mark_returns_the_exchange(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            pool._busy = InterruptOnce()
            with self.assertRaises(KeyboardInterrupt):
                pool.acquire(time.monotonic() + 30)
            self.assertEqual(pool._busy, set())
            self.assertEqual(len(pool._idle), 1)
            response = provider.decide(request_for("t0-0.txt"))
            self.assertEqual(MARKER.findall(response.answers["echo"]), ["t0-0.txt"])

    def test_interrupt_between_pop_and_mark_is_restored_by_the_next_acquire(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            first, second = take(pool), take(pool)
            pool.release(first)
            pool.release(second)
            pool._idle = InterruptOnPop(pool._idle)
            with self.assertRaises(KeyboardInterrupt):
                pool.acquire(time.monotonic() + 30)
            self.assertEqual(pool._busy, set())
            # The exchange popped by the interrupt is not lost: a pool of two
            # serves two acquires at once, both exchanges, with no wait.
            got = [pool.acquire(time.monotonic() + 2) for _ in range(2)]
            self.assertNotIn(None, got)
            self.assertEqual({id(exchange) for exchange in got}, {id(first), id(second)})
            for exchange in got:
                pool.release(exchange)
            response = provider.decide(request_for("t0-0.txt"))
            self.assertEqual(MARKER.findall(response.answers["echo"]), ["t0-0.txt"])
            self.assertEqual(pool._busy, set())

    def test_interrupt_in_release_still_returns_the_exchange(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            first, second = take(pool), take(pool)
            pool._busy = InterruptOnDiscard(pool._busy)
            with self.assertRaises(KeyboardInterrupt):
                pool.release(first)
            self.assertEqual(pool._busy, {second})
            self.assertEqual(len(pool._idle), 1)
            pool.release(second)
            got = [pool.acquire(time.monotonic() + 2) for _ in range(2)]
            self.assertNotIn(None, got)
            self.assertEqual({id(exchange) for exchange in got}, {id(first), id(second)})
            for exchange in got:
                pool.release(exchange)
            self.assertEqual(pool._busy, set())

    def test_interrupt_in_the_retiring_check_still_closes_the_exchange(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            exchange = take(pool)
            exchange.connected = True
            pool.close()
            self.assertIn(exchange, pool._retiring)
            self.assertEqual(exchange.close_calls, 0)
            pool._retiring = InterruptOnContains(pool._retiring)
            with self.assertRaises(KeyboardInterrupt):
                pool.release(exchange)
            self.assertEqual(exchange.close_calls, 1)
            self.assertNotIn(exchange, pool._retiring)
            self.assertIn(exchange, pool._idle)
            got = take(pool)
            self.assertIs(got, exchange)
            self.assertEqual(got.close_calls, 1)
            self.assertFalse(got.connected)
            pool.release(got)
            self.assertEqual(pool._busy, set())

    def test_failed_send_deadline_gives_the_exchange_back(self):
        ledger = Ledger(latency=0.0)
        with patch.object(hosted, "HttpsExchange", ledger.factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=2)
            pool = provider._pool
            assert pool is not None
            ledger.deadline_raise.append(RuntimeError("offline failure"))
            with self.assertRaises(RuntimeError):
                provider.decide(request_for("t0-0.txt"))
            self.assertEqual(ledger.posts, 0)
            self.assertEqual(pool._busy, set())
            self.assertEqual(len(pool._idle), 1)
            response = provider.decide(request_for("t0-0.txt"))
            self.assertEqual(MARKER.findall(response.answers["echo"]), ["t0-0.txt"])

    def test_context_failure_is_connect_failed_at_every_pool_size(self):
        def failing_context() -> object:
            raise ssl.SSLError("offline context failure")

        outcomes: dict[int, tuple[str, dict[str, object]]] = {}
        for max_connections in (1, 2, 4):
            with self.subTest(max_connections=max_connections):
                with patch.object(exchange_module, "make_tls_context", failing_context), \
                        patch.object(hosted, "HttpsExchange", real_factory):
                    provider = EchoDecisions(KEY, environ={},
                                             max_connections=max_connections)
                    with self.assertRaises(ProviderError) as caught:
                        provider.decide(request_for("t0-0.txt"))
                    error = caught.exception
                    self.assertIsNone(error.__context__)
                    outcomes[max_connections] = (error.code, dict(error.info or {}))
                    self.assertEqual(error.code, "connect_failed")
                    self.assertEqual(error.classification,
                                     classify("connect_failed"))
        self.assertEqual(outcomes[1], outcomes[2])
        self.assertEqual(outcomes[1], outcomes[4])
        self.assertEqual(outcomes[1][1]["phase"], "connect")
        self.assertIs(outcomes[1][1]["reused"], False)


class CopyTests(unittest.TestCase):
    def test_one_connection_copies_and_pickles_as_before(self):
        provider = DecisionsProvider(KEY, environ={})
        provider.wire_size(encode_request(STATE, QUESTIONS))
        for clone in (copy.deepcopy(provider), pickle.loads(pickle.dumps(provider))):
            self.assertEqual(clone.identity, provider.identity)
            self.assertIsNone(clone._pool)
            self.assertIsNone(clone._encoded)

    def test_pooled_provider_refuses_to_be_copied(self):
        provider = DecisionsProvider(KEY, environ={}, max_connections=2)
        with self.assertRaises(TypeError):
            copy.deepcopy(provider)
        with self.assertRaises(TypeError):
            pickle.dumps(provider)


class SharedContextTests(unittest.TestCase):
    def test_real_exchanges_share_one_context(self):
        built: list[object] = []

        def counting_context() -> object:
            built.append(object())
            return built[-1]

        with patch.object(exchange_module, "make_tls_context", counting_context), \
                patch.object(hosted, "HttpsExchange", real_factory):
            provider = EchoDecisions(KEY, environ={}, max_connections=3)
            pool = provider._pool
            assert pool is not None
            held = [take(pool), take(pool), take(pool)]
            self.assertEqual(len(built), 1)
            self.assertEqual(sum(exchange.contexts_built for exchange in held), 1)
            self.assertEqual(len({id(exchange.context) for exchange in held}), 1)
            self.assertIsNone(pool.acquire(time.monotonic() + 0.05))
            for exchange in held:
                pool.release(exchange)
            provider.close()


if __name__ == "__main__":
    unittest.main()
