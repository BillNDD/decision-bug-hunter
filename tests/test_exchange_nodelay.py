"""TCP_NODELAY on every exchange socket, with the pre-A10 connect path as oracle.

No socket is opened. Each connection is a fake that records what the exchange
does to it, and every scripted exchange runs through ``tests.fakes``.
``_old_open`` is a frozen copy of ``HttpsExchange._open`` from before the
option was set; the equivalence test runs it and the current method over
seeded, generated connection cases and compares what each one does.
"""
import errno
import random
import socket
import unittest

from decision_bug_hunter.exchange import (Deadline, ExchangeError, HttpsExchange,
                                          _close_quietly, connect_addresses)
from tests.fakes import FakeClock, Reply, ScriptedHTTPS, shared_test_context


HOST = "api.example.test"
PATH = "/v1/test"
NODELAY = (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
#: Stands for an OSError raised with no errno at all (``None`` means no error).
ERRNOLESS = "errnoless"
OPTION_CASES = (None, errno.ENOPROTOOPT, errno.EPERM, errno.ECONNRESET, ERRNOLESS)
SEEDS = 400


class _OptionScript(ScriptedHTTPS):
    """``ScriptedHTTPS`` whose every socket records its ``setsockopt`` calls.

    With ``option_error`` set, each such call raises it instead of returning.
    """

    def __init__(self, steps, *, option_error=None, **kwargs):
        super().__init__(steps, **kwargs)
        self.option_error = option_error
        self.options = []

    def connect(self, address, timeout=None, source_address=None):
        sock = super().connect(address, timeout, source_address)
        index = sock.index

        def setsockopt(*args):
            self.options.append((index, args))
            if self.option_error is not None:
                raise self.option_error
        # An instance attribute shadows FakeSocket.setsockopt for this socket.
        sock.setsockopt = setsockopt
        return sock


class _RecordingSocket:
    """A TCP socket stand-in whose operations all land in one shared log."""

    def __init__(self, ident, log, clock, behaviour, option):
        self.ident, self.log, self.clock = ident, log, clock
        self.behaviour, self.option = behaviour, option
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value
        self.log.append(("settimeout", value))

    def connect(self, address):
        self.log.append(("connect", tuple(address), self.timeout))
        kind = self.behaviour[tuple(address)]
        if kind == "refused":
            raise ConnectionRefusedError("refused")
        if kind == "blackhole":
            self.clock.advance(self.timeout)
            raise TimeoutError("timed out")

    def setsockopt(self, *args):
        self.log.append(("setsockopt", args))
        if self.option == ERRNOLESS:
            raise OSError("scripted")
        if self.option is not None:
            raise OSError(self.option, "scripted")

    def close(self):
        self.log.append(("close", self.ident))


def _old_open(exchange, deadline):
    """Frozen copy of ``HttpsExchange._open`` before TCP_NODELAY was set."""
    remaining = deadline.remaining()
    if remaining <= 0:
        raise TimeoutError("deadline reached")
    if exchange._connect is not None:
        raw = exchange._connect((exchange.host, exchange.port), remaining)
    else:
        raw = connect_addresses(exchange.host, exchange.port, deadline,
                                resolve=exchange._resolve, make_socket=exchange._make_socket)
    try:
        remaining = deadline.remaining()
        if remaining <= 0:
            raise TimeoutError("deadline reached")
        raw.settimeout(remaining)
        return exchange._wrap(raw, exchange.context, exchange.host)
    except BaseException:
        _close_quietly(raw)
        raise


def _generate(seed):
    """One connection case, fully determined by *seed*."""
    rng = random.Random(seed)
    count = rng.randint(1, 3)
    return {
        "injected": rng.random() < 0.5,
        "option": rng.choice(OPTION_CASES),
        "behaviour": [rng.choice(["ok", "ok", "refused", "blackhole"]) for _ in range(count)],
        "budget": rng.choice([0.0, 0.5, 2.0, 30.0]),
        "wrap_fails": rng.random() < 0.2,
    }


def _run(old, case):
    """Opens one connection with the old or the current method; returns the
    outcome and the ordered log of every operation on every socket."""
    log, clock, made = [], FakeClock(0.0), []

    def new_socket(behaviour):
        sock = _RecordingSocket(len(made), log, clock, behaviour, case["option"])
        made.append(sock)
        return sock

    def wrap(sock, context, host):
        log.append(("wrap", host))
        if case["wrap_fails"]:
            raise ConnectionAbortedError("wrap")
        return sock

    if case["injected"]:
        kind = case["behaviour"][0]

        def connect(address, timeout):
            log.append(("connect", tuple(address), timeout))
            if kind == "refused":
                raise ConnectionRefusedError("refused")
            if kind == "blackhole":
                clock.advance(timeout)
                raise TimeoutError("timed out")
            return new_socket({})
        exchange = HttpsExchange(HOST, PATH, connect=connect, wrap=wrap, clock=clock,
                                 context=shared_test_context())
    else:
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.%d" % (index + 1), 443))
                     for index in range(len(case["behaviour"]))]
        behaviour = {info[4]: kind for info, kind in zip(addresses, case["behaviour"])}

        def resolve(host, port, family, kind):
            return addresses

        def make_socket(family, kind, proto):
            return new_socket(behaviour)
        exchange = HttpsExchange(HOST, PATH, resolve=resolve, make_socket=make_socket,
                                 wrap=wrap, clock=clock, context=shared_test_context())
    deadline = Deadline.after(case["budget"], clock)
    open_connection = _old_open if old else HttpsExchange._open
    try:
        sock = open_connection(exchange, deadline)
        result = ("ok", sock.ident)
    except Exception as exc:
        result = ("raise", type(exc).__name__, getattr(exc, "errno", None), str(exc))
    return result, log


class NoDelayTests(unittest.TestCase):
    """The option is set once per connection, before TLS, and only ENOPROTOOPT
    is ignored."""

    def script(self, steps, **kwargs):
        script = _OptionScript(steps, clock=FakeClock(0.0), host=HOST, **kwargs)
        return script, script.exchange(HOST, PATH)

    def test_option_is_set_on_a_new_connection(self):
        script, exchange = self.script([Reply(body=b'{"ok": true}')])
        outcome = exchange.post(b"{}", {}, exchange.deadline(30.0))
        self.assertEqual((outcome.status, outcome.body), (200, b'{"ok": true}'))
        self.assertEqual(script.options, [(0, NODELAY)])

    def test_reused_connection_does_not_set_the_option_again(self):
        script, exchange = self.script([Reply(body=b"{}"), Reply(body=b"{}")])
        exchange.post(b"{}", {}, exchange.deadline(30.0))
        exchange.post(b"{}", {}, exchange.deadline(30.0))
        self.assertEqual(script.reuse_count, 1)
        self.assertEqual(script.options, [(0, NODELAY)])

    def test_enoprotoopt_is_ignored(self):
        script, exchange = self.script([Reply(body=b'{"ok": true}')],
                                       option_error=OSError(errno.ENOPROTOOPT, "scripted"))
        outcome = exchange.post(b"{}", {}, exchange.deadline(30.0))
        self.assertEqual(outcome.status, 200)
        self.assertEqual(script.options, [(0, NODELAY)])

    def test_other_option_errors_fail_the_connect_phase_and_close(self):
        for error_number, kind in ((errno.EPERM, "os"), (errno.ECONNRESET, "reset")):
            with self.subTest(errno=errno.errorcode[error_number]):
                script, exchange = self.script(
                    [Reply(body=b"{}")], option_error=OSError(error_number, "scripted"))
                with self.assertRaises(ExchangeError) as caught:
                    exchange.post(b"{}", {}, exchange.deadline(30.0))
                error = caught.exception
                self.assertEqual((error.phase, error.kind), ("connect", kind))
                self.assertEqual((error.reused, error.bytes_sent, error.response_bytes),
                                 (False, 0, 0))
                self.assertEqual(script.requests, [])
                self.assertEqual(script.closed, [0])

    def test_an_option_error_without_an_errno_fails_the_connect_phase_and_closes(self):
        # errno is None, which is not ENOPROTOOPT, so it is raised like any other error.
        error = OSError("boom")
        self.assertIsNone(error.errno)
        script, exchange = self.script([Reply(body=b"{}")], option_error=error)
        with self.assertRaises(ExchangeError) as caught:
            exchange.post(b"{}", {}, exchange.deadline(30.0))
        failure = caught.exception
        self.assertEqual((failure.phase, failure.kind), ("connect", "os"))
        self.assertEqual((failure.reused, failure.bytes_sent, failure.response_bytes),
                         (False, 0, 0))
        self.assertEqual(script.requests, [])
        self.assertEqual(script.closed, [0])

    def test_address_path_sets_the_option_before_tls_wrap(self):
        log, clock = [], FakeClock(0.0)
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))]

        def make_socket(family, kind, proto):
            return _RecordingSocket(0, log, clock, {("192.0.2.1", 443): "ok"}, None)

        def wrap(sock, context, host):
            log.append(("wrap", host))
            return sock
        exchange = HttpsExchange(HOST, PATH, resolve=lambda *a: addresses,
                                 make_socket=make_socket, wrap=wrap, clock=clock,
                                 context=shared_test_context())
        sock = exchange._open(exchange.deadline(30.0))
        self.assertIsInstance(sock, _RecordingSocket)
        self.assertEqual([entry[0] for entry in log],
                         ["settimeout", "connect", "setsockopt", "settimeout", "wrap"])
        self.assertEqual(log[2], ("setsockopt", NODELAY))

    def test_address_path_enoprotoopt_is_ignored_and_other_errors_close(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))]
        for option, expected in ((errno.ENOPROTOOPT, "ok"), (errno.EPERM, "raise"),
                                 (ERRNOLESS, "raise")):
            with self.subTest(errno=option if option == ERRNOLESS else errno.errorcode[option]):
                log, clock = [], FakeClock(0.0)

                def make_socket(family, kind, proto, option=option):
                    return _RecordingSocket(0, log, clock,
                                            {("192.0.2.1", 443): "ok"}, option)
                exchange = HttpsExchange(HOST, PATH, resolve=lambda *a: addresses,
                                         make_socket=make_socket,
                                         wrap=lambda sock, context, host: sock,
                                         clock=clock, context=shared_test_context())
                if expected == "ok":
                    self.assertEqual(exchange._open(exchange.deadline(30.0)).ident, 0)
                    self.assertNotIn(("close", 0), log)
                else:
                    with self.assertRaises(OSError) as caught:
                        exchange._open(exchange.deadline(30.0))
                    self.assertEqual(caught.exception.errno,
                                     None if option == ERRNOLESS else option)
                    self.assertEqual(log[-1], ("close", 0))


class NoDelayEquivalenceTests(unittest.TestCase):
    """Over seeded generated connection cases, the current ``_open`` matches
    the frozen pre-A10 ``_open`` in everything except the one option call."""

    def test_generated_connections_match_the_frozen_old_open(self):
        seen = {"socket_none": 0, "enoprotoopt": 0, "error": 0, "errnoless": 0,
                "no_socket": 0}
        for seed in range(SEEDS):
            case = _generate(seed)
            with self.subTest(seed=seed, case=case):
                old_result, old_log = _run(True, case)
                new_result, new_log = _run(False, case)
                options = [entry for entry in new_log if entry[0] == "setsockopt"]
                self.assertLessEqual(len(options), 1)
                if not options:
                    # The connect failed, so no socket reached the option.
                    seen["no_socket"] += 1
                    self.assertEqual((new_result, new_log), (old_result, old_log))
                    continue
                self.assertEqual(options, [("setsockopt", NODELAY)])
                position = new_log.index(("setsockopt", NODELAY))
                if case["option"] in (None, errno.ENOPROTOOPT):
                    seen["socket_none" if case["option"] is None else "enoprotoopt"] += 1
                    self.assertEqual(new_result, old_result)
                    self.assertEqual([entry for entry in new_log if entry[0] != "setsockopt"],
                                     old_log)
                else:
                    seen["errnoless" if case["option"] == ERRNOLESS else "error"] += 1
                    self.assertEqual(new_result[0], "raise")
                    self.assertEqual(new_result[2],
                                     None if case["option"] == ERRNOLESS else case["option"])
                    self.assertEqual(new_log[:position], old_log[:position])
                    self.assertEqual([entry[0] for entry in new_log[position + 1:]],
                                     ["close"])
        for name, count in seen.items():
            self.assertGreater(count, 0, name)


if __name__ == "__main__":
    unittest.main()
