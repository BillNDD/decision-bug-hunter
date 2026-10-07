"""HTTPS exchange contracts: absolute deadline, reuse rules, bounded bodies.

Every test runs over ``tests.fakes.ScriptedHTTPS``; no socket is opened and
no wall-clock sleep happens. Delays move only the fake clock.
"""
from contextlib import redirect_stderr, redirect_stdout
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import decisions
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.exchange import (ERROR_BODY_CAP, Deadline, ExchangeError,
                                          HttpsExchange, Outcome, make_tls_context)
from decision_bug_hunter.protocol import QUESTION, ProviderError
from decision_bug_hunter.providers import ValidatedGateway
from tests.fakes import (ConnectFailure, Delay, FakeClock, Raise, Reply, ScriptedHTTPS,
                         SendFailure, Silence)
from tests.support import clean_provider_env, openai_body


KEY = "offline-sentinel-credential-9d41"
HOST = "api.example.test"
PATH = "/v1/test"
BODY = b'{"answers": {}}'
SLACK = 0.05
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
QUESTIONS = {"screen": QUESTION}
ANSWERS = {"screen": {"type": "noul", "noul": 0.25}}
METADATA = {"sequence": 1, "phase": "test"}


def head(status=200, headers=(("Content-Type", "application/json"),)):
    lines = [f"HTTP/1.1 {status} Scripted"] + [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def trickle(data, gap):
    """One byte at a time, ``gap`` fake seconds apart."""
    events = []
    for index in range(len(data)):
        if index:
            events.append(Delay(gap))
        events.append(data[index:index + 1])
    return events


class ExchangeCase(unittest.TestCase):
    def script(self, steps, **kwargs):
        script = ScriptedHTTPS(steps, clock=FakeClock(0.0), host=HOST)
        return script, script.exchange(HOST, PATH, **kwargs)

    def post(self, exchange, seconds=30.0, **kwargs):
        deadline = exchange.deadline(seconds)
        return exchange.post(b"{}", {"Authorization": "Bearer " + KEY}, deadline, **kwargs)

    def assert_aborted_at_deadline(self, script, exchange, seconds, phase="receive"):
        start = script.clock.now
        with self.assertRaises(ExchangeError) as caught:
            self.post(exchange, seconds)
        error = caught.exception
        self.assertEqual((error.phase, error.kind), (phase, "timeout"))
        self.assertLessEqual(script.clock.now - start, seconds + SLACK)
        self.assertGreaterEqual(script.clock.now - start, seconds - SLACK)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(KEY, str(error))
        self.assertEqual(script.closed, [0])
        return error


class TlsContextTests(ExchangeCase):
    def test_tls_context_ignores_sslkeylogfile(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "keys.log"
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(log)}):
                context = make_tls_context()
            self.assertFalse(log.exists())
        self.assertIsNone(getattr(context, "keylog_filename", None))
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        if sys.version_info >= (3, 13):
            self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
            self.assertTrue(context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN)

    def test_tls_context_built_once_per_provider(self):
        built = []

        def counting():
            built.append(1)
            return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Two replies whose peer closes afterwards: the second call reconnects
        # and performs a second handshake with the same context object.
        script = ScriptedHTTPS([Reply(body=openai_body(ANSWERS), close_after=True),
                                Reply(body=openai_body(ANSWERS), close_after=True)],
                               clock=FakeClock(0.0), host=decisions.HOST)
        exchange = script.exchange(decisions.HOST, decisions.PATH, context=None)
        provider = DecisionsProvider(KEY, environ={}, exchange=exchange)
        with tempfile.TemporaryDirectory() as td, \
                patch("decision_bug_hunter.exchange.make_tls_context", side_effect=counting):
            gateway = ValidatedGateway(provider, Path(td) / "receipts")
            for sequence in (1, 2):
                gateway.evaluate({**STATE, "n": sequence}, QUESTIONS, metadata=METADATA)
            gateway.close()
        self.assertEqual(len(built), 1)
        self.assertEqual(exchange.contexts_built, 1)
        self.assertEqual(len(script.connects), 2)
        self.assertIs(script.contexts[0], script.contexts[1])
        self.assertEqual(script.server_hostnames, [decisions.HOST, decisions.HOST])

    def test_unavailable_provider_builds_no_context(self):
        exchange = HttpsExchange(HOST, PATH, connect=lambda *a: self.fail("connect"))
        provider = DecisionsProvider(environ={}, exchange=exchange)
        with self.assertRaises(ProviderError):
            provider.require_available()
        self.assertEqual(exchange.contexts_built, 0)


class RequestTests(ExchangeCase):
    def test_global_debuglevel_never_prints_authorization(self):
        script, exchange = self.script([Reply(body=BODY)])
        out, err = io.StringIO(), io.StringIO()
        with patch.object(http.client.HTTPConnection, "debuglevel", 1), \
                patch.object(http.client.HTTPResponse, "debuglevel", 1, create=True), \
                redirect_stdout(out), redirect_stderr(err):
            outcome = self.post(exchange)
        self.assertEqual(outcome.body, BODY)
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_request_bytes_have_fixed_origin_and_no_connection_header(self):
        script, exchange = self.script([Reply(body=BODY)])
        with clean_provider_env(HTTPS_PROXY="http://proxy.invalid:1", ALL_PROXY="x"):
            self.post(exchange, 12.5)
        self.assertEqual(script.connects, [((HOST, 443), 12.5)])
        (request,) = script.requests
        self.assertEqual((request.method, request.target), ("POST", PATH))
        self.assertEqual(request.header("Host"), HOST)
        self.assertEqual(request.header("Content-Length"), "2")
        self.assertIsNone(request.header("Connection"))
        self.assertEqual(request.header("Authorization"), "Bearer " + KEY)

    def test_unsafe_headers_or_bodies_never_connect(self):
        script, exchange = self.script([])
        deadline = exchange.deadline(5)
        for headers in ({"X-Bad": "a\r\nInjected: 1"}, {"Bad Name": "v"},
                        {"Host": "elsewhere"}, {"content-length": "1"}, {"X": 1}):
            with self.subTest(headers=headers):
                with self.assertRaises(ProviderError) as caught:
                    exchange.post(b"{}", headers, deadline)
                self.assertEqual(caught.exception.code, "invalid_request")
        with self.assertRaises(ProviderError):
            exchange.post("text", {}, deadline)
        self.assertEqual(script.connects, [])

    def test_expired_deadline_never_connects(self):
        script, exchange = self.script([])
        with self.assertRaises(ExchangeError) as caught:
            exchange.post(b"{}", {}, Deadline(-1.0, script.clock))
        self.assertEqual((caught.exception.phase, caught.exception.kind), ("connect", "timeout"))
        self.assertEqual(caught.exception.bytes_sent, 0)
        self.assertEqual(script.connects, [])

    def test_connect_and_send_failures_are_structural(self):
        cases = [(ConnectFailure(ConnectionRefusedError(KEY)), "connect", "os"),
                 (ConnectFailure(socket.gaierror(KEY)), "connect", "os"),
                 (ConnectFailure(delay=99.0), "connect", "timeout"),
                 (SendFailure(BrokenPipeError(KEY)), "send", "reset"),
                 (SendFailure(ssl.SSLError(KEY)), "send", "tls")]
        for step, phase, kind in cases:
            with self.subTest(phase=phase, kind=kind):
                script, exchange = self.script([step])
                with self.assertRaises(ExchangeError) as caught:
                    self.post(exchange, 5.0)
                error = caught.exception
                self.assertEqual((error.phase, error.kind, error.reused), (phase, kind, False))
                self.assertEqual(error.bytes_sent, 0)
                self.assertEqual(error.response_bytes, 0)
                self.assertIsNone(error.__context__)
                self.assertNotIn(KEY, str(error))
                self.assertLessEqual(script.clock.now, 5.0 + SLACK)

    def test_tls_handshake_runs_under_the_remaining_deadline(self):
        script = ScriptedHTTPS([ConnectFailure(delay=2.0), Reply(body=BODY)],
                               clock=FakeClock(0.0), host=HOST)
        seen = []

        def wrap(sock, context, server_hostname):
            seen.append(sock.gettimeout())
            return sock

        exchange = HttpsExchange(HOST, PATH, connect=script, wrap=wrap,
                                 readable=script.readable, clock=script.clock,
                                 context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
        with self.assertRaises(ExchangeError):
            self.post(exchange, 10.0)
        script.clock.advance(1.0)
        self.post(exchange, 10.0)
        self.assertEqual(script.connects[1][1], 10.0)
        self.assertEqual(seen, [10.0])


class DeadlineTests(ExchangeCase):
    def test_trickling_status_line_aborted(self):
        script, exchange = self.script([Reply(events=trickle(head(), 0.3))])
        self.assert_aborted_at_deadline(script, exchange, 2.0)

    def test_trickling_headers_aborted(self):
        headers = (("Content-Type", "application/json"), ("X-Padding", "p" * 200),
                   ("Content-Length", str(len(BODY))))
        wire = head(200, headers)
        status_line = wire.index(b"\r\n") + 2
        events = [wire[:status_line]] + trickle(wire[status_line:], 0.25) + [BODY]
        script, exchange = self.script([Reply(events=events)])
        error = self.assert_aborted_at_deadline(script, exchange, 3.0)
        self.assertGreater(error.response_bytes, status_line)

    def test_trickling_chunked_body_aborted(self):
        body = b'{"answers": {"padding": "' + b"x" * 400 + b'"}}'
        script, exchange = self.script([Reply(body=body, chunked=True, chunk_size=1,
                                              delay_between=0.2)])
        self.assert_aborted_at_deadline(script, exchange, 4.0)

    def test_trickling_content_length_body_aborted(self):
        script, exchange = self.script([Reply(body=b"[" + b" " * 300 + b"]", chunk_size=2,
                                              delay_between=0.5)])
        self.assert_aborted_at_deadline(script, exchange, 5.0)

    def test_silent_peer_aborted(self):
        script, exchange = self.script([Silence()])
        self.assert_aborted_at_deadline(script, exchange, 7.0)

    def test_late_complete_200_accepted_marked_late(self):
        wire = head(200, (("Content-Type", "application/json"),
                          ("Content-Length", str(len(BODY))))) + BODY
        script, exchange = self.script([Reply(events=[Delay(5.0), wire])])
        outcome = self.post(exchange, 5.0)
        self.assertEqual((outcome.status, outcome.body, outcome.late), (200, BODY, True))
        self.assertEqual(outcome.elapsed, 5.0)
        script2, exchange2 = self.script([Reply(events=[Delay(4.0), wire])])
        self.assertFalse(self.post(exchange2, 5.0).late)

    def test_each_receive_rearms_the_socket_timeout(self):
        script, exchange = self.script([Reply(body=BODY, chunk_size=4, delay_between=1.0)])
        self.post(exchange, 30.0)
        timeouts = [value for _, value in script.settimeout_calls]
        # Send at 30, then one re-arm per receive, each the remaining budget.
        self.assertEqual(timeouts[0], 30.0)
        self.assertTrue(all(b <= a for a, b in zip(timeouts, timeouts[1:])))
        self.assertLessEqual(timeouts[-1], 30.0 - 2.0)


class ReuseTests(ExchangeCase):
    def test_connection_reused_after_complete_200(self):
        script, exchange = self.script([Reply(body=BODY),
                                        Reply(body=BODY, chunked=True, chunk_size=3),
                                        Reply(body=BODY)])
        outcomes = [self.post(exchange) for _ in range(3)]
        self.assertEqual([o.reused for o in outcomes], [False, True, True])
        self.assertEqual((len(script.connects), script.reuse_count), (1, 2))
        self.assertEqual(script.closed, [])
        exchange.close()
        self.assertEqual(script.closed, [0])

    def test_connection_discarded_after_error_or_non_200(self):
        trailing = head(200, (("Content-Type", "application/json"),
                              ("Content-Length", str(len(BODY))))) + BODY + b"HTTP/1.1"
        firsts = {
            "non_200": Reply(status=500, body=b"{}"),
            "framing": Reply(body=BODY, headers=[("Content-Type", "text/plain"),
                                                 ("Content-Length", str(len(BODY)))]),
            "connection_close": Reply(body=BODY, headers=[
                ("Content-Type", "application/json"), ("Content-Length", str(len(BODY))),
                ("Connection", "close")]),
            "unread_bytes": Reply(events=[trailing]),
            "reset": Reply(body=BODY, fail_after=3),
        }
        for label, first in firsts.items():
            with self.subTest(label=label):
                script, exchange = self.script([first, Reply(body=BODY)])
                try:
                    self.post(exchange)
                except (ExchangeError, ProviderError):
                    pass
                self.assertEqual(script.closed, [0])
                outcome = self.post(exchange)
                self.assertFalse(outcome.reused)
                self.assertEqual(len(script.connects), 2)

    def test_readable_idle_socket_reconnects(self):
        for label in ("peer_closed", "pending_tls_bytes"):
            with self.subTest(label=label):
                script, exchange = self.script([Reply(body=BODY), Reply(body=BODY)])
                self.post(exchange)
                if label == "peer_closed":
                    script.sockets[0].peer_closed = True
                else:
                    script.sockets[0].pending_bytes = 5
                self.assertFalse(self.post(exchange).reused)
                self.assertEqual((len(script.connects), script.closed), (2, [0]))

    def test_idle_over_10s_reconnects(self):
        script, exchange = self.script([Reply(body=BODY), Reply(body=BODY), Reply(body=BODY)])
        self.post(exchange)
        script.clock.advance(9.5)
        self.assertTrue(self.post(exchange).reused)
        script.clock.advance(10.5)
        self.assertFalse(self.post(exchange).reused)
        self.assertEqual(len(script.connects), 2)

    def test_reused_socket_failure_reports_reuse_and_timing(self):
        script, exchange = self.script([
            Reply(body=BODY), Reply(events=[Delay(0.4), Raise(ConnectionResetError(KEY))])])
        self.post(exchange)
        with self.assertRaises(ExchangeError) as caught:
            self.post(exchange)
        error = caught.exception
        self.assertEqual((error.phase, error.kind, error.reused), ("receive", "reset", True))
        self.assertEqual(error.response_bytes, 0)
        self.assertGreater(error.bytes_sent, 0)
        self.assertAlmostEqual(error.since_send, 0.4)


class ErrorBodyTests(ExchangeCase):
    def outcome(self, reply, *, seconds=30.0, read_errors=True):
        script, exchange = self.script([reply])
        outcome = self.post(exchange, seconds, read_errors=read_errors, credentials=(KEY,))
        self.assertEqual(script.closed, [0])
        return script, outcome

    def test_error_body_states(self):
        ok = json.dumps({"error": {"message": "bad", "code": 400}}).encode()
        big = json.dumps({"error": {"message": "m" * ERROR_BODY_CAP}}).encode()
        escaped = json.dumps({"error": {"message": "\\u006f" + KEY[1:]}}).encode()
        escaped = escaped.replace(b"\\\\u006f", b"\\u006f")
        json_type = [("Content-Type", "application/json")]
        cases = [
            (Reply(status=400, body=ok), "ok"),
            (Reply(status=400, body=big), "oversized"),
            (Reply(status=400, body=big, chunked=True, chunk_size=4096), "oversized"),
            (Reply(status=400, body=b"plain", headers=[("Content-Type", "text/plain"),
                                                       ("Content-Length", "5")]), "not_json"),
            (Reply(status=400, body=b"{nope"), "not_json"),
            (Reply(status=400, body=ok, headers=json_type + [
                ("Content-Encoding", "gzip"), ("Content-Length", str(len(ok)))]), "not_json"),
            (Reply(status=401, body=json.dumps({"error": KEY}).encode()), "withheld_sensitive"),
            (Reply(status=401, body=b'{"error": "Incorrect key sk-ab***yz"}'),
             "withheld_sensitive"),
            (Reply(status=401, body=escaped), "withheld_sensitive"),
            (Reply(status=500, body=b""), "absent"),
            (Reply(status=500, body=ok, fail_after=4), "absent"),
        ]
        for reply, state in cases:
            with self.subTest(state=state, status=reply.status):
                _, outcome = self.outcome(reply)
                self.assertEqual(outcome.error_body_state, state)
                self.assertEqual(outcome.body, b"")
                if state == "ok":
                    self.assertEqual(outcome.error_raw, ok)
                else:
                    self.assertIsNone(outcome.error_raw)
        _, unread = self.outcome(Reply(status=400, body=ok), read_errors=False)
        self.assertEqual((unread.status, unread.error_body_state, unread.error_raw),
                         (400, "unread", None))

    def test_error_body_read_respects_deadline(self):
        body = json.dumps({"error": {"message": "slow"}}).encode()
        _, outcome = self.outcome(Reply(status=503, body=body, chunk_size=1,
                                        delay_between=0.5), seconds=3.0)
        self.assertEqual((outcome.status, outcome.error_body_state), (503, "absent"))
        self.assertLessEqual(outcome.elapsed, 3.0 + SLACK)

    def test_only_allow_listed_headers_are_kept(self):
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(BODY))),
                   ("cf-ray", "8f00aa-GRU"), ("Set-Cookie", "s=1"), ("Server", "edge"),
                   ("X-Generation-Id", "gen-dec-1"), ("Retry-After", "2"),
                   ("X-RateLimit-Remaining", "9")]
        script, exchange = self.script([Reply(body=BODY, headers=headers)])
        outcome = self.post(exchange)
        self.assertIsInstance(outcome, Outcome)
        self.assertEqual({name for name, _ in outcome.headers},
                         {"content-type", "content-length", "x-generation-id",
                          "retry-after", "x-ratelimit-remaining"})
        self.assertEqual(outcome.header("X-Generation-Id"), "gen-dec-1")
        self.assertIsNone(outcome.header("cf-ray"))


if __name__ == "__main__":
    unittest.main()
