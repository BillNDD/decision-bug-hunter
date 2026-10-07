"""The offline harness itself: network guard, environment scrub, fakes, seam.

These tests establish that the suite cannot reach a provider or read a real
credential; they say nothing about any live service.
"""
import argparse
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import decisions
from decision_bug_hunter.core import Source
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.protocol import ProviderError, QUESTION, validate_answer_objects
from decision_bug_hunter.providers import ValidatedGateway
from tests import network_guard
from tests.fakes import (ConnectFailure, FakeClock, FakeSleep, Reply, ScriptedHTTPS,
                         SendFailure, Silence, seeded_rng)
from tests.network_guard import NetworkAccessForbidden
from tests.support import (clean_provider_env, is_provider_variable, openai_body,
                           openrouter_body)


KEY = "offline-harness-sentinel-credential-31d9"
STATE = {"file": "example.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "private-sample-line"}]}],
         "context_scope": "declared_standalone"}
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "none": "No supported suspicion."}}
QUESTIONS = {"screen": QUESTION, "where": CHOICE}
ANSWERS = {"screen": {"type": "noul", "noul": Decimal("0.95")},
           "where": {"type": "choice", "choice": "L1-1", "confidence": Decimal("0.93"),
                     "probabilities": {"L1-1": Decimal("0.95"), "none": Decimal("0.05")}}}
METADATA = {"sequence": 1, "phase": "test"}
TEST_NET = ("192.0.2.1", 443)  # RFC 5737 documentation address; never routed.

#: Tests that read provider configuration from the process environment. They
#: are re-run under exported dummy keys by test_suite_safe_with_provider_keys_set.
ENVIRONMENT_SENSITIVE = (
    "tests.test_decisions.AvailabilityTests",
    "tests.test_decisions.EndToEndCliTests",
    "tests.test_provider_boundary.ProviderBoundaryTests."
    "test_unavailable_before_any_source_read_output_or_network",
    "tests.test_cli",
    "tests.test_project_scope",
    "tests.test_provider_ownership",
)


class NetworkGuardTests(unittest.TestCase):
    def forget(self, before):
        del network_guard.attempts[before:]

    def test_network_guard_active(self):
        self.assertTrue(network_guard.active())
        self.assertFalse(issubclass(NetworkAccessForbidden, Exception))
        before = len(network_guard.attempts)
        self.addCleanup(self.forget, before)
        probes = (
            ("socket.socket.connect", lambda: socket.socket.connect(None, TEST_NET)),
            ("socket.socket.connect_ex", lambda: socket.socket.connect_ex(None, TEST_NET)),
            ("socket.create_connection",
             lambda: socket.create_connection(TEST_NET, timeout=0.01)),
            ("socket.getaddrinfo", lambda: socket.getaddrinfo("example.invalid", 443)),
            ("ssl.SSLContext.wrap_socket",
             lambda: ssl.SSLContext.wrap_socket(None, None)),
        )
        for label, probe in probes:
            with self.subTest(label=label):
                with self.assertRaises(NetworkAccessForbidden) as caught:
                    probe()
                self.assertEqual(network_guard.attempts[-1], label)
                self.assertNotIn("192.0.2.1", str(caught.exception))
        self.assertEqual(network_guard.attempts[before:], [label for label, _ in probes])

    def test_guard_is_not_absorbed_by_the_gateway(self):
        """A provider ``Exception`` becomes transport_failed; the guard must not."""
        before = len(network_guard.attempts)
        self.addCleanup(self.forget, before)
        with tempfile.TemporaryDirectory() as td:
            gateway = ValidatedGateway(DecisionsProvider(KEY, environ={}),
                                       Path(td) / "receipts")
            self.addCleanup(gateway.close)
            with self.assertRaises(NetworkAccessForbidden):
                gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
        self.assertEqual(network_guard.attempts[before:], ["socket.create_connection"])


class EnvironmentTests(unittest.TestCase):
    POLLUTED = {
        "OPENAI_API_KEY": "dummy-openai", "OPENAI_ORG_ID": "org-dummy",
        "OPENAI_PROJECT_ID": "proj-dummy", "OPENAI_BASE_URL": "https://192.0.2.1",
        "OPENROUTER_API_KEY": "dummy-openrouter", "OPENROUTER_REFERER": "x",
        "ANTHROPIC_API_KEY": "dummy-other", "DBH_PROVIDER": "openrouter",
        "SSLKEYLOGFILE": "keylog.txt", "HTTP_PROXY": "http://192.0.2.1:9",
        "HTTPS_PROXY": "http://192.0.2.1:9", "ALL_PROXY": "socks5://192.0.2.1:9",
        "DBH_TEST_SECRET": "scrub-on-request", "DBH_UNRELATED_SETTING": "kept",
    }

    def test_clean_provider_env_removes_all_provider_variables(self):
        with patch.dict(os.environ, self.POLLUTED):
            with clean_provider_env("DBH_TEST_SECRET"):
                remaining = [k for k in os.environ if is_provider_variable(k)]
                self.assertEqual(remaining, [])
                self.assertNotIn("DBH_TEST_SECRET", os.environ)
                self.assertEqual(os.environ["DBH_UNRELATED_SETTING"], "kept")
                with self.assertRaises(ProviderError) as caught:
                    DecisionsProvider().require_available()
                self.assertEqual(caught.exception.code, "provider_unavailable")
            for name, value in self.POLLUTED.items():
                self.assertEqual(os.environ[name], value)
        for name in ("https_proxy", "openai_api_key", "Some_API_KEY"):
            self.assertTrue(is_provider_variable(name), name)

    def test_clean_provider_env_can_set_named_values(self):
        with patch.dict(os.environ, self.POLLUTED):
            with clean_provider_env(OPENAI_API_KEY=KEY):
                self.assertEqual(os.environ["OPENAI_API_KEY"], KEY)
                self.assertNotIn("OPENROUTER_API_KEY", os.environ)
                DecisionsProvider().require_available()
            self.assertEqual(os.environ["OPENAI_API_KEY"], "dummy-openai")

    def test_suite_safe_with_provider_keys_set(self):
        """Environment-reading tests pass with dummy keys exported, offline."""
        before = len(network_guard.attempts)
        dummies = {"OPENAI_API_KEY": "dbh-dummy-openai-key-not-a-credential",
                   "OPENROUTER_API_KEY": "dbh-dummy-openrouter-key-not-a-credential",
                   "DBH_PROVIDER": "openrouter",
                   "HTTPS_PROXY": "http://192.0.2.1:9", "HTTP_PROXY": "http://192.0.2.1:9"}
        suite = unittest.defaultTestLoader.loadTestsFromNames(ENVIRONMENT_SENSITIVE)
        result = unittest.TestResult()
        with patch.dict(os.environ, dummies), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            suite.run(result)
        problems = [test.id() for test, _ in result.failures + result.errors]
        self.assertEqual(problems, [])
        self.assertGreater(result.testsRun, 40)
        self.assertEqual(network_guard.attempts[before:], [])


class BodyBuilderTests(unittest.TestCase):
    def test_openrouter_body_matches_observed_shape(self):
        data = json.loads(openrouter_body(ANSWERS, input_tokens=8457), parse_float=Decimal)
        self.assertEqual(set(data), {"answers", "id", "model", "provider", "usage"})
        self.assertRegex(data["model"], r"\Aopenai/gpt-6-luna-decisions-[0-9]{8}\Z")
        self.assertEqual(data["provider"], "OpenAI")
        self.assertTrue(data["id"].startswith("gen-dec-"))
        self.assertEqual(set(data["usage"]), {"input_tokens", "output_tokens", "cost"})
        self.assertEqual(data["usage"]["output_tokens"], 0)
        self.assertEqual(data["usage"]["cost"], Decimal(8457) * Decimal("1e-7"))
        self.assertEqual(validate_answer_objects(data["answers"], QUESTIONS, 2), ANSWERS)
        trimmed = json.loads(openrouter_body(ANSWERS, omit=("usage", "id"), extra_key=1))
        self.assertEqual(set(trimmed), {"answers", "model", "provider", "extra_key"})

    def test_openai_body_translates_through_the_adapter(self):
        response = decisions.translate_response(openai_body(ANSWERS, input_tokens=42),
                                                QUESTIONS)
        self.assertIsNone(response.error)
        self.assertEqual(response.answers, ANSWERS)
        self.assertEqual(response.usage, {"input_tokens": 42, "output_tokens": 0})


class ScriptedHttpsTests(unittest.TestCase):
    def test_scripted_https_serves_the_hosted_adapter_through_http_client(self):
        script = ScriptedHTTPS([Reply(body=openai_body(ANSWERS), chunk_size=7)],
                               host="api.openai.com")
        exchange = script.exchange(decisions.HOST, decisions.PATH)
        with tempfile.TemporaryDirectory() as td:
            gateway = ValidatedGateway(DecisionsProvider(KEY, environ={}, exchange=exchange),
                                       Path(td) / "receipts")
            answers = gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
            # The complete 200 keeps the connection until the gateway closes.
            self.assertEqual(script.closed, [])
            gateway.close()
        self.assertEqual(answers, ANSWERS)
        self.assertTrue(script.exhausted)
        self.assertEqual(len(script.connects), 1)
        self.assertEqual(script.connects[0][0], ("api.openai.com", 443))
        self.assertIsInstance(script.contexts[0], ssl.SSLContext)
        (request,) = script.requests
        self.assertEqual((request.method, request.target), ("POST", "/v1/decisions"))
        self.assertEqual(request.header("Authorization"), "Bearer " + KEY)
        self.assertEqual(json.loads(request.body)["model"], "gpt-6-luna")
        self.assertEqual(script.closed, [0])

    def test_keep_alive_reuse_and_settimeout_are_recorded(self):
        script = ScriptedHTTPS([Reply(body=b'{"n":1}'), Reply(body=b'{"n":2}')])
        connection = script.https_connection("openrouter.ai", 443, timeout=5.0)
        bodies = []
        for _ in range(2):
            connection.request("POST", "/api/alpha/decisions", body=b"{}")
            bodies.append(connection.getresponse().read())
        connection.close()
        self.assertEqual(bodies, [b'{"n":1}', b'{"n":2}'])
        self.assertEqual((len(script.connects), script.reuse_count), (1, 1))
        self.assertEqual(script.connects[0], (("openrouter.ai", 443), 5.0))
        sock = script(("openrouter.ai", 443), 2.0)
        sock.settimeout(1.5)
        sock.settimeout(None)
        self.assertEqual(script.settimeout_calls, [(1, 1.5), (1, None)])
        self.assertEqual(sock.pending(), 0)
        self.assertFalse(sock.readable_idle())

    def test_delays_advance_only_the_fake_clock(self):
        clock = FakeClock(0.0)
        body = b'{"answers": {}}'
        script = ScriptedHTTPS([Reply(body=body, chunk_size=4, delay_between=0.4),
                                Reply(body=body, delay_before=2.0)], clock=clock)
        connection = script.https_connection("h", 443, timeout=0.5)
        connection.request("POST", "/", body=b"x")
        # Each read waits 0.4 s < 0.5 s: a trickle defeats per-operation timeouts.
        self.assertEqual(connection.getresponse().read(), body)
        self.assertAlmostEqual(clock.now, 0.4 * 3)
        connection.request("POST", "/", body=b"y")
        with self.assertRaises(TimeoutError):
            connection.getresponse()
        self.assertAlmostEqual(clock.now, 0.4 * 3 + 0.5)

    def test_chunked_bodies_and_scripted_failures(self):
        body = b'{"chunked": true}'
        script = ScriptedHTTPS([
            Reply(body=body, chunked=True, chunk_size=3),
            Reply(body=body, fail_after=5, fail_with=ConnectionResetError("reset")),
            ConnectFailure(),
            SendFailure(),
            Silence(),
        ])
        connection = script.https_connection("h", 443, timeout=1.0)
        connection.request("POST", "/", body=b"a")
        self.assertEqual(connection.getresponse().read(), body)
        connection.request("POST", "/", body=b"b")
        response = connection.getresponse()
        with self.assertRaises(ConnectionResetError):
            response.read()
        self.assertIsInstance(script.raised[-1][1], ConnectionResetError)
        connection.close()
        with self.assertRaises(ConnectionRefusedError):
            script.https_connection("h", 443, timeout=1.0).request("POST", "/", body=b"c")
        failing = script.https_connection("h", 443, timeout=1.0)
        with self.assertRaises(BrokenPipeError):
            failing.request("POST", "/", body=b"d")
        silent = script.https_connection("h", 443, timeout=1.0)
        silent.request("POST", "/", body=b"e")
        with self.assertRaises(TimeoutError):
            silent.getresponse()
        self.assertTrue(script.exhausted)
        with self.assertRaises(AssertionError):
            silent.close()
            script.https_connection("h", 443, timeout=1.0).request("POST", "/", body=b"f")
        self.assertEqual([r.body for r in script.requests], [b"a", b"b", b"d", b"e", b"f"])

    def test_scripted_hosted_adapter_failures_map_to_fixed_codes(self):
        cases = ((Reply(status=503, body=b"{}"), "http_server_error"),
                 (Reply(body=openai_body(ANSWERS), delay_before=120.0), "deadline_exceeded"),
                 (ConnectFailure(), "transport_failed"))
        for step, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as td:
                script = ScriptedHTTPS([step])
                exchange = script.exchange(decisions.HOST, decisions.PATH)
                with patch.object(socket, "create_connection",
                                  side_effect=AssertionError("real connector")):
                    gateway = ValidatedGateway(
                        DecisionsProvider(KEY, environ={}, exchange=exchange),
                        Path(td) / "receipts")
                    with self.assertRaises(ProviderError) as caught:
                        gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
                    gateway.close()
                self.assertEqual(caught.exception.code, code)


class FakeTimeTests(unittest.TestCase):
    def test_fake_sleep_and_seeded_rng_are_deterministic(self):
        clock = FakeClock(10.0)
        sleep = FakeSleep(clock)
        sleep(1.5)
        sleep(0)
        self.assertEqual((clock(), clock.monotonic(), sleep.calls, sleep.total),
                         (11.5, 11.5, [1.5, 0], 1.5))
        with self.assertRaises(ValueError):
            sleep(-1)
        with self.assertRaises(AssertionError):
            clock.advance(-0.1)
        first = [seeded_rng(7).uniform(0, 8) for _ in range(3)]
        self.assertEqual(first, [seeded_rng(7).uniform(0, 8) for _ in range(3)])
        rng = seeded_rng(7)
        self.assertNotEqual(rng.random(), rng.random())


class ProviderSeamTests(unittest.TestCase):
    def test_make_provider_returns_the_hosted_adapter(self):
        with clean_provider_env():
            provider = cli.make_provider(argparse.Namespace())
        self.assertIsInstance(provider, DecisionsProvider)
        with self.assertRaises(ProviderError) as caught:
            provider.require_available()
        self.assertEqual(caught.exception.code, "provider_unavailable")

    def test_cli_builds_its_provider_only_through_make_provider(self):
        provider = DecisionsProvider(environ={})
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as td, \
                patch.object(cli, "make_provider", return_value=provider) as seam, \
                patch("decision_bug_hunter.__main__.DecisionsProvider",
                      side_effect=AssertionError("bypassed the seam")), \
                patch.object(Source, "read", side_effect=AssertionError("source read")), \
                redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli.main(["absent-target.py", "--scope", "standalone",
                             "--output-dir", str(Path(td) / "out")])
            self.assertFalse((Path(td) / "out").exists())
        self.assertEqual(code, 2)
        self.assertIn("provider_unavailable", err.getvalue())
        seam.assert_called_once()
        self.assertEqual(Path(seam.call_args.args[0].file).name, "absent-target.py")

    def test_no_test_patches_the_provider_class_on_the_cli(self):
        pattern = re.compile(r"""cli\s*,\s*['"]DecisionsProvider['"]""")
        offenders = [path.name for path in Path(__file__).parent.glob("test_*.py")
                     if pattern.search(path.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [])


class HttpClientSanityTests(unittest.TestCase):
    def test_scripted_connection_is_plain_http_client(self):
        script = ScriptedHTTPS([])
        connection = script.https_connection("h", 443)
        self.assertIsInstance(connection, http.client.HTTPConnection)
        self.assertNotIsInstance(connection, http.client.HTTPSConnection)


if __name__ == "__main__":
    unittest.main()
