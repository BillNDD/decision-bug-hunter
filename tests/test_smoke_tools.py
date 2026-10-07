"""Smoke tooling v2: observed fixtures, builder drift and runner sanitizing.

Fully offline: the runners talk to ``tests.fakes.ScriptedHTTPS`` through a
real ``HttpsExchange``; no socket is opened and no provider key is read.
The tools live outside the package (tools/smoke), so these tests skip when
that directory is not present, as in an sdist that prunes it.
"""
from decimal import Decimal
import importlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

from decision_bug_hunter import openrouter, protocol
from decision_bug_hunter.hosted import error_object
from tests.fakes import ConnectFailure, FakeClock, Reply, ScriptedHTTPS
from tests.support import clean_provider_env, openai_body, openrouter_body

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "tools" / "smoke"
FIXTURES = ROOT / "tests" / "fixtures" / "openrouter" / "observed" / "2026-10-06"
PROMOTED = {"S01", "S02", "S08", "S10", "S10b", "S11", "S16", "S17", "S18", "S19"}
KEY = "offline-smoke-sentinel-7c2e"
RAY = "8c1f2e3d4a5b6c7d-GRU"
EDGE = re.compile(r"[0-9a-f]+-[A-Z]{3}")
SECRET_MESSAGE = "Model zzz-private-detail does not exist"


def tool(name):
    if str(SMOKE) not in sys.path:
        sys.path.insert(0, str(SMOKE))
    return importlib.import_module(name)


def noisy_headers(body, *, extra=()):
    return [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
            ("cf-ray", RAY), ("Server", "cloudflare"), ("Set-Cookie", "session=abc123"),
            ("X-Generation-Id", "gen-dec-scripted0001"), *extra]


def walk(value, key=None):
    """Yield (key, value) for every leaf and container."""
    yield key, value
    if isinstance(value, dict):
        for k, v in value.items():
            yield from walk(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v, key)


@unittest.skipUnless(SMOKE.is_dir() and FIXTURES.is_dir(), "tools/smoke or fixtures absent")
class ObservedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = tool("build_openrouter")
        cls.common = tool("smoke_common")
        entries, files = cls.builder.build("v1")
        cls.v1_requests = {e["id"]: json.loads(files[e["file"]]) for e in entries}
        cls.v1_hashes = {e["id"]: e["request_sha256"] for e in entries}
        cls.fixtures = {path.stem: json.loads(path.read_text(encoding="utf-8"))
                        for path in sorted(FIXTURES.glob("S*.json"))}

    def test_promoted_set_is_exact_and_excludes_s15(self):
        self.assertEqual(set(self.fixtures), PROMOTED)
        index = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(set(index["ids"]), PROMOTED)
        self.assertEqual(index["builder_state_layout"], "v1")
        self.assertFalse(list(FIXTURES.glob("S15*")))

    def test_observed_2026_10_06_decode(self):
        expected_errors = {"S08": "http_rejected", "S16": "http_rejected",
                           "S18": "routing_no_endpoint"}
        for sid, fixture in self.fixtures.items():
            with self.subTest(sid):
                questions = self.v1_requests[sid]["questions"]
                raw = json.dumps(fixture["body"]).encode()
                if fixture["status"] != 200:
                    error = error_object(raw)
                    self.assertEqual(openrouter.status_code(fixture["status"], error),
                                     expected_errors[sid])
                    self.assertEqual(fixture["code"], expected_errors[sid])
                    self.assertEqual(openrouter.error_fields(fixture["status"], error),
                                     fixture["error"])
                    self.assertEqual(fixture["error"]["error_code"], fixture["status"])
                    continue
                response = openrouter.decode_response(raw, questions)
                self.assertEqual(response.provenance["model_returned"],
                                 "openai/gpt-6-luna-decisions-20261006")
                self.assertEqual(response.provenance["upstream_provider"], "OpenAI")
                usage = fixture["body"]["usage"]
                self.assertEqual(usage["output_tokens"], 0)
                self.assertEqual(response.cost_usd,
                                 Decimal(usage["input_tokens"]) * Decimal("1e-7"))
                if any(q.get("type") == "score" for q in questions.values()):
                    # Score questions stay locally unsupported (S01, S17).
                    self.assertEqual(response.error, "response_schema")
                    continue
                self.assertIsNone(response.error)
                self.assertEqual(list(response.answers), list(questions))
                # Strict mass and argmax hold on every observed vector (D2).
                protocol.validate_answer_objects(response.answers, questions)

    def test_observed_fixtures_have_no_message_metadata_ids_or_unlisted_headers(self):
        common = self.common
        allowed = set(common.ALLOWED_HEADERS) | set(common.PLACEHOLDER_HEADERS)
        for path in sorted(FIXTURES.glob("*.json")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path.name):
                self.assertNotIn("gen-dec-", text)
                self.assertNotIn("cf-ray", text.lower())
                self.assertIsNone(EDGE.search(text))
                data = json.loads(text)
                if path.name == "index.json":
                    continue
                for name, value in data["headers"].items():
                    self.assertTrue(name in allowed or name.startswith("x-ratelimit-"), name)
                    if name in common.PLACEHOLDER_HEADERS:
                        self.assertEqual(value, common.PLACEHOLDER_HEADERS[name])
                for name in data["dropped_header_names"]:
                    self.assertNotEqual(name, "cf-ray")
                for key, value in walk(data):
                    self.assertNotEqual(key, "message")
                    if key == "id" and value is not data["id"]:
                        self.assertIn(value, ("<gen-id>", "<id>"))
                    if key == "metadata":
                        for inner_key, leaf in walk(value):
                            if isinstance(leaf, str) and inner_key not in (
                                    "error_type", "provider_code"):
                                self.assertEqual(leaf, common.WITHHELD)

    def test_builder_output_matches_committed_bodies(self):
        builder = self.builder
        entries, files = builder.build()
        suite = SMOKE / "openrouter"
        committed = {path.name for path in suite.glob("*.json")} - {"manifest.json"}
        self.assertEqual(committed, set(files))
        for name, data in files.items():
            self.assertEqual((suite / name).read_bytes(), data, name)
        self.assertEqual((suite / "manifest.json").read_bytes(), builder.manifest_bytes(entries))
        manifest = json.loads((suite / "manifest.json").read_text(encoding="utf-8"))
        ids = {entry["id"] for entry in manifest["entries"]}
        observed = manifest["observed"]["2026-10-06"]
        self.assertEqual(observed["state_layout"], "v1")
        self.assertFalse(any(sid.startswith("S15") for sid in ids | set(observed["request_sha256"])))
        for sid, fixture in self.fixtures.items():
            self.assertEqual(fixture["request_sha256"], observed["request_sha256"][sid], sid)
        for sid, digest in observed["request_sha256"].items():
            self.assertEqual(self.v1_hashes[sid], digest, sid)
        families = {entry.get("family", entry["id"]) for entry in manifest["entries"]}
        for family in ("S01h", "S02s", "S12b", "S12c", "S13c", "S13c-pis", "S19b", "S19c",
                       "S20", "S21", "S22"):
            self.assertIn(family, families)
        optional = {entry["id"] for entry in manifest["entries"] if entry.get("optional")}
        self.assertEqual(optional, {"S21", "S22"})
        for name, data in files.items():
            lowered = data.decode("utf-8").lower()
            self.assertNotIn("typesafe", lowered, name)
            self.assertNotIn("jev", lowered, name)
        provider = openrouter.OpenRouterProvider(KEY, environ={})
        for entry in manifest["entries"]:
            if entry["send"] == "splice":
                payload = files[entry["file"]]
                self.assertLessEqual(len(payload), provider.model_spec.max_envelope_bytes)
                wire, questions = provider.encode(payload)
                self.assertLessEqual(len(questions), provider.model_spec.max_questions)
                self.assertIn(b'"provider":{"allow_fallbacks":false,"data_collection":"deny"}',
                              wire)


@unittest.skipUnless(SMOKE.is_dir(), "tools/smoke absent")
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.runner = tool("run_openrouter")
        self.common = tool("smoke_common")
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name) / "run"
        self.slept = []

    def run_scripted(self, argv, steps, *, runner=None, host=openrouter.HOST,
                     path=openrouter.PATH):
        runner = runner or self.runner
        clock = FakeClock()
        script = ScriptedHTTPS(steps, clock=clock, host=host)
        lines = []
        with clean_provider_env():
            code = runner.main([*argv, "--out", str(self.out), "--pause", "0"],
                               environ={runner.ROUTE.variable: KEY},
                               exchange=script.exchange(host, path), sleep=self.slept.append,
                               clock=clock, echo=lines.append)
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in
                   (self.out / "results.jsonl").read_text(encoding="utf-8").splitlines()]
        return script, records, lines

    def tiny_ok(self, **extra):
        body = openrouter_body({"q": {"type": "noul", "noul": Decimal("0.91")}})
        return Reply(body=body, headers=noisy_headers(body), **extra)

    def bad_model(self):
        body = json.dumps({"error": {"code": 400, "message": SECRET_MESSAGE}}).encode()
        return Reply(status=400, body=body, headers=noisy_headers(body))

    def test_runner_summary_contains_no_body_text_or_header_values(self):
        _script, records, lines = self.run_scripted(["--only", "S16,S19b"],
                                                    [self.bad_model(), self.tiny_ok()])
        self.assertEqual([(r["id"], r["status"], r["code"]) for r in records],
                         [("S16", 400, "http_rejected"), ("S19b", 200, "ok")])
        summary = (self.out / "summary.md").read_text(encoding="utf-8")
        results = (self.out / "results.jsonl").read_text(encoding="utf-8")
        for text in (summary, "\n".join(lines)):
            for forbidden in (RAY, "GRU", "cloudflare", "session=abc123", "gen-dec-",
                              "zzz-private-detail", "does not exist", "application/json",
                              "gpt-6-luna-decisions-20261006", "OpenAI", KEY):
                self.assertNotIn(forbidden, text)
        for forbidden in (RAY, "cloudflare", "session=abc123", "gen-dec-", "zzz-private-detail",
                          "does not exist", KEY):
            self.assertNotIn(forbidden, results)
        self.assertIn("| S16 |", summary)
        self.assertIn("http_rejected", summary)
        self.assertEqual(records[0]["error"], {"error_code": 400, "moderation": False,
                                               "routing_metadata": False})
        self.assertEqual(records[0]["body"], {"error": {"code": 400}})
        self.assertTrue((self.out / ".gitignore").is_file())
        self.assertTrue((self.out / "CACHEDIR.TAG").is_file())
        self.assertFalse((self.out / "raw").exists())

    def test_runner_drops_cf_ray_at_capture(self):
        kept, dropped = self.common.capture_headers(
            [("CF-RAY", RAY), ("Server", "cloudflare"), ("Content-Type", "application/json"),
             ("X-Generation-Id", "gen-dec-1"), ("X-Request-Id", "req_1"),
             ("X-RateLimit-Remaining", "9")], dropped=("cf-ray", "date"))
        self.assertEqual(kept, {"content-type": "application/json", "x-generation-id": "<gen-id>",
                                "x-request-id": "<request-id>", "x-ratelimit-remaining": "9"})
        self.assertEqual(dropped, ["date", "server"])
        _script, records, _lines = self.run_scripted(["--only", "S19b"], [self.tiny_ok()])
        results = (self.out / "results.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("cf-ray", results.lower())
        self.assertIsNone(EDGE.search(results))
        record = records[0]
        self.assertEqual(record["dropped_header_names"], ["server", "set-cookie"])
        self.assertEqual(record["headers"]["x-generation-id"], "<gen-id>")
        self.assertEqual(record["body"]["id"], "<gen-id>")
        self.assertEqual(record["send"], "splice")
        self.assertEqual(record["submission"], "sent")

    def test_runner_continues_after_network_exception(self):
        script, records, _lines = self.run_scripted(
            ["--only", "S20"], [ConnectFailure(), self.tiny_ok()])
        self.assertEqual(len(records), 2)
        failed, ok = records
        self.assertEqual((failed["status"], failed["phase"], failed["submission"], failed["code"]),
                         (None, "connect", "not_sent", "connect_failed"))
        self.assertEqual(failed["exception"], "os")
        self.assertEqual((ok["status"], ok["code"], ok["repeat"]), (200, "ok", 1))
        self.assertEqual(len(script.requests), 1)
        # The splice adds DBH's default routing object; the key never reaches a file.
        self.assertIn(b'"data_collection":"deny"', script.requests[0].body)
        self.assertEqual(script.requests[0].header("Authorization"), "Bearer " + KEY)
        self.assertEqual(script.requests[0].header("Accept-Encoding"), "identity")

    def test_runner_retries_rate_limit_once(self):
        body = json.dumps({"error": {"code": 429, "message": "slow down"}}).encode()
        limited = Reply(status=429, body=body, headers=noisy_headers(
            body, extra=(("Retry-After", "7"),)))
        _script, records, _lines = self.run_scripted(["--only", "S19b"], [limited, self.tiny_ok()])
        self.assertEqual([(r["attempt"], r["status"]) for r in records], [(1, 429), (2, 200)])
        self.assertEqual(records[0]["retry_reason"], "http_rate_limited")
        self.assertEqual(self.slept, [7.0])

    def test_keep_raw_writes_only_under_raw(self):
        self.run_scripted(["--only", "S19b", "--keep-raw"], [self.tiny_ok()])
        raw = list((self.out / "raw").iterdir())
        self.assertEqual([path.name for path in raw], ["S19b-r0-a1.json"])
        self.assertNotIn("gen-dec-", (self.out / "results.jsonl").read_text(encoding="utf-8"))

    def test_dry_run_needs_no_key_and_no_network(self):
        lines = []
        with clean_provider_env():
            self.assertEqual(self.runner.main(["--dry-run"], environ={}, echo=lines.append), 0)
        self.assertIn("No network use", lines[0])
        self.assertFalse(any("S15" in line for line in lines))
        self.assertFalse(any(line.split()[0] in ("S21", "S22") for line in lines[1:]))

    def test_openai_runner_shares_the_sanitizing_path(self):
        runner = tool("run_openai")
        entry = next(e for e in runner.build_entries() if e.id == "O01")
        answers = {}
        for name, question in entry.questions.items():
            if question["type"] == "noul":
                answers[name] = {"type": "noul", "noul": Decimal("0.4")}
            else:
                options = list(question["criteria"])
                answers[name] = {"type": "choice", "choice": options[0], "confidence": Decimal(1),
                                 "probabilities": {o: Decimal(int(i == 0))
                                                   for i, o in enumerate(options)}}
        body = openai_body(answers)
        reply = Reply(body=body, headers=noisy_headers(body, extra=(("x-request-id", "req_secret1"),)))
        script, records, _lines = self.run_scripted(["--only", "O01"], [reply], runner=runner,
                                                    host="api.openai.com", path="/v1/decisions")
        record = records[0]
        self.assertEqual((record["route"], record["status"], record["code"]), ("openai", 200, "ok"))
        self.assertEqual(record["headers"]["x-request-id"], "<request-id>")
        self.assertNotIn("req_secret1", (self.out / "results.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(script.requests[0].target, "/v1/decisions")

    def test_smoke_tools_use_the_exchange_and_never_urllib(self):
        sources = {path.name: path.read_text(encoding="utf-8") for path in SMOKE.glob("*.py")}
        for name, text in sources.items():
            self.assertIsNone(re.search(r"^\s*(?:import|from)\s+urllib", text, re.M), name)
        self.assertIn("from decision_bug_hunter.exchange import", sources["smoke_common.py"])
        for name in ("run_openrouter.py", "run_openai.py", "sanitize.py"):
            self.assertIn("import smoke_common", sources[name])
        self.assertFalse((ROOT / "tools" / "live_probe.py").exists())
        readme = (SMOKE / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("Authorization: Bearer", readme)
        self.assertNotIn("curl", readme)


@unittest.skipUnless(SMOKE.is_dir(), "tools/smoke absent")
class SanitizerTests(unittest.TestCase):
    V1 = {"id": "S18", "file": "S18-zdr-probe.json", "repeat": 0, "attempt": 1,
          "request_sha256": "a" * 64, "request_bytes": 322, "status": 404, "elapsed_s": 0.31,
          "headers": {"content-type": "application/json", "cf-ray": RAY,
                      "x-generation-id": "gen-dec-abc", "openrouter-region": "x"},
          "response": {"error": {"code": 404, "message": "No endpoints found matching ...",
                                 "metadata": {"failed_routing_step": "Filter by Data Policy",
                                              "routing_funnel": [{"step": "Filter"}],
                                              "user_id": "user_123"}}}}

    def setUp(self):
        self.sanitize = tool("sanitize")
        self.common = tool("smoke_common")

    def test_v1_record_sanitized_and_idempotent(self):
        clean = self.sanitize.sanitize_record(self.V1)
        self.assertEqual(clean["headers"], {"content-type": "application/json",
                                            "x-generation-id": "<gen-id>"})
        self.assertEqual(clean["dropped_header_names"], ["openrouter-region"])
        self.assertEqual(clean["code"], "routing_no_endpoint")
        self.assertTrue(clean["error"]["routing_metadata"])
        error = clean["body"]["error"]
        self.assertNotIn("message", error)
        self.assertEqual(error["metadata"]["failed_routing_step"], self.common.WITHHELD)
        self.assertEqual(error["metadata"]["user_id"], "<id>")
        text = json.dumps(clean)
        for forbidden in (RAY, "gen-dec-", "No endpoints", "Data Policy", "user_123"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(self.sanitize.sanitize_record(clean), clean)
        self.assertIsNone(self.sanitize.sanitize_record({**self.V1, "id": "S15"}))

    def test_in_place_moves_originals_and_promote_refuses_s15(self):
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            (run / "results.jsonl").write_text(json.dumps(self.V1) + "\n", encoding="utf-8")
            (run / "summary.md").write_text(f"headers {{'cf-ray': '{RAY}'}}\n", encoding="utf-8")
            self.sanitize.sanitize_in_place(run)
            self.assertTrue((run / "raw" / "results.unsanitized.jsonl").is_file())
            self.assertTrue((run / "raw" / "summary.unsanitized.md").is_file())
            for name in ("results.jsonl", "summary.md"):
                text = (run / name).read_text(encoding="utf-8")
                self.assertNotIn(RAY, text)
                self.assertNotIn("gen-dec-", text)
            self.assertTrue((run / ".gitignore").is_file())
            with self.assertRaises(SystemExit):
                self.sanitize.sanitize_in_place(run)
            with self.assertRaises(SystemExit):
                self.sanitize.promote(run, "2026-10-06", ["S15"], fixtures=run / "fixtures")
            written = self.sanitize.promote(run, "2026-10-06", ["S18"], layout="v1",
                                            fixtures=run / "fixtures")
            fixture = json.loads(written[0].read_text(encoding="utf-8"))
            self.assertEqual(fixture["builder"], {"state_layout": "v1"})
            self.assertEqual(fixture["status"], 404)


if __name__ == "__main__":
    unittest.main()
