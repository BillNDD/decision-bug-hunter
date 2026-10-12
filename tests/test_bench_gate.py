"""The benchmark gate: golden values on two fast scenarios, and its comparison rules.

The gate runs in subprocesses (one per scenario, PYTHONHASHSEED=0), so this
module needs only the offline suite. It runs on every supported Python.
"""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "tools" / "bench" / "bench.py"
GOLDEN = ROOT / "tools" / "bench" / "golden.json"


def load_bench():
    spec = importlib.util.spec_from_file_location("dbh_bench_gate_under_test", BENCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bench = load_bench()


def golden_entry():
    return {"config": {}, "jobs": 1, "fingerprint": "f" * 64,
            "request_envelopes_sha256": "e" * 64,
            "cases": [{"id": "C001", "report_sha256": "r" * 64, "receipts_sha256": "t" * 64,
                       "receipt_files": 2}],
            "exact": {"provider_calls": 10, "receipt_writes": 20},
            "counters": {**{name: 100 for name in bench.GATED},
                         "dbh_ncalls": 1000, "json_dumps_chars": 5000, "sha256_calls": 40}}


def observed(golden, *, counters=None, exact=None, fingerprint=None, timing_affected=0):
    record = copy.deepcopy(golden)
    record.update(timing_affected=timing_affected, deterministic=True)
    record["counters"].update(counters or {})
    record["exact"].update(exact or {})
    if fingerprint is not None:
        record["fingerprint"] = fingerprint
    return record


class GateComparisonTests(unittest.TestCase):
    def test_identical_record_passes_silently(self):
        golden = golden_entry()
        failures, notices = bench.gate_compare(golden, observed(golden))
        self.assertEqual(failures, [])
        self.assertEqual(notices, [])

    def test_modified_fingerprint_fails(self):
        golden = golden_entry()
        failures, _ = bench.gate_compare(golden, observed(golden, fingerprint="0" * 64))
        self.assertTrue(any("fingerprint differs" in line for line in failures), failures)

    def test_modified_envelope_hash_fails(self):
        golden = golden_entry()
        record = observed(golden)
        record["request_envelopes_sha256"] = "0" * 64
        failures, _ = bench.gate_compare(golden, record)
        self.assertTrue(any("request_envelopes_sha256" in line for line in failures), failures)

    def test_exact_value_change_fails(self):
        golden = golden_entry()
        failures, _ = bench.gate_compare(golden, observed(golden, exact={"provider_calls": 11}))
        self.assertEqual(failures, ["exact provider_calls: 10 -> 11"])

    def test_counter_three_percent_over_fails(self):
        golden = golden_entry()
        failures, _ = bench.gate_compare(golden, observed(golden, counters={"dbh_ncalls": 1030}))
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("dbh_ncalls", failures[0])

    def test_counter_one_percent_over_passes(self):
        golden = golden_entry()
        failures, notices = bench.gate_compare(golden, observed(golden,
                                                                counters={"dbh_ncalls": 1010}))
        self.assertEqual(failures, [])
        self.assertEqual(notices, [])

    def test_byte_counter_tolerance_is_one_percent(self):
        golden = golden_entry()
        ok, _ = bench.gate_compare(golden, observed(golden, counters={"json_dumps_chars": 5050}))
        self.assertEqual(ok, [])
        failures, _ = bench.gate_compare(golden,
                                         observed(golden, counters={"json_dumps_chars": 5060}))
        self.assertTrue(any("json_dumps_chars" in line for line in failures), failures)

    def test_counter_five_percent_under_passes_with_ratchet_notice(self):
        golden = golden_entry()
        failures, notices = bench.gate_compare(golden, observed(golden,
                                                                counters={"dbh_ncalls": 950}))
        self.assertEqual(failures, [])
        self.assertEqual(len(notices), 1, notices)
        self.assertIn("--update-golden", notices[0])

    def test_missing_golden_entry_fails(self):
        failures, notices = bench.gate_compare(None, observed(golden_entry()))
        self.assertEqual(len(failures), 1)
        self.assertIn("no golden entry", failures[0])
        self.assertEqual(notices, [])

    def test_timing_affected_run_fails(self):
        golden = golden_entry()
        failures, _ = bench.gate_compare(golden, observed(golden, timing_affected=1))
        self.assertTrue(any("timing-affected" in line for line in failures), failures)

    def test_seed_runs_may_differ_only_in_byte_band_within_tolerance(self):
        golden = golden_entry()
        first = observed(golden, counters={"json_dumps_chars": 5000})
        second = observed(golden, counters={"json_dumps_chars": 5010})
        hard, noted = bench.record_differences(first, second)
        self.assertEqual(hard, [])
        self.assertEqual(len(noted), 1)

    def test_seed_runs_may_not_differ_in_call_counts(self):
        golden = golden_entry()
        first = observed(golden)
        second = observed(golden, counters={"dbh_ncalls": 1001})
        hard, _ = bench.record_differences(first, second)
        self.assertEqual(hard, ["counters.dbh_ncalls"])


class CounterVersionRuleTests(unittest.TestCase):
    """The cost counters are comparable only on the Python minor version that recorded them."""

    def test_counters_over_ceiling_are_informational_when_not_gated(self):
        golden = golden_entry()
        record = observed(golden, counters={"dbh_ncalls": 5000, "sha256_calls": 400})
        failures, notices = bench.gate_compare(golden, record, gate_counters=False)
        self.assertEqual(failures, [])
        self.assertEqual(len(notices), 1, notices)
        self.assertIn("informational", notices[0])
        self.assertIn("dbh_ncalls 1000 -> 5000", notices[0])
        self.assertIn("sha256_calls 40 -> 400", notices[0])
        self.assertNotIn("json_dumps_chars", notices[0])
        self.assertNotIn("none above its ceiling", notices[0])

    def test_counters_within_ceiling_still_get_a_notice_when_not_gated(self):
        golden = golden_entry()
        failures, notices = bench.gate_compare(golden, observed(golden), gate_counters=False)
        self.assertEqual(failures, [])
        self.assertEqual(len(notices), 1, notices)
        self.assertIn("informational", notices[0])
        self.assertIn("none above its ceiling", notices[0])

    def test_a_missing_counter_fails_even_when_not_gated(self):
        golden = golden_entry()
        for gate_counters in (True, False):
            with self.subTest(gate_counters=gate_counters):
                record = observed(golden)
                del record["counters"]["dbh_ncalls"]
                failures, notices = bench.gate_compare(golden, record,
                                                       gate_counters=gate_counters)
                self.assertEqual(failures, ["counter dbh_ncalls missing"])
                self.assertNotIn("dbh_ncalls", " ".join(notices))
        empty = observed(golden)
        empty["counters"] = {}
        failures, _ = bench.gate_compare(golden, empty, gate_counters=False)
        self.assertEqual(len(failures), len(bench.GATED), failures)

    def test_identity_and_exact_values_still_fail_when_not_gated(self):
        golden = golden_entry()
        record = observed(golden, fingerprint="0" * 64, exact={"provider_calls": 11},
                          counters={"dbh_ncalls": 5000}, timing_affected=1)
        failures, _ = bench.gate_compare(golden, record, gate_counters=False)
        text = "\n".join(failures)
        self.assertIn("fingerprint differs", text)
        self.assertIn("exact provider_calls: 10 -> 11", text)
        self.assertIn("timing-affected", text)
        self.assertNotIn("dbh_ncalls", text)

    def test_missing_golden_entry_still_fails_when_not_gated(self):
        failures, _ = bench.gate_compare(None, observed(golden_entry()), gate_counters=False)
        self.assertEqual(len(failures), 1)

    def test_counters_are_gated_by_default(self):
        golden = golden_entry()
        failures, _ = bench.gate_compare(golden, observed(golden, counters={"dbh_ncalls": 1030}))
        self.assertEqual(len(failures), 1, failures)

    def test_minor_version_of_a_version_string(self):
        self.assertEqual(bench.minor_of("3.12.10"), "3.12")
        self.assertEqual(bench.minor_of("3.11.0"), "3.11")
        self.assertEqual(bench.minor_of("3.13"), "3.13")
        self.assertEqual(bench.running_minor(), "%d.%d" % sys.version_info[:2])

    def test_gating_follows_the_recorded_minor_version(self):
        meta = {"python_minor": "3.12", "recorded_with_python": "3.12.10"}
        for running, gated in (("3.12", True), ("3.11", False), ("3.13", False)):
            with self.subTest(running=running):
                with mock.patch.object(bench, "running_minor", return_value=running):
                    self.assertEqual(bench.counters_gated(meta), gated)

    def test_the_version_is_read_from_the_full_string_when_the_minor_is_absent(self):
        with mock.patch.object(bench, "running_minor", return_value="3.11"):
            self.assertEqual(bench.recorded_minor({"recorded_with_python": "3.12.10"}), "3.12")
            self.assertFalse(bench.counters_gated({"recorded_with_python": "3.12.10"}))

    def test_a_golden_file_that_names_no_version_is_gated(self):
        with mock.patch.object(bench, "running_minor", return_value="3.11"):
            self.assertIsNone(bench.recorded_minor({}))
            self.assertTrue(bench.counters_gated({}))

    @staticmethod
    def _bench_state(stack, running, golden, **extra):
        """Patch the golden file, its recorded version and the running version."""
        patches = {"running_minor": mock.Mock(return_value=running),
                   "load_golden": mock.Mock(return_value=golden),
                   "load_golden_meta": mock.Mock(return_value={"python_minor": "3.12"}),
                   **extra}
        for name, replacement in patches.items():
            stack.enter_context(mock.patch.object(bench, name, replacement))

    def test_do_gate_reports_counters_as_notice_on_another_minor_version(self):
        golden = golden_entry()
        record = observed(golden, counters={"dbh_ncalls": 5000})
        args = types.SimpleNamespace(parallel=1, count_receipts="memory")
        for running, expected_code, expected_text in (
                ("3.11", 0, "NOTICE cost counters are informational"),
                ("3.12", 1, "FAIL dbh_ncalls")):
            out = io.StringIO()
            with self.subTest(running=running), contextlib.ExitStack() as stack:
                self._bench_state(stack, running, {"s": golden},
                                  run_children=mock.Mock(return_value={"s": record}))
                stack.enter_context(contextlib.redirect_stdout(out))
                self.assertEqual(bench.do_gate(["s"], args), expected_code, out.getvalue())
            self.assertIn(expected_text, out.getvalue())

    def test_update_golden_refuses_a_partial_record_on_another_minor_version(self):
        args = types.SimpleNamespace(parallel=1, count_receipts="memory")
        out = io.StringIO()
        run, write = mock.Mock(), mock.Mock()
        with contextlib.ExitStack() as stack:
            self._bench_state(stack, "3.11", {"a": golden_entry(), "b": golden_entry()},
                              run_children=run, write_golden=write)
            stack.enter_context(contextlib.redirect_stdout(out))
            self.assertEqual(bench.do_update(["a"], args), 1)
        run.assert_not_called()
        write.assert_not_called()
        self.assertIn("mix versions", out.getvalue())

    def _run_update(self, running, recorded_meta, golden, names):
        """do_update with the benchmark runs mocked; returns (exit code, run, write, output)."""
        args = types.SimpleNamespace(parallel=1, count_receipts="memory")
        record = observed(golden_entry())
        run = mock.Mock(return_value={name: record for name in names})
        write = mock.Mock()
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            self._bench_state(stack, running, dict(golden), run_children=run,
                              write_golden=write,
                              load_golden_meta=mock.Mock(return_value=recorded_meta))
            stack.enter_context(contextlib.redirect_stdout(out))
            code = bench.do_update(names, args)
        return code, run, write, out.getvalue()

    def test_update_golden_may_re_record_every_scenario_on_another_minor_version(self):
        golden = {"a": golden_entry(), "b": golden_entry()}
        code, run, write, output = self._run_update(
            "3.11", {"python_minor": "3.12"}, golden, ["a", "b"])
        self.assertEqual(code, 0, output)
        self.assertEqual(run.call_count, 2)
        write.assert_called_once()

    def test_update_golden_may_re_record_some_scenarios_on_the_recorded_minor_version(self):
        golden = {"a": golden_entry(), "b": golden_entry()}
        code, _, write, output = self._run_update("3.12", {"python_minor": "3.12"}, golden, ["a"])
        self.assertEqual(code, 0, output)
        write.assert_called_once()

    def test_update_golden_does_not_refuse_when_the_golden_names_no_version(self):
        golden = {"a": golden_entry(), "b": golden_entry()}
        code, _, write, output = self._run_update("3.11", {}, golden, ["a"])
        self.assertEqual(code, 0, output)
        self.assertNotIn("mix versions", output)
        write.assert_called_once()

    def test_write_golden_records_the_running_python_minor_version(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "golden.json"
            with mock.patch.object(bench, "GOLDEN", target), \
                    mock.patch.object(bench, "running_minor", return_value="3.99"):
                bench.write_golden({})
                meta = json.loads(target.read_text(encoding="utf-8"))["meta"]
                self.assertEqual(meta["python_minor"], "3.99")
                self.assertIn("recorded_with_python", meta)
                self.assertEqual(bench.load_golden_meta()["python_minor"], "3.99")
                self.assertEqual(bench.recorded_minor(bench.load_golden_meta()), "3.99")


class GoldenFileTests(unittest.TestCase):
    def test_golden_records_the_python_minor_version(self):
        import json
        meta = json.loads(GOLDEN.read_text(encoding="utf-8"))["meta"]
        self.assertRegex(meta["python_minor"], r"^3\.\d+$")
        self.assertEqual(bench.minor_of(meta["recorded_with_python"]), meta["python_minor"])

    def test_golden_covers_every_scenario_with_every_field(self):
        import json
        scenarios = json.loads(GOLDEN.read_text(encoding="utf-8"))["scenarios"]
        self.assertEqual(set(scenarios), set(bench.SCENARIOS))
        for name, entry in scenarios.items():
            self.assertEqual(set(entry), set(bench.GOLDEN_FIELDS), name)
            self.assertEqual(set(entry["counters"]), set(bench.GATED), name)
            self.assertIsInstance(entry["exact"]["provider_calls"], int, name)


def golden_scenarios():
    import json
    return json.loads(GOLDEN.read_text(encoding="utf-8"))["scenarios"]


class TileSieveScenarioTests(unittest.TestCase):
    """The recorded values of the whole-file Tile Sieve scenarios (OpenAI judge)."""

    def test_the_four_scenarios_are_recorded(self):
        golden = golden_scenarios()
        for name in ("catalog-4-tile-sieve", "catalog-tile-sieve", "synth-200-tile-sieve",
                     "synth-1000-tile-sieve"):
            with self.subTest(name=name):
                self.assertIn(name, golden)
                self.assertEqual(golden[name]["config"], {"search_policy": "tile-sieve-beta"})
                self.assertEqual(bench.SCENARIOS[name]["config"], golden[name]["config"])
                self.assertNotIn("model", bench.SCENARIOS[name])

    def test_the_oversize_file_falls_back_to_exactly_the_legacy_requests(self):
        golden = golden_scenarios()
        legacy, sieve = golden["synth-1000"], golden["synth-1000-tile-sieve"]
        self.assertEqual(sieve["exact"], legacy["exact"])
        self.assertEqual(sieve["request_envelopes_sha256"], legacy["request_envelopes_sha256"])
        # Only the report differs: it names the policy and the fallback.
        self.assertNotEqual(sieve["fingerprint"], legacy["fingerprint"])

    def test_the_catalog_asks_36_distinct_tile_requests_then_the_focus_requests(self):
        exact = golden_scenarios()["catalog-tile-sieve"]["exact"]
        phases = exact["rounds_by_phase"]
        self.assertLessEqual(set(phases), {"ts-screen-l0", "ts-screen-l1", "ts-focus"})
        self.assertEqual(phases["ts-screen-l0"] + phases["ts-screen-l1"], 36)
        self.assertEqual(exact["provider_calls"], 36 + phases["ts-focus"])
        self.assertEqual(exact["unique_requests"], exact["provider_calls"])

    def test_a_file_that_fits_asks_its_two_looks_and_one_focus_request(self):
        exact = golden_scenarios()["synth-200-tile-sieve"]["exact"]
        self.assertEqual(exact["rounds_by_phase"],
                         {"ts-focus": 1, "ts-screen-l0": 1, "ts-screen-l1": 1})
        self.assertEqual(exact["provider_calls"], 3)

    def test_the_short_catalog_subset_skips_the_second_look(self):
        phases = golden_scenarios()["catalog-4-tile-sieve"]["exact"]["rounds_by_phase"]
        self.assertLessEqual(set(phases), {"ts-screen-l0", "ts-focus"})


class FullPrecisionJudgeTests(unittest.TestCase):
    """The offline Microsoft judge writes full-precision, identity-consistent answers."""

    SEED = b"seed"

    def test_a_noul_value_moves_by_under_a_tenth_of_a_nanounit(self):
        moved = set()
        for index in range(50):
            answer = bench.full_precision_answer(self.SEED, f"q{index}",
                                                 {"type": "noul", "noul": 0.95})
            self.assertEqual(answer["type"], "noul")
            self.assertLessEqual(abs(answer["noul"] - 0.95), 1.0001e-10)
            moved.add(answer["noul"])
        self.assertGreater(len(moved), 40)
        self.assertNotEqual(round(min(moved), 2), min(moved))

    def test_a_noul_value_stays_a_probability(self):
        for value in (0, 1, 0.0, 1.0):
            answer = bench.full_precision_answer(self.SEED, "q", {"type": "noul", "noul": value})
            self.assertTrue(0.0 <= answer["noul"] <= 1.0, answer)

    def test_a_choice_keeps_its_argmax_mass_and_confidence_identity(self):
        for options in (["a", "b"], ["L1-1", "L2-2", "L3-3", "none", "unlocalized"]):
            for chosen in options:
                with self.subTest(options=len(options), chosen=chosen):
                    given = {"type": "choice", "choice": chosen, "confidence": 1,
                             "probabilities": {k: int(k == chosen) for k in options}}
                    answer = bench.full_precision_answer(self.SEED, "where", given)
                    values = answer["probabilities"]
                    self.assertEqual(list(values), options)
                    self.assertEqual(answer["choice"], chosen)
                    self.assertEqual(max(values, key=values.get), chosen)
                    self.assertLess(abs(sum(values.values()) - 1), 1e-12)
                    self.assertTrue(all(0.0 <= v <= 1.0 for v in values.values()))
                    k = len(options)
                    expected = (values[chosen] - 1 / k) / (1 - 1 / k)
                    self.assertAlmostEqual(answer["confidence"], expected, delta=1e-15)
                    self.assertNotEqual(values[chosen], 1)

    def test_the_answer_is_deterministic_and_depends_on_the_request(self):
        given = {"type": "noul", "noul": 0.05}
        first = bench.full_precision_answer(self.SEED, "q", given)
        self.assertEqual(first, bench.full_precision_answer(self.SEED, "q", given))
        self.assertNotEqual(first, bench.full_precision_answer(b"other", "q", given))

    def test_the_fake_exchange_answers_in_the_microsoft_shape(self):
        from decimal import Decimal
        import json
        bench._import_code()

        class Judge:
            def answer(self, qid, question, state):
                if question["type"] == "choice":
                    return {"type": "choice", "choice": "none", "confidence": 1,
                            "probabilities": {"a": 0, "none": 1}}
                return {"type": "noul", "noul": 0.05}

        body = json.dumps({"model": "microsoft/microsoft-decision-1", "state": {},
                           "questions": {"p": {"type": "noul"}, "c": {"type": "choice"}}}
                          ).encode()
        model = "microsoft/microsoft-decision-1"
        fake = bench.FakeExchange(Judge(), bench.JudgeClock(), None, model, True)
        data = json.loads(fake.post(body, {}, 1.0).body)
        self.assertEqual(data["model"], model + "-20261009")
        self.assertEqual(data["provider"], "Azure")
        tokens = max(1, len(body) // 4)
        self.assertEqual(data["usage"], {"input_tokens": tokens, "output_tokens": 0,
                                         "cost": float(Decimal(tokens) * Decimal("4.2e-8"))})
        self.assertNotEqual(data["answers"]["p"]["noul"], 0.05)
        self.assertNotEqual(data["answers"]["c"]["probabilities"]["none"], 1)
        plain = bench.FakeExchange(Judge(), bench.JudgeClock(), None)
        data = json.loads(plain.post(body, {}, 1.0).body)
        self.assertEqual(data["model"], "openai/gpt-6-luna-decisions-20261006")
        self.assertEqual(data["answers"]["p"]["noul"], 0.05)

    def test_the_offline_provider_selects_the_model(self):
        bench._import_code()
        judge = bench.make_judge([])
        provider = bench.offline_provider(judge, bench.JudgeClock(), None,
                                          model="microsoft/microsoft-decision-1",
                                          full_precision=True)
        self.addCleanup(provider.close)
        self.assertEqual(provider.model_spec.id, "microsoft/microsoft-decision-1")
        self.assertEqual(provider.model_spec.judge, "microsoft")
        default = bench.offline_provider(judge, bench.JudgeClock(), None)
        self.addCleanup(default.close)
        self.assertEqual(default.model_spec.judge, "openai")


class MicrosoftScenarioTests(unittest.TestCase):
    """catalog-4-microsoft: legacy-v1 through the real OpenRouter adapter, full precision."""

    @staticmethod
    def record(name):
        return bench.run_child(name, seed=0, count_receipts="memory", reps=0, profile=False,
                               tracemalloc_run=False)

    def test_the_scenario_asks_the_microsoft_model_with_full_precision(self):
        spec = bench.SCENARIOS["catalog-4-microsoft"]
        self.assertEqual(spec["model"], "microsoft/microsoft-decision-1")
        self.assertEqual(spec["precision"], "full")
        self.assertEqual(spec["config"], {})
        self.assertIn("catalog-4-microsoft", golden_scenarios())
        self.assertEqual(bench.route_options(spec),
                         {"model": "microsoft/microsoft-decision-1", "full_precision": True})
        self.assertEqual(bench.route_options(bench.SCENARIOS["catalog-4"]),
                         {"model": None, "full_precision": False})

    def test_the_report_names_the_judge_and_the_mass_gate_has_no_rounding_allowance(self):
        record = self.record("catalog-4-microsoft")
        self.assertEqual(record["info"]["judges"], ["microsoft"])
        halves = record["info"]["gate_half_quanta"]
        self.assertGreater(sum(halves.values()), 0)
        self.assertEqual(set(halves), {"0"})
        golden = golden_scenarios()["catalog-4-microsoft"]
        self.assertEqual(record["fingerprint"], golden["fingerprint"])
        self.assertEqual(record["exact"], golden["exact"])

    def test_the_openai_scenario_names_no_judge_and_keeps_its_display_quantum(self):
        record = self.record("catalog-4")
        self.assertEqual(record["info"]["judges"], ["openai"])
        self.assertEqual(set(record["info"]["gate_half_quanta"]), {"1/200"})

    def test_the_microsoft_run_differs_from_the_openai_run_only_in_its_answers(self):
        golden = golden_scenarios()
        self.assertNotEqual(golden["catalog-4-microsoft"]["fingerprint"],
                            golden["catalog-4"]["fingerprint"])
        self.assertEqual(golden["catalog-4-microsoft"]["exact"]["rounds_by_phase"],
                         golden["catalog-4"]["exact"]["rounds_by_phase"])
        self.assertEqual(golden["catalog-4-microsoft"]["request_envelopes_sha256"],
                         golden["catalog-4"]["request_envelopes_sha256"])


class GateRunTests(unittest.TestCase):
    def test_gate_passes_on_two_fast_scenarios(self):
        result = subprocess.run(
            [sys.executable, str(BENCH), "--gate", "--scenario", "synth-200",
             "--scenario", "catalog-4"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=1800)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-2000:])
        self.assertIn("gate passed", result.stdout)
        self.assertIn("synth-200: ok", result.stdout)
        self.assertIn("catalog-4: ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
