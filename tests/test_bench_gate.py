"""The benchmark gate: golden values on two fast scenarios, and its comparison rules.

The gate runs in subprocesses (one per scenario, PYTHONHASHSEED=0), so this
module needs only the offline suite. It runs on every supported Python.
"""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

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


class GoldenFileTests(unittest.TestCase):
    def test_golden_covers_every_scenario_with_every_field(self):
        import json
        scenarios = json.loads(GOLDEN.read_text(encoding="utf-8"))["scenarios"]
        self.assertEqual(set(scenarios), set(bench.SCENARIOS))
        for name, entry in scenarios.items():
            self.assertEqual(set(entry), set(bench.GOLDEN_FIELDS), name)
            self.assertEqual(set(entry["counters"]), set(bench.GATED), name)
            self.assertIsInstance(entry["exact"]["provider_calls"], int, name)


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
