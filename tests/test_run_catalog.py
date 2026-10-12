"""Catalog runner scoring, summary, dry run and cost stop (tools/eval), fully offline.

``judge`` and ``summarize`` run on hand-built reports; the Tile Sieve dry run
only plans bytes; ``main`` runs with the CLI call replaced. The CLI is never
run and nothing touches the network. Skips when tools/eval is absent, as in an
sdist that prunes it.
"""
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import importlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "tools" / "eval"


def tool(name):
    if str(EVAL) not in sys.path:
        sys.path.insert(0, str(EVAL))
    return importlib.import_module(name)


def report(*, spend=None, findings=(), status="complete", usage=None, tile=None,
           returned=None):
    """A minimal b1-shaped report with the fields judge() reads."""
    result = {"status": status, "calls_attempted": 3, "provider": "openrouter",
              "model": "openai/gpt-6-luna-decisions",
              "usage": usage if usage is not None else {"input_tokens": 1200, "output_tokens": 0},
              "spend": spend, "issues": [],
              "handoff": {"findings": [{"suspect": list(span)} for span in findings]}}
    if tile is not None:
        result["tile_sieve"] = tile
    if returned is not None:
        result["provenance"] = {"route": "openrouter-decisions", "models_returned": returned}
    return result


def spend(reported="0", estimated="0", unknown="0"):
    """A report's spend block as the engine writes it: the upper bound is the sum."""
    upper = Decimal(reported) + Decimal(estimated) + Decimal(unknown)
    return {"provider_reported_usd": reported, "estimated_usd": estimated,
            "unknown_usage_upper_bound_usd": unknown, "upper_bound_usd": format(upper, "f")}


@unittest.skipUnless(EVAL.is_dir(), "tools/eval absent")
class CatalogSpendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.run_catalog = tool("run_catalog")
        cases = {case["id"]: case for case in tool("catalog").cases()}
        cls.defect, cls.clear = cases["C001"], cases["C002"]

    def test_judge_records_provider_reported_usd(self):
        judge = self.run_catalog.judge
        row = judge(self.clear, report(spend={"provider_reported_usd": "0.000846",
                                              "estimated_usd": "0.0009"}), 0)
        self.assertEqual(row["provider_reported_usd"], "0.000846")
        self.assertTrue(row["location_pass"])
        for spend in (None, {}, {"provider_reported_usd": None},
                      {"provider_reported_usd": 0.0008}, {"provider_reported_usd": "1e-4"},
                      {"provider_reported_usd": "-0.1"}, "0.1"):
            self.assertIsNone(judge(self.clear, report(spend=spend), 0)["provider_reported_usd"],
                              spend)
        self.assertIsNone(judge(self.clear, None, 2)["provider_reported_usd"])

    def test_summary_sums_provider_reported_cost_not_usage(self):
        judge = self.run_catalog.judge
        rows = []
        for case, rep, code in (
                (self.defect, report(spend={"provider_reported_usd": "0.0123"},
                                     findings=[(1, 2)]), 1),
                (self.clear, report(spend={"provider_reported_usd": "0.0323"},
                                    usage={"input_tokens": 10, "output_tokens": 0,
                                           "cost_usd": 9.5}), 0),
                (self.clear, report(spend=None, usage={"input_tokens": 5, "cost_usd": 7}), 0)):
            row = judge(case, rep, code)
            row.update(id=case["id"], family=case["family"], expected=case["expected"],
                       exit_code=code, elapsed_s=0.1, stderr_tail=[])
            rows.append(row)
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "results.json").write_text(json.dumps(
                {"catalog_revision": "test", "cli_args": [], "cases": rows}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.run_catalog.summarize(out)
            summary = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("Provider-reported cost: $0.0446 (1 case(s) without a provider-reported "
                      "cost).", summary)
        self.assertIn("Input tokens: 1215.", summary)
        self.assertNotIn("16.5", summary)

    def test_summary_without_unknown_cases_has_no_note(self):
        row = self.run_catalog.judge(self.clear, report(spend={"provider_reported_usd": "0"}), 0)
        row.update(id="C002", family=self.clear["family"], expected="clear", exit_code=0,
                   elapsed_s=0.1, stderr_tail=[])
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "results.json").write_text(json.dumps(
                {"catalog_revision": "test", "cli_args": ["--state-layout", "v2"],
                 "cases": [row]}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.run_catalog.summarize(out)
            summary = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("Provider-reported cost: $0.", summary)
        self.assertNotIn("without a provider-reported cost", summary)
        self.assertIn("`--state-layout v2`", summary)
        # A results.json from before the judge was recorded has no judge line.
        self.assertNotIn("Judge:", summary)


def finished(run_catalog, case, rep, code=0):
    """A case row as ``run_case`` returns it, from a hand-built report."""
    row = run_catalog.judge(case, rep, code)
    row.update(id=case["id"], family=case["family"], expected=case["expected"],
               exit_code=code, elapsed_s=0.1, stderr_tail=[])
    return row


@unittest.skipUnless(EVAL.is_dir(), "tools/eval absent")
class CatalogRunTests(unittest.TestCase):
    """``main`` with the CLI call replaced: forwarding, the judge, the dry run, the stop."""

    @classmethod
    def setUpClass(cls):
        cls.run_catalog = tool("run_catalog")
        cls.cases = tool("catalog").cases()

    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("DBH_JUDGE", "DBH_PROVIDER"):
            os.environ.pop(name, None)

    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_catalog.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def fake_run_case(self, amount="0.02", returned=None, tile=None, estimated="0"):
        """A ``run_case`` replacement that reports *amount* (and *estimated*) per case."""
        calls = []

        def run_case(case, extra, keep):
            calls.append((case["id"], list(extra)))
            return finished(self.run_catalog, case,
                            report(spend=spend(amount, estimated), returned=returned,
                                   tile=tile))
        run_case.calls = calls
        return run_case

    def results(self, temp):
        return json.loads((Path(temp) / "results.json").read_text(encoding="utf-8"))

    def test_tile_sieve_dry_run_builds_no_provider_and_opens_no_socket(self):
        offline = AssertionError("the dry run must stay offline")
        cli = self.run_catalog.cli
        with mock.patch.object(cli, "make_provider", side_effect=offline), \
                mock.patch("decision_bug_hunter.providers.make_provider", side_effect=offline), \
                mock.patch.object(socket, "socket", side_effect=offline), \
                mock.patch.object(socket, "create_connection", side_effect=offline), \
                mock.patch.object(subprocess, "run", side_effect=offline):
            code, out, err = self.main("--dry-run", "--search-policy", "tile-sieve-beta",
                                       "--", "--judge", "openai", "--provider", "openrouter")
        self.assertEqual((code, err), (0, ""))
        lines = out.splitlines()
        self.assertEqual(len([line for line in lines if " whole-file: " in line]), 34)
        self.assertRegex(lines[1], r"^C001 defect whole-file: \d+ tile request\(s\), "
                                   r"\d+ questions, max [\d,]+ B$")
        self.assertIn("Totals: 36 tile requests, 34 focus requests projected (one per "
                      "whole-file case), 0 legacy fallback(s); projected request bytes ",
                      lines[-1])
        self.assertNotIn("<=", lines[-1])
        self.assertIn("at openai $0.10 per million input tokens", lines[-1])

    def test_dry_run_states_the_hard_limit_and_does_not_invent_one(self):
        code, out, _ = self.main("--dry-run", "--search-policy", "tile-sieve-beta", "--",
                                 "--judge", "openai", "--provider", "openai")
        self.assertEqual(code, 0)
        worst = out.splitlines()[-2]
        # The catalog's per-case --max-calls: 32 for most cases and 96 for the long ones.
        calls = sum(case["max_calls"] for case in self.cases)
        self.assertTrue(worst.startswith(
            "Worst case: the engine has no fixed limit on focus requests per case; "), worst)
        self.assertIn(f"at most {calls:,} requests over 34 case(s)", worst)
        bound = self.run_catalog.call_cap_bound(calls, (Decimal("0.10"), Decimal("0")))
        self.assertIn(f"at most ${self.run_catalog.money(bound)} with every request", worst)
        # A forwarded --max-calls replaces the catalog's cap for every case.
        _, out, _ = self.main("--dry-run", "--search-policy", "tile-sieve-beta", "--only",
                              "C001,C002", "--", "--judge", "openai", "--max-calls", "7",
                              "--max-cost", "0.02")
        self.assertIn("at most 14 requests over 2 case(s)", out)
        self.assertIn("--max-cost $0.02 per case, if lower, binds first", out)

    def test_cost_bound_follows_the_judges_price(self):
        run_catalog = self.run_catalog
        prices = {}
        for judge, route in (("openai", "openai"), ("openai", "openrouter"),
                             ("microsoft", "openrouter"), ("microsoft", "foundry")):
            selection = run_catalog.Selection(judge, None, route, None, "tile-sieve-beta",
                                              "utf-8-sig")
            prices[judge, route] = run_catalog.judge_prices(selection)
        self.assertEqual({prices["openai", "openai"], prices["openai", "openrouter"]},
                         {(Decimal("0.10"), Decimal("0"))})
        self.assertEqual({prices["microsoft", "openrouter"], prices["microsoft", "foundry"]},
                         {(Decimal("0.042"), Decimal("0"))})
        bounds = {}
        for judge in ("openai", "microsoft"):
            selection = run_catalog.Selection(judge, None, "openrouter", None,
                                              "tile-sieve-beta", "utf-8-sig")
            out = io.StringIO()
            with redirect_stdout(out):
                run_catalog.dry_run_tile_sieve(self.cases[:6], selection)
            last = out.getvalue().splitlines()[-1]
            self.assertIn(f"at {judge} $", last)
            bounds[judge] = Decimal(re.search(r"cost bound \$([0-9.]+)", last).group(1))
        self.assertGreater(bounds["openai"], 0)
        self.assertLess(bounds["microsoft"], bounds["openai"])
        self.assertAlmostEqual(bounds["microsoft"], bounds["openai"] * Decimal("0.42"),
                               delta=Decimal("0.00001"))

    def test_dry_run_prints_a_fallback_case_and_counts_it(self):
        run_catalog = self.run_catalog
        selection = run_catalog.Selection("openai", None, "openai", None, "tile-sieve-beta",
                                          "utf-8-sig")
        fallback = run_catalog.plans.Fallback("request_bytes", {"bytes": 30000, "limit": 24064})
        out = io.StringIO()
        with mock.patch.object(run_catalog, "plan_case", return_value=fallback), \
                redirect_stdout(out):
            run_catalog.dry_run_tile_sieve(self.cases[:2], selection)
        lines = out.getvalue().splitlines()
        self.assertTrue(lines[1].startswith("C001 defect legacy-fallback: request_bytes "))
        self.assertIn("scan with legacy-v1", lines[1])
        self.assertIn("Totals: 0 tile requests, 0 focus requests projected (one per "
                      "whole-file case), 2 legacy fallback(s);", lines[-1])

    def test_search_policy_judge_and_route_are_forwarded(self):
        fake = self.fake_run_case()
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog, "run_case", fake):
            code, _, _ = self.main("--only", "C001", "--out", temp, "--search-policy",
                                   "scoped-v2-beta", "--", "--judge", "openai", "--provider",
                                   "openrouter", "--max-cost", "0.02")
        self.assertEqual(code, 0)
        self.assertEqual(fake.calls, [("C001", ["--search-policy", "scoped-v2-beta", "--judge",
                                                "openai", "--provider", "openrouter",
                                                "--max-cost", "0.02"])])

    def test_forwarded_arguments_reach_the_cli_process(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 2, "", "")
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog.subprocess, "run", run):
            code, _, _ = self.main("--only", "C001", "--out", temp, "--search-policy",
                                   "tile-sieve-beta", "--", "--judge=openai", "--provider=openai")
        self.assertEqual(code, 0)
        [argv] = calls
        tail = argv[argv.index("--max-calls") + 2:]
        self.assertEqual(tail, ["--search-policy", "tile-sieve-beta", "--judge=openai",
                                "--provider=openai"])

    def test_judge_and_route_are_recorded_in_results_and_summary(self):
        dated = "microsoft/microsoft-decision-1-20261009"
        fake = self.fake_run_case(returned=[dated])
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog, "run_case", fake):
            code, _, _ = self.main("--only", "C001,C002", "--out", temp, "--", "--judge",
                                   "microsoft", "--provider", "openrouter")
            results = self.results(temp)
            summary = (Path(temp) / "summary.md").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertEqual((results["judge"], results["provider"], results["search_policy"]),
                         ("microsoft", "openrouter", "legacy-v1"))
        self.assertEqual(results["model_requested"], "microsoft/microsoft-decision-1")
        self.assertEqual([row["models_returned"] for row in results["cases"]], [[dated]] * 2)
        self.assertIn("Judge: microsoft. Route: openrouter. Search policy: legacy-v1.", summary)
        self.assertIn("Model requested: microsoft/microsoft-decision-1. "
                      f"Models returned: {dated}.", summary)

    def test_an_explicit_model_is_recorded_as_requested(self):
        fake = self.fake_run_case()
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog, "run_case", fake):
            self.main("--only", "C001", "--out", temp, "--", "--judge", "openai", "--provider",
                      "openrouter", "--model", "openai/gpt-6-luna-decisions")
            results = self.results(temp)
        self.assertEqual(results["model_requested"], "openai/gpt-6-luna-decisions")

    def test_max_total_cost_stops_before_the_next_case(self):
        fake = self.fake_run_case(amount="0.02")
        ids = [case["id"] for case in self.cases[:6]]
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog, "run_case", fake):
            code, out, _ = self.main("--only", ",".join(ids), "--out", temp,
                                     "--max-total-cost", "0.05", "--", "--judge", "openai",
                                     "--provider", "openai")
            results = self.results(temp)
            summary = (Path(temp) / "summary.md").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        # 0.02, 0.04, 0.06: the third case crosses the limit, so the fourth never runs.
        self.assertEqual([case_id for case_id, _ in fake.calls], ids[:3])
        self.assertEqual(results["stopped_at_case"], ids[3])
        self.assertEqual((results["max_total_cost"], Decimal(results["spent_usd"])),
                         ("0.05", Decimal("0.06")))
        self.assertEqual(len(results["cases"]), 3)
        self.assertIn(f"Stopping before {ids[3]}", out)
        self.assertIn(f"Stopped before {ids[3]}: the summed cost reached --max-total-cost $0.05",
                      summary)

    def test_a_run_inside_the_limit_records_no_stop(self):
        fake = self.fake_run_case(amount="0.01")
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog, "run_case", fake):
            self.main("--only", "C001,C002", "--out", temp, "--max-total-cost", "1", "--",
                      "--judge", "openai", "--provider", "openai")
            results = self.results(temp)
            summary = (Path(temp) / "summary.md").read_text(encoding="utf-8")
        self.assertIsNone(results["stopped_at_case"])
        self.assertEqual(len(fake.calls), 2)
        self.assertNotIn("Stopped before", summary)

    def test_case_cost_is_the_upper_bound_and_never_zero_without_a_record(self):
        cost = self.run_catalog.case_cost
        limit = (Decimal("0.02"), "max-cost")
        full = spend("0", "0.0153561", "0.001")
        self.assertEqual(cost(dict(full), limit), (Decimal("0.0163561"), "report"))
        # Components without the bound are summed; the stderr source is kept.
        self.assertEqual(cost({"provider_reported_usd": "0.5", "estimated_usd": "0.25",
                               "spend_source": "stderr"}, limit),
                         (Decimal("0.75"), "stderr"))
        self.assertEqual(cost({"provider_reported_usd": None, "estimated_usd": None,
                               "upper_bound_usd": None, "usage": {"input_tokens": 9}}, limit),
                         limit)
        self.assertEqual(cost({}, limit), limit)

    def test_the_limit_is_the_forwarded_max_cost_else_the_call_cap_bound(self):
        bound = self.run_catalog.limit_bound
        prices = (Decimal("0.10"), Decimal("0"))
        self.assertEqual(bound(32, 5, Decimal("0.02"), prices), (Decimal("0.02"), "max-cost"))
        full = self.run_catalog.call_cap_bound(1, prices)
        self.assertGreater(full, 0)
        self.assertEqual(bound(32, None, None, prices), (32 * full, "call-cap"))
        self.assertEqual(bound(32, 5, None, prices), (5 * full, "call-cap"))

    def test_an_openai_direct_report_binds_the_total_cost_guard_on_its_estimate(self):
        # OpenAI direct reports no cost: reported 0, the list-price estimate is the spend.
        fake = self.fake_run_case(amount="0", estimated="0.002")
        ids = [case["id"] for case in self.cases[:6]]
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog, "run_case", fake):
            code, out, _ = self.main("--only", ",".join(ids), "--out", temp,
                                     "--max-total-cost", "0.005", "--", "--judge", "openai",
                                     "--provider", "openai")
            results = self.results(temp)
            summary = (Path(temp) / "summary.md").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        # 0.002, 0.004, 0.006: the third case crosses the limit, so the fourth never runs.
        self.assertEqual([case_id for case_id, _ in fake.calls], ids[:3])
        self.assertEqual(results["stopped_at_case"], ids[3])
        self.assertEqual(Decimal(results["spent_usd"]), Decimal("0.006"))
        self.assertEqual([row["cost_basis"] for row in results["cases"]], ["report"] * 3)
        self.assertEqual(results["spend"]["provider_reported_usd"], "0")
        self.assertEqual(Decimal(results["spend"]["estimated_usd"]), Decimal("0.006"))
        self.assertIn("Provider-reported cost: $0.", summary)
        self.assertIn("List-price estimate: $0.006. Unknown-usage bound: $0. "
                      "Reported-or-estimated cost: $0.006.", summary)
        self.assertIn("(each case's upper bound): $0.006.", summary)
        self.assertIn(f"Stopping before {ids[3]}", out)

    def test_an_openrouter_report_is_counted_as_before(self):
        fake = self.fake_run_case(amount="0.02")
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog, "run_case", fake):
            self.main("--only", "C001,C002", "--out", temp, "--", "--judge", "openai",
                      "--provider", "openrouter")
            results = self.results(temp)
            summary = (Path(temp) / "summary.md").read_text(encoding="utf-8")
        self.assertEqual(Decimal(results["spent_usd"]), Decimal("0.04"))
        self.assertEqual([row["cost_usd"] for row in results["cases"]], ["0.02", "0.02"])
        self.assertIn("Provider-reported cost: $0.04.", summary)
        self.assertIn("List-price estimate: $0. Unknown-usage bound: $0. "
                      "Reported-or-estimated cost: $0.04.", summary)
        self.assertNotIn("counted from", summary)

    def run_without_reports(self, stderr, own, forwarded):
        """``main`` with every CLI process saving no report and printing *stderr*."""
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 2, "", stderr)
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(self.run_catalog.subprocess, "run", run):
            code, out, _ = self.main(*own, "--out", temp, "--", *forwarded)
            return code, out, self.results(temp)

    def test_a_case_with_no_report_is_counted_from_the_stderr_spend_line(self):
        line = ("Spend (USD): provider-reported 0, estimated 0.02, unknown-usage bound "
                "0.01.\n")
        code, _, results = self.run_without_reports(
            "Scan failed (x).\n" + line,
            ("--only", "C001,C002,C003", "--max-total-cost", "0.05"),
            ("--judge", "openai", "--provider", "openai"))
        self.assertEqual(code, 0)
        # 0.03, 0.06: the third case never runs.
        self.assertEqual([row["id"] for row in results["cases"]], ["C001", "C002"])
        self.assertEqual(results["stopped_at_case"], "C003")
        self.assertEqual(Decimal(results["spent_usd"]), Decimal("0.06"))
        first = results["cases"][0]
        self.assertEqual((first["status"], first["cost_basis"], first["spend_source"]),
                         ("missing", "stderr", "stderr"))
        self.assertEqual((first["estimated_usd"], first["unknown_usage_upper_bound_usd"],
                          first["upper_bound_usd"]), ("0.02", "0.01", "0.03"))

    def test_a_case_with_neither_is_counted_at_its_bound_never_zero(self):
        code, _, results = self.run_without_reports(
            "", ("--only", "C001,C002"),
            ("--judge", "openai", "--provider", "openai", "--max-cost", "0.02"))
        self.assertEqual(code, 0)
        self.assertEqual([(row["cost_usd"], row["cost_basis"]) for row in results["cases"]],
                         [("0.02", "max-cost")] * 2)
        self.assertEqual(Decimal(results["spent_usd"]), Decimal("0.04"))
        code, _, results = self.run_without_reports(
            "Spend (USD): garbled\n", ("--only", "C001"),
            ("--judge", "openai", "--provider", "openai"))
        [row] = results["cases"]
        expected = self.run_catalog.call_cap_bound(self.cases[0]["max_calls"],
                                                   (Decimal("0.10"), Decimal("0")))
        self.assertEqual((Decimal(row["cost_usd"]), row["cost_basis"]), (expected, "call-cap"))
        self.assertGreater(Decimal(results["spent_usd"]), 0)

    def test_stderr_spend_reads_only_the_clis_line(self):
        read = self.run_catalog.stderr_spend
        got = read("noise\nSpend (USD): provider-reported 0.001, estimated 0.002, "
                   "unknown-usage bound 0.0005.\n")
        self.assertEqual(got, {"provider_reported_usd": "0.001", "estimated_usd": "0.002",
                               "unknown_usage_upper_bound_usd": "0.0005",
                               "upper_bound_usd": "0.0035"})
        none = dict.fromkeys(got)
        for text in ("", "Spend (USD): provider-reported None, estimated 0, unknown-usage "
                         "bound 0.", "Spend (USD): provider-reported 1e-3, estimated 0, "
                                     "unknown-usage bound 0."):
            self.assertEqual(read(text), none, text)

    def test_summarize_recomputes_an_older_directory_the_new_way(self):
        # A run recorded before the upper bound was kept: OpenAI direct, reported 0, so the
        # old runner wrote spent_usd 0 and cost_usd from the reported amount alone.
        rows = []
        for case, rep in [(c, report(spend={"provider_reported_usd": "0",
                                            "estimated_usd": "0.005"}))
                          for c in self.cases[:3]] + [(self.cases[3], None)]:
            row = finished(self.run_catalog, case, rep, 0 if rep else 2)
            row.update(cost_usd="0")
            row.pop("unknown_usage_upper_bound_usd")
            row.pop("upper_bound_usd")
            rows.append(row)
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "results.json").write_text(json.dumps(
                {"catalog_revision": "test", "cli_args": ["--judge", "openai"],
                 "judge": "openai", "provider": "openai", "search_policy": "tile-sieve-beta",
                 "spent_usd": "0", "cases": rows}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.run_catalog.summarize(out)
            summary = (out / "summary.md").read_text(encoding="utf-8")
            recorded = self.results(temp)
        bound = self.run_catalog.call_cap_bound(self.cases[3]["max_calls"],
                                                (Decimal("0.10"), Decimal("0")))
        # No saved report to read: the unknown-usage bound was never recorded, not measured as 0.
        self.assertIn("List-price estimate: $0.015. Unknown-usage bound: $0 (4 case(s) recorded "
                      "before it was kept). Reported-or-estimated cost: $0.015.", summary)
        self.assertIn(f"(each case's upper bound): ${Decimal('0.015') + bound} "
                      "(1 from --max-calls full-size requests at list price). The unknown-usage "
                      "bound is missing for 4 case(s), so this may be low.", summary)
        self.assertEqual(recorded["spent_usd"], "0")

    def test_summarize_takes_an_older_rows_upper_bound_from_its_saved_report(self):
        # The older runner saved reports/<id>-report.json but kept only the reported and
        # estimated amounts in the row; the report holds the unknown-usage bound.
        spend = {"provider_reported_usd": "0", "estimated_usd": "0.005",
                 "unknown_usage_upper_bound_usd": "0.004", "upper_bound_usd": "0.009"}
        row = finished(self.run_catalog, self.cases[0], report(spend=spend), 0)
        row.update(provider_reported_usd="0", estimated_usd="0.005", cost_usd="0")
        row.pop("unknown_usage_upper_bound_usd")
        row.pop("upper_bound_usd")
        text = json.dumps({"catalog_revision": "test", "cli_args": ["--judge", "openai"],
                           "judge": "openai", "provider": "openai", "spent_usd": "0",
                           "cases": [row]})
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "reports").mkdir()
            (out / "reports" / f"{row['id']}-report.json").write_text(
                json.dumps(report(spend=spend)), encoding="utf-8")
            (out / "results.json").write_text(text, encoding="utf-8")
            before = (out / "results.json").read_bytes()
            with redirect_stdout(io.StringIO()):
                self.run_catalog.summarize(out)
            summary = (out / "summary.md").read_text(encoding="utf-8")
            self.assertEqual((out / "results.json").read_bytes(), before)
            # A saved report that is not JSON is treated as absent.
            (out / "reports" / f"{row['id']}-report.json").write_text("{", encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.run_catalog.summarize(out)
            broken = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("List-price estimate: $0.005. Unknown-usage bound: $0.004. "
                      "Reported-or-estimated cost: $0.005.", summary)
        self.assertIn("(each case's upper bound): $0.009.", summary)
        self.assertNotIn("recorded before it was kept", summary)
        self.assertIn("Unknown-usage bound: $0 (1 case(s) recorded before it was kept).", broken)

    def test_a_case_that_cannot_be_priced_is_counted_at_its_record(self):
        row = finished(self.run_catalog, self.cases[0], None, 2)
        row.update(cost_usd="0.003")
        totals = self.run_catalog.spend_totals([row], {"cli_args": []})
        self.assertEqual((totals["counted_usd"], totals["cost_bases"]),
                         ("0.003", {"recorded": 1}))

    def test_a_missing_judge_is_reported_up_front_as_the_cli_reports_it(self):
        offline = AssertionError("nothing may run")
        hint = self.run_catalog.cli.JUDGE_CHOICE_HINT
        for argv in (("--dry-run",), ("--dry-run", "--search-policy", "tile-sieve-beta"),
                     ("--only", "C001", "--", "--provider", "openai")):
            with mock.patch.object(self.run_catalog, "run_case", side_effect=offline), \
                    mock.patch.object(self.run_catalog, "plan_case", side_effect=offline):
                code, out, err = self.main(*argv)
            self.assertEqual((code, out, err), (3, "", f"NEED_USER_INPUT judge: {hint}\n"), argv)

    def test_the_judge_may_come_from_the_environment_as_for_the_cli(self):
        os.environ["DBH_JUDGE"] = "openai"
        code, out, _ = self.main("--dry-run", "--only", "C001")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("C001 defect decision-bug-hunter "))

    def test_microsoft_with_tile_sieve_is_refused_up_front_with_the_cli_text(self):
        offline = AssertionError("nothing may run")
        text = ("Scan failed (invalid_search_configuration: tile-sieve-beta has no "
                "calibrated thresholds for judge microsoft).\n")
        for argv in (("--dry-run", "--search-policy", "tile-sieve-beta", "--", "--judge",
                      "microsoft", "--provider", "openrouter"),
                     ("--search-policy", "tile-sieve-beta", "--", "--judge", "microsoft"),
                     ("--search-policy", "tile-sieve-beta", "--", "--judge", "microsoft",
                      "--provider", "openai"),
                     ("--", "--judge", "microsoft", "--search-policy", "tile-sieve-beta")):
            with mock.patch.object(self.run_catalog, "run_case", side_effect=offline), \
                    mock.patch.object(self.run_catalog, "plan_case", side_effect=offline), \
                    mock.patch.object(subprocess, "run", side_effect=offline):
                code, out, err = self.main(*argv)
            self.assertEqual((code, out, err), (2, "", text), argv)

    def test_microsoft_runs_the_legacy_policy(self):
        code, out, err = self.main("--dry-run", "--only", "C001", "--", "--judge", "microsoft")
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(out.endswith("--judge microsoft\n"))

    def test_a_route_outside_the_judges_is_refused_as_the_cli_refuses_it(self):
        code, _, err = self.main("--dry-run", "--", "--judge", "microsoft", "--provider",
                                 "openai")
        self.assertEqual(code, 3)
        self.assertEqual(err, "NEED_USER_INPUT judge_route: microsoft routes: openrouter | foundry\n")

    def test_forwarded_arguments_are_read_as_the_cli_reads_them(self):
        # An unambiguous abbreviation is the CLI's --judge, not a missing judge.
        code, out, err = self.main("--dry-run", "--only", "C001", "--", "--judg", "openai")
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(out.endswith("--judg openai\n"))
        code, _, err = self.main("--dry-run", "--only", "C001", "--", "--judge=openai",
                                 "--provid", "openai", "--search-p", "legacy-v1")
        self.assertEqual((code, err), (0, ""))
        # An ambiguous one is refused as the CLI refuses it.
        code, out, err = self.main("--dry-run", "--", "--judge", "openai", "--max-c", "1")
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err, "Invalid command-line arguments; use --help for usage.\n")

    def test_a_rejected_forwarded_value_is_never_echoed(self):
        offline = AssertionError("nothing may run")
        secret = "sk-dbh-not-a-real-value"
        for argv in (("--judge", secret), ("--judge", "openai", "--provider", secret),
                     ("--judge", "openai", "--search-policy", secret),
                     ("--judge", "openai", "--max-cost", secret),
                     ("--judge", "openai", "--max-calls", secret)):
            with mock.patch.object(self.run_catalog, "run_case", side_effect=offline), \
                    mock.patch.object(subprocess, "run", side_effect=offline):
                code, out, err = self.main("--dry-run", "--", *argv)
            self.assertEqual(code, 2, argv)
            self.assertNotIn(secret, out + err)
            self.assertEqual(err, "Invalid command-line arguments; use --help for usage.\n")

    def test_a_budget_the_cli_would_refuse_is_refused_up_front(self):
        offline = AssertionError("nothing may run")
        cost_text = "Scan failed (invalid_request).\n"
        calls_text = "Scan failed (invalid_input_or_configuration).\n"
        for argv, text in ((("--max-cost", "-1"), cost_text), (("--max-cost", "0"), cost_text),
                           (("--max-cost", "1e5"), cost_text),
                           (("--max-calls", "0"), calls_text),
                           (("--max-calls", "-3"), calls_text),
                           (("--max-calls", "100001"), calls_text)):
            for own in ((), ("--dry-run",)):
                with tempfile.TemporaryDirectory() as temp, \
                        mock.patch.object(self.run_catalog, "run_case", side_effect=offline), \
                        mock.patch.object(subprocess, "run", side_effect=offline):
                    code, out, err = self.main(*own, "--out", temp, "--only", "C001", "--",
                                               "--judge", "openai", "--provider", "openai",
                                               *argv)
                    self.assertEqual((code, out, err), (2, "", text), (argv, own))
                    self.assertFalse((Path(temp) / "results.json").exists(), argv)

    def test_the_budget_edges_the_cli_accepts_are_not_refused(self):
        for argv in (("--max-cost", "1000"), ("--max-cost", "0.000001"),
                     ("--max-calls", "1"), ("--max-calls", "100000")):
            code, _, err = self.main("--dry-run", "--only", "C001", "--", "--judge", "openai",
                                     "--provider", "openai", *argv)
            self.assertEqual((code, err), (0, ""), argv)

    def test_conflicting_search_policies_are_refused(self):
        code, _, err = self.main("--dry-run", "--search-policy", "tile-sieve-beta", "--",
                                 "--judge", "openai", "--search-policy", "legacy-v1")
        self.assertEqual(code, 2)
        self.assertIn("--search-policy differs", err)

    def test_a_policy_given_only_after_the_dashes_selects_the_tile_sieve_dry_run(self):
        code, out, _ = self.main("--dry-run", "--only", "C001", "--", "--judge", "openai",
                                 "--search-policy", "tile-sieve-beta")
        self.assertEqual(code, 0)
        self.assertIn(" whole-file: ", out)
        self.assertIn("Totals: ", out)

    def test_judge_reads_the_mode_and_the_models_returned(self):
        case = next(c for c in self.cases if c["id"] == "C002")
        whole = self.run_catalog.judge(case, report(tile={"mode": "whole-file"},
                                                    returned=["b", "a", "a"]), 0)
        self.assertEqual((whole["mode"], whole["models_returned"]), ("whole-file", ["a", "b"]))
        fell = self.run_catalog.judge(case, report(
            tile={"mode": "legacy-fallback", "reason": "request_bytes"}), 0)
        self.assertEqual((fell["mode"], fell["fallback_reason"]),
                         ("legacy-fallback", "request_bytes"))
        for bad in (report(tile="x", returned="y"), None):
            row = self.run_catalog.judge(case, bad, 0)
            self.assertEqual((row["mode"], row["models_returned"]), (None, []))

    def test_summary_has_a_mode_column_and_a_fallback_count(self):
        run_catalog = self.run_catalog
        rows = [finished(run_catalog, self.cases[1], report(tile={"mode": "whole-file"})),
                finished(run_catalog, self.cases[1], report(
                    tile={"mode": "legacy-fallback", "reason": "request_bytes"})),
                finished(run_catalog, self.cases[1], report(tile={"mode": "whole-file"}))]
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "results.json").write_text(json.dumps(
                {"catalog_revision": "test", "cli_args": ["--search-policy", "tile-sieve-beta"],
                 "judge": "openai", "provider": None, "search_policy": "tile-sieve-beta",
                 "cases": rows}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                run_catalog.summarize(out)
            summary = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("| Case | Family | Expected | Mode | Status |", summary)
        self.assertIn("Whole-file cases: 2. Legacy-v1 fallbacks: 1.", summary)
        self.assertIn("| whole-file | complete |", summary)
        self.assertIn("Route: not given.", summary)


if __name__ == "__main__":
    unittest.main()
