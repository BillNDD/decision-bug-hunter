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

    def fake_run_case(self, amount="0.02", returned=None, tile=None):
        """A ``run_case`` replacement that reports *amount* per case and records the calls."""
        calls = []

        def run_case(case, extra, keep):
            calls.append((case["id"], list(extra)))
            return finished(self.run_catalog, case,
                            report(spend={"provider_reported_usd": amount}, returned=returned,
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
        self.assertIn("Totals: 36 tile requests, <= 34 focus, 0 legacy fallback(s); "
                      "projected request bytes ", lines[-1])
        self.assertIn("at openai $0.10 per million input tokens", lines[-1])

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
        self.assertIn("Totals: 0 tile requests, <= 0 focus, 2 legacy fallback(s);", lines[-1])

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

    def test_case_cost_prefers_reported_then_estimated_then_usage(self):
        prices = (Decimal("0.10"), Decimal("0"))
        cost = self.run_catalog.case_cost
        usage = {"input_tokens": 2000000, "output_tokens": 0}
        self.assertEqual(cost({"provider_reported_usd": "0.5", "estimated_usd": "0.7",
                               "usage": usage}, prices), Decimal("0.5"))
        self.assertEqual(cost({"provider_reported_usd": None, "estimated_usd": "0.7",
                               "usage": usage}, prices), Decimal("0.7"))
        self.assertEqual(cost({"provider_reported_usd": None, "estimated_usd": None,
                               "usage": usage}, prices), Decimal("0.2"))
        self.assertEqual(cost({"usage": {}}, prices), 0)
        self.assertEqual(cost({"usage": None}, prices), 0)

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
